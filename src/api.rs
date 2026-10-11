//! Transport-independent HTTP/JSON API for the bulbs.
//!
//! `Api::handle` maps a request to a response without touching sockets, so the
//! security rules (token, Origin, Host) and the input validation can be tested
//! without any bulb. `src/bin/tapo-server.rs` puts it behind a real listener.

use std::sync::Mutex;

use serde_json::{Map, Value, json};

use crate::pake::ct_eq;
use crate::{Device, Error};

pub struct Request<'a> {
    pub method: &'a str,
    /// Path with optional query string, as received.
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub authorization: Option<&'a str>,
    pub body: &'a [u8],
}

pub struct Response {
    pub status: u16,
    pub body: Value,
}

pub struct Config {
    /// Secret every `/v1` request must present as `Authorization: Bearer <token>`.
    pub token: String,
    /// Browser origins allowed to call the API. Empty = no web page can.
    pub allowed_origins: Vec<String>,
    /// Reject requests whose Host header is not localhost (DNS-rebinding defence).
    pub enforce_host: bool,
}

pub struct Api {
    lights: Vec<(String, Mutex<Device>)>,
    cfg: Config,
}

fn reply(status: u16, body: Value) -> Response {
    Response { status, body }
}

fn fail(status: u16, kind: &str, message: &str) -> Response {
    reply(status, json!({"error": message, "kind": kind}))
}

fn is_local_host(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn error_response(e: &Error) -> Response {
    let (status, kind) = match e {
        Error::Locked { .. } => (423, "locked"),
        Error::Device { .. } => (502, "device"),
        Error::Unsupported(_) => (501, "unsupported"),
        Error::Http(_) => (504, "unreachable"),
        Error::Protocol(_) | Error::Crypto(_) => (502, "protocol"),
    };
    let mut body = json!({"error": e.to_string(), "kind": kind});
    if let Error::Locked { retry_in_secs } = e {
        body["retryInSecs"] = json!(retry_in_secs);
    }
    reply(status, body)
}

/// Validated body of `POST /v1/lights/{host}`.
#[derive(Default, Debug, PartialEq)]
struct Change {
    on: Option<bool>,
    brightness: Option<u8>,
    color_temp: Option<u16>,
    color: Option<(u16, u8)>,
}

fn int_in(map: &Map<String, Value>, key: &str, lo: i64, hi: i64) -> Result<Option<i64>, String> {
    match map.get(key) {
        None => Ok(None),
        Some(v) => match v.as_i64() {
            Some(n) if (lo..=hi).contains(&n) => Ok(Some(n)),
            _ => Err(format!("{key} must be an integer between {lo} and {hi}")),
        },
    }
}

fn parse_change(body: &[u8]) -> Result<Change, String> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| "body must be a JSON object".to_string())?;
    let map = value.as_object().ok_or("body must be a JSON object")?;
    if let Some(unknown) = map
        .keys()
        .find(|k| !["on", "brightness", "colorTemp", "hue", "saturation"].contains(&k.as_str()))
    {
        return Err(format!("unknown field {unknown}"));
    }
    let on = match map.get("on") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err("on must be true or false".into()),
    };
    let brightness = int_in(map, "brightness", 1, 100)?.map(|n| n as u8);
    let color_temp = int_in(map, "colorTemp", 1000, 10000)?.map(|n| n as u16);
    let hue = int_in(map, "hue", 0, 360)?;
    let saturation = int_in(map, "saturation", 0, 100)?;
    let color = match (hue, saturation) {
        (Some(h), Some(s)) => Some((h as u16, s as u8)),
        (None, None) => None,
        _ => return Err("hue and saturation must be sent together".into()),
    };
    if color.is_some() && color_temp.is_some() {
        return Err("send either colorTemp or hue/saturation, not both".into());
    }
    if on.is_none() && brightness.is_none() && color_temp.is_none() && color.is_none() {
        return Err("nothing to change".into());
    }
    Ok(Change {
        on,
        brightness,
        color_temp,
        color,
    })
}

impl Api {
    pub fn new(devices: Vec<Device>, cfg: Config) -> Self {
        let lights = devices
            .into_iter()
            .map(|d| (d.host().to_string(), Mutex::new(d)))
            .collect();
        Self { lights, cfg }
    }

    pub fn handle(&self, req: &Request) -> Response {
        if self.cfg.enforce_host && !req.host.is_some_and(is_local_host) {
            return fail(403, "forbidden", "Host header must be localhost");
        }
        // Browsers always send Origin on cross-site requests; programs usually do not.
        if let Some(origin) = req.origin
            && !self.cfg.allowed_origins.iter().any(|o| o == origin)
        {
            return fail(403, "forbidden", "origin not allowed");
        }
        let path = req
            .path
            .split('?')
            .next()
            .unwrap_or("/")
            .trim_end_matches('/');
        if path == "/health" && req.method == "GET" {
            return reply(200, json!({"ok": true}));
        }
        let token_ok = req
            .authorization
            .and_then(|h| h.strip_prefix("Bearer "))
            .is_some_and(|t| ct_eq(t.as_bytes(), self.cfg.token.as_bytes()));
        if !token_ok {
            return fail(401, "unauthorized", "missing or invalid bearer token");
        }
        match (req.method, path) {
            ("GET", "/v1/lights") => reply(200, json!({"lights": self.all(Self::read)})),
            ("POST", "/v1/lights/all") => self.set_all(req.body),
            ("GET", p) | ("POST", p) | ("PUT", p) | ("PATCH", p)
                if p.starts_with("/v1/lights/") =>
            {
                let host = &p["/v1/lights/".len()..];
                let Some(idx) = self.lights.iter().position(|(h, _)| h == host) else {
                    return fail(404, "not_found", "unknown light");
                };
                if req.method == "GET" {
                    return Self::read_or_error(&self.lights[idx].1);
                }
                match parse_change(req.body) {
                    Err(m) => fail(400, "bad_request", &m),
                    Ok(change) => Self::apply(&self.lights[idx].1, &change),
                }
            }
            (_, p) if p == "/v1/lights" || p.starts_with("/v1/lights/") => {
                fail(405, "method_not_allowed", "method not allowed")
            }
            _ => fail(404, "not_found", "no such endpoint"),
        }
    }

    /// Runs `f` on every bulb in parallel and collects one JSON object per bulb.
    fn all(&self, f: impl Fn(&Mutex<Device>) -> Value + Sync) -> Vec<Value> {
        std::thread::scope(|scope| {
            let handles: Vec<_> = self
                .lights
                .iter()
                .map(|(_, d)| scope.spawn(|| f(d)))
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| json!({"error": "internal error"}))
                })
                .collect()
        })
    }

    fn lock(device: &Mutex<Device>) -> std::sync::MutexGuard<'_, Device> {
        device
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn read(device: &Mutex<Device>) -> Value {
        let mut dev = Self::lock(device);
        match dev.state() {
            Ok(s) => s.to_json(),
            Err(e) => json!({"host": dev.host(), "error": e.to_string()}),
        }
    }

    fn read_or_error(device: &Mutex<Device>) -> Response {
        match Self::lock(device).state() {
            Ok(s) => reply(200, s.to_json()),
            Err(e) => error_response(&e),
        }
    }

    fn apply(device: &Mutex<Device>, c: &Change) -> Response {
        let mut dev = Self::lock(device);
        let result = (|| {
            if let Some(on) = c.on {
                dev.set_power(on)?;
            }
            match (c.color, c.color_temp) {
                (Some((h, s)), _) => dev.set_hsv(h, s, c.brightness)?,
                (None, Some(k)) => {
                    dev.set_color_temp(k)?;
                    if let Some(b) = c.brightness {
                        dev.set_brightness(b)?;
                    }
                }
                (None, None) => {
                    if let Some(b) = c.brightness {
                        dev.set_brightness(b)?;
                    }
                }
            }
            dev.state()
        })();
        match result {
            Ok(s) => reply(200, s.to_json()),
            Err(e) => error_response(&e),
        }
    }

    fn set_all(&self, body: &[u8]) -> Response {
        let on = match serde_json::from_slice::<Value>(body)
            .ok()
            .as_ref()
            .and_then(|v| v.as_object())
        {
            Some(m) if m.len() == 1 => m.get("on").and_then(Value::as_bool),
            _ => None,
        };
        let Some(on) = on else {
            return fail(400, "bad_request", "body must be {\"on\": true|false}");
        };
        let lights = self.all(|d| {
            let mut dev = Self::lock(d);
            match dev.set_power(on).and_then(|_| dev.state()) {
                Ok(s) => s.to_json(),
                Err(e) => json!({"host": dev.host(), "error": e.to_string()}),
            }
        });
        reply(200, json!({"lights": lights}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "secret-token";

    fn api() -> Api {
        // 192.0.2.1 is TEST-NET-1: none of these tests may ever reach a device.
        Api::new(
            vec![Device::new("192.0.2.1", "a@example.com", "x")],
            Config {
                token: TOKEN.into(),
                allowed_origins: vec!["http://localhost:5173".into()],
                enforce_host: true,
            },
        )
    }

    fn call(
        method: &str,
        path: &str,
        auth: Option<&str>,
        origin: Option<&str>,
        host: Option<&str>,
        body: &str,
    ) -> Response {
        api().handle(&Request {
            method,
            path,
            host,
            origin,
            authorization: auth,
            body: body.as_bytes(),
        })
    }

    const OK_AUTH: Option<&str> = Some("Bearer secret-token");
    const LOCAL: Option<&str> = Some("127.0.0.1:8787");

    #[test]
    fn health_needs_no_token() {
        assert_eq!(call("GET", "/health", None, None, LOCAL, "").status, 200);
    }

    #[test]
    fn token_is_required_and_checked() {
        assert_eq!(call("GET", "/v1/lights", None, None, LOCAL, "").status, 401);
        assert_eq!(
            call("GET", "/v1/lights", Some("Bearer nope"), None, LOCAL, "").status,
            401
        );
        assert_eq!(
            call("GET", "/v1/lights", Some("secret-token"), None, LOCAL, "").status,
            401
        );
    }

    #[test]
    fn foreign_origin_and_host_are_rejected() {
        let evil = Some("https://evil.example");
        assert_eq!(
            call("POST", "/v1/lights/all", OK_AUTH, evil, LOCAL, "{}").status,
            403
        );
        assert_eq!(call("GET", "/health", None, evil, LOCAL, "").status, 403);
        assert_eq!(
            call("GET", "/health", None, None, Some("evil.example"), "").status,
            403
        );
        assert_eq!(call("GET", "/health", None, None, None, "").status, 403);
        assert_eq!(
            call(
                "GET",
                "/health",
                None,
                Some("http://localhost:5173"),
                Some("localhost:8787"),
                ""
            )
            .status,
            200
        );
    }

    #[test]
    fn local_host_parsing() {
        assert!(
            is_local_host("localhost:8787")
                && is_local_host("127.0.0.1")
                && is_local_host("[::1]:80")
        );
        assert!(!is_local_host("localhost.evil.com") && !is_local_host("127.0.0.1.evil.com:80"));
    }

    #[test]
    fn unknown_light_and_endpoint() {
        assert_eq!(
            call("GET", "/v1/lights/10.9.9.9", OK_AUTH, None, LOCAL, "").status,
            404
        );
        assert_eq!(call("GET", "/nope", OK_AUTH, None, LOCAL, "").status, 404);
        assert_eq!(
            call("DELETE", "/v1/lights", OK_AUTH, None, LOCAL, "").status,
            405
        );
    }

    #[test]
    fn invalid_bodies_never_reach_the_device() {
        for body in [
            "",
            "[]",
            "{}",
            r#"{"on":"yes"}"#,
            r#"{"brightness":0}"#,
            r#"{"brightness":101}"#,
            r#"{"brightness":50.5}"#,
            r#"{"hue":10}"#,
            r#"{"hue":361,"saturation":1}"#,
            r#"{"colorTemp":3000,"hue":1,"saturation":1}"#,
            r#"{"on":true,"password":"x"}"#,
        ] {
            let r = call("POST", "/v1/lights/192.0.2.1", OK_AUTH, None, LOCAL, body);
            assert_eq!(r.status, 400, "body {body:?} should be rejected");
        }
        assert_eq!(
            call(
                "POST",
                "/v1/lights/all",
                OK_AUTH,
                None,
                LOCAL,
                r#"{"on":1}"#
            )
            .status,
            400
        );
    }

    #[test]
    fn valid_change_parses() {
        let c = parse_change(br#"{"on":true,"brightness":40,"hue":120,"saturation":80}"#).unwrap();
        assert_eq!(
            c,
            Change {
                on: Some(true),
                brightness: Some(40),
                color_temp: None,
                color: Some((120, 80))
            }
        );
    }
}

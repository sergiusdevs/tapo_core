//! HTTP side of TPAP: discover -> pake_register -> pake_share -> encrypted queries.
//! Only plain-HTTP, password-authenticated bulbs are supported (what the L530 uses).

use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use md5::{Digest as _, Md5};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::http;
use crate::pake::{self, Error, Register, Result, Session};

/// After an authentication failure the bulb counts attempts (it locks at 15).
/// We refuse to try again for this long, and at most this many attempts total.
const COOLDOWN: Duration = Duration::from_secs(360);
const TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone)]
pub struct LightState {
    pub host: String,
    pub name: String,
    pub model: String,
    pub on: bool,
    pub brightness: u8,
    pub supports_color: bool,
    pub hue: u16,
    pub saturation: u8,
    pub supports_temp: bool,
    pub color_temp: u16,
    pub temp_range: (u16, u16),
}

impl LightState {
    pub fn to_json(&self) -> Value {
        json!({
            "host": self.host, "name": self.name, "model": self.model, "on": self.on,
            "brightness": self.brightness,
            "supportsColor": self.supports_color, "hue": self.hue, "saturation": self.saturation,
            "supportsTemp": self.supports_temp, "colorTemp": self.color_temp,
            "tempMin": self.temp_range.0, "tempMax": self.temp_range.1,
        })
    }
}

struct Active {
    session: Session,
    addr: String,
    ds_path: String,
    seq: u32,
}

pub struct Device {
    host: String,
    email: String,
    password: String,
    terminal_uuid: String,
    active: Option<Active>,
    locked_until: Option<Instant>,
}

fn hex_digest<D: sha2::digest::Digest>(data: &[u8]) -> String {
    hex::encode(D::digest(data))
}

impl Drop for Device {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl Device {
    pub fn new(host: &str, email: &str, password: &str) -> Self {
        let random: [u8; 16] = rand::random();
        Self {
            host: host.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            terminal_uuid: B64.encode(Md5::digest(random)),
            active: None,
            locked_until: None,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    // ---- low-level HTTP -------------------------------------------------

    fn post_json(&self, addr: &str, body: &Value, step: &str) -> Result<Value> {
        let (status, bytes) = http::post(
            addr,
            "/",
            "application/json",
            body.to_string().as_bytes(),
            TIMEOUT,
        )
        .map_err(|e| Error::Http(format!("{step}: {e}")))?;
        if status != 200 {
            return Err(Error::Http(format!("{step}: status {status}")));
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            let head: String = String::from_utf8_lossy(&bytes).chars().take(60).collect();
            Error::Protocol(format!(
                "{step}: invalid JSON: {e} (len {}, starts {head:?})",
                bytes.len()
            ))
        })
    }

    /// Checks `error_code`; auth-related failures arm the cooldown.
    fn check(&mut self, response: &Value, step: &str) -> Result<()> {
        let code = response
            .get("error_code")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if code == 0 {
            return Ok(());
        }
        // -2101 is the account/credential error; -2102 / -2203 / -1501 are related login rejections.
        if matches!(code, -2101 | -2102 | -2203 | -1501) || step == "pake_share" {
            self.locked_until = Some(Instant::now() + COOLDOWN);
        }
        let info = response
            .get("error_info")
            .map(Value::to_string)
            .unwrap_or_default();
        Err(Error::Device {
            code,
            message: format!("{step} failed {info}"),
        })
    }

    fn login(&mut self, addr: &str, params: Value, step: &str) -> Result<Value> {
        let resp = self.post_json(addr, &json!({"method": "login", "params": params}), step)?;
        self.check(&resp, step)?;
        resp.get("result")
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("{step}: response has no result")))
    }

    // ---- handshake ------------------------------------------------------

    fn guard(&self) -> Result<()> {
        if let Some(until) = self.locked_until {
            let now = Instant::now();
            if until > now {
                return Err(Error::Locked {
                    retry_in_secs: (until - now).as_secs() + 1,
                });
            }
        }
        Ok(())
    }

    fn credentials_string(&self, extra: Option<&Value>) -> Result<String> {
        let Some(extra) =
            extra.filter(|v| !v.is_null() && !v.as_object().is_some_and(|o| o.is_empty()))
        else {
            return Ok(if self.email.is_empty() {
                self.password.clone()
            } else {
                format!("{}/{}", self.email, self.password)
            });
        };
        let kind = extra
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        let passwd_id = extra
            .pointer("/params/passwd_id")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        match (kind.as_str(), passwd_id) {
            ("password_shadow", 2) => Ok(hex_digest::<Sha1>(self.password.as_bytes())),
            _ => Err(Error::Unsupported(format!(
                "extra_crypt {kind}/{passwd_id}"
            ))),
        }
    }

    fn handshake(&mut self) -> Result<()> {
        self.guard()?;
        let fixed_port = self.host.contains(':');
        let base = if fixed_port {
            self.host.clone()
        } else {
            format!("{}:80", self.host)
        };

        let disc = self.login(&base, json!({"sub_method": "discover"}), "discover")?;
        let tpap = disc
            .get("tpap")
            .ok_or_else(|| Error::Protocol("discover: no tpap object".into()))?;
        let as_i64 = |k: &str| tpap.get(k).and_then(Value::as_i64);
        if as_i64("tls").unwrap_or(0) != 0 {
            return Err(Error::Unsupported("this bulb requires TLS".into()));
        }
        if tpap
            .get("dac")
            .and_then(|v| v.as_bool().or_else(|| v.as_i64().map(|n| n != 0)))
            .unwrap_or(false)
        {
            return Err(Error::Unsupported(
                "device attestation (DAC) is not implemented".into(),
            ));
        }
        let pake_modes: Vec<i64> = tpap
            .get("pake")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default();
        if !pake_modes.iter().any(|m| *m == 2 || *m == 5) {
            return Err(Error::Unsupported(format!(
                "pake modes {pake_modes:?} (need password auth)"
            )));
        }
        let port = as_i64("port").unwrap_or(80);
        let base = if fixed_port {
            self.host.clone()
        } else {
            format!("{}:{port}", self.host)
        };

        let register_username = if as_i64("user_hash_type") == Some(1) {
            hex_digest::<Sha256>(b"admin").to_uppercase()
        } else {
            hex::encode(Md5::digest(b"admin"))
        };
        let user_random: [u8; 32] = rand::random();
        let reg = self.login(
            &base,
            json!({
                "sub_method": "pake_register",
                "username": register_username,
                "user_random": B64.encode(user_random),
                "cipher_suites": [1],
                "encryption": ["aes_128_ccm"],
                "passcode_type": "userpw",
                "stok": null,
            }),
            "pake_register",
        )?;

        let field = |k: &str| -> Result<Vec<u8>> {
            let s = reg.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
            let s = s.ok_or_else(|| Error::Protocol(format!("register response missing {k}")))?;
            B64.decode(s)
                .map_err(|e| Error::Protocol(format!("{k}: {e}")))
        };
        if reg.get("cipher_suites").and_then(Value::as_i64) != Some(1) {
            return Err(Error::Unsupported(
                "only cipher suite 1 is implemented".into(),
            ));
        }
        if reg
            .get("encryption")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .as_deref()
            != Some("aes_128_ccm")
        {
            return Err(Error::Unsupported("only aes_128_ccm is implemented".into()));
        }
        let iterations =
            reg.get("iterations")
                .and_then(Value::as_u64)
                .filter(|n| *n > 0 && *n <= 1_000_000)
                .ok_or_else(|| Error::Protocol("invalid iterations".into()))? as u32;
        let register = Register {
            dev_random: field("dev_random")?,
            dev_salt: field("dev_salt")?,
            dev_share: field("dev_share")?,
            iterations,
        };
        let credentials = self.credentials_string(reg.get("extra_crypt"))?;
        let share =
            pake::build_share(&credentials, &user_random, &register, pake::random_scalar())?;

        let result = self.login(
            &base,
            json!({
                "sub_method": "pake_share",
                "user_share": B64.encode(&share.user_share),
                "user_confirm": B64.encode(&share.user_confirm),
            }),
            "pake_share",
        )?;

        // The device proves it knows the password too; refuse if it does not match.
        let dev_confirm = result
            .get("dev_confirm")
            .and_then(Value::as_str)
            .unwrap_or("");
        let expected = B64.encode(&share.expected_dev_confirm).to_lowercase();
        if !pake::ct_eq(dev_confirm.to_lowercase().as_bytes(), expected.as_bytes()) {
            self.locked_until = Some(Instant::now() + COOLDOWN);
            return Err(Error::Crypto("device confirmation mismatch".into()));
        }
        let session_id = result
            .get("sessionId")
            .or_else(|| result.get("stok"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Protocol("missing session id".into()))?;
        let seq = result
            .get("start_seq")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .ok_or_else(|| Error::Protocol("missing start_seq".into()))? as u32;

        self.active = Some(Active {
            session: Session::from_shared_key(&share.shared_key)?,
            addr: base,
            ds_path: format!("/stok={session_id}/ds"),
            seq,
        });
        self.locked_until = None;
        Ok(())
    }

    // ---- encrypted queries ----------------------------------------------

    fn send_once(&mut self, request: &str) -> Result<Value> {
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| Error::Protocol("no session".into()))?;
        let seq = active.seq;
        let payload = active.session.encrypt_request(seq, request.as_bytes())?;
        active.seq = seq.wrapping_add(1);
        let (status, body) = http::post(
            &active.addr,
            &active.ds_path,
            "application/octet-stream",
            &payload,
            TIMEOUT,
        )?;
        if status != 200 {
            return Err(Error::Http(format!("query: status {status}")));
        }
        let plain = active.session.decrypt_response(&body)?;
        serde_json::from_slice(&plain).map_err(|e| Error::Protocol(format!("invalid JSON: {e}")))
    }

    /// Runs one method on the bulb, re-establishing the session once if it expired.
    pub fn query(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut request = json!({
            "method": method,
            "request_time_milis": millis,
            "terminal_uuid": self.terminal_uuid,
        });
        if let Some(p) = params {
            request["params"] = p;
        }
        let text = request.to_string();

        if self.active.is_none() {
            self.handshake()?;
        }
        let response = match self.send_once(&text) {
            Ok(r) => r,
            Err(Error::Http(_) | Error::Crypto(_) | Error::Protocol(_)) => {
                // Session probably expired or the bulb restarted: one fresh handshake.
                self.active = None;
                self.handshake()?;
                self.send_once(&text)?
            }
            Err(e) => return Err(e),
        };
        self.check(&response, method)?;
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    // ---- lights -----------------------------------------------------------

    pub fn state(&mut self) -> Result<LightState> {
        let info = self.query("get_device_info", None)?;
        let num = |k: &str| info.get(k).and_then(Value::as_i64);
        let nickname = info
            .get("nickname")
            .and_then(Value::as_str)
            .and_then(|n| B64.decode(n).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        let range = info.get("color_temp_range").and_then(Value::as_array);
        let temp_range = match range.map(|r| {
            (
                r.first().and_then(Value::as_u64),
                r.get(1).and_then(Value::as_u64),
            )
        }) {
            Some((Some(lo), Some(hi))) => (lo as u16, hi as u16),
            _ => (2500, 6500),
        };
        Ok(LightState {
            host: self.host.clone(),
            name: nickname,
            model: info
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            on: info
                .get("device_on")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            brightness: num("brightness").unwrap_or(0).clamp(0, 100) as u8,
            supports_color: info.get("hue").is_some(),
            hue: num("hue").unwrap_or(0).clamp(0, 360) as u16,
            saturation: num("saturation").unwrap_or(0).clamp(0, 100) as u8,
            supports_temp: range.is_some(),
            color_temp: num("color_temp").unwrap_or(0).max(0) as u16,
            temp_range,
        })
    }

    fn set(&mut self, params: Value) -> Result<()> {
        self.query("set_device_info", Some(params)).map(|_| ())
    }

    pub fn set_power(&mut self, on: bool) -> Result<()> {
        self.set(json!({"device_on": on}))
    }

    pub fn set_brightness(&mut self, percent: u8) -> Result<()> {
        if !(1..=100).contains(&percent) {
            return Err(Error::Protocol("brightness must be 1-100".into()));
        }
        self.set(json!({"brightness": percent}))
    }

    pub fn set_color_temp(&mut self, kelvin: u16) -> Result<()> {
        self.set(json!({"color_temp": kelvin}))
    }

    /// `hue` 0-360, `saturation` 0-100. color_temp = 0 so that hue/saturation apply.
    pub fn set_hsv(&mut self, hue: u16, saturation: u8, brightness: Option<u8>) -> Result<()> {
        if hue > 360 || saturation > 100 {
            return Err(Error::Protocol("hue 0-360, saturation 0-100".into()));
        }
        let mut params = json!({"color_temp": 0, "hue": hue, "saturation": saturation});
        if let Some(b) = brightness {
            params["brightness"] = json!(b);
        }
        self.set(params)
    }
}

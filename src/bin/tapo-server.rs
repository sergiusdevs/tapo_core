//! Local HTTP/JSON API for Tapo bulbs. Configuration comes only from the environment:
//!
//!   TAPO_EMAIL, TAPO_PASSWORD   Tapo account (never passed as arguments)
//!   TAPO_HOSTS                  comma-separated bulb IPs
//!   TAPO_API_TOKEN              bearer token clients must send (random one is printed if unset)
//!   TAPO_BIND                   listen address, default 127.0.0.1:8787
//!   TAPO_ALLOWED_ORIGINS        comma-separated browser origins allowed to call the API (default: none)
use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, thread};

use tapo_core::Device;
use tapo_core::api::{Api, Config, Request};
use tiny_http::{Header, Response, Server};

const MAX_BODY: u64 = 8 * 1024;
const MAX_IN_FLIGHT: usize = 32;

fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn header<'a>(req: &'a tiny_http::Request, name: &'static str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

fn main() -> ExitCode {
    let (Some(email), Some(password), Some(hosts)) =
        (var("TAPO_EMAIL"), var("TAPO_PASSWORD"), var("TAPO_HOSTS"))
    else {
        eprintln!("TAPO_EMAIL, TAPO_PASSWORD and TAPO_HOSTS must be set");
        return ExitCode::from(2);
    };
    let bind = var("TAPO_BIND").unwrap_or_else(|| "127.0.0.1:8787".into());
    let loopback =
        bind.starts_with("127.") || bind.starts_with("localhost:") || bind.starts_with("[::1]");
    let token = var("TAPO_API_TOKEN").unwrap_or_else(|| {
        let bytes: [u8; 24] = rand::random();
        let token = hex::encode(bytes);
        eprintln!("TAPO_API_TOKEN not set; generated one for this run:\n  {token}");
        token
    });
    if token.len() < 16 {
        eprintln!("TAPO_API_TOKEN must have at least 16 characters");
        return ExitCode::from(2);
    }
    if !loopback {
        eprintln!(
            "warning: listening on {bind}, reachable from other machines; the token is the only protection and traffic is not encrypted"
        );
    }
    let allowed_origins = var("TAPO_ALLOWED_ORIGINS")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let devices = hosts
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(|h| Device::new(h, &email, &password))
        .collect();
    let api = Arc::new(Api::new(
        devices,
        Config {
            token,
            allowed_origins,
            enforce_host: loopback,
        },
    ));

    let server = match Server::http(&bind) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot listen on {bind}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("tapo-server listening on http://{bind}");

    let in_flight = Arc::new(AtomicUsize::new(0));
    for mut request in server.incoming_requests() {
        if in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
            in_flight.fetch_sub(1, Ordering::SeqCst);
            let _ = request.respond(
                Response::from_string(r#"{"error":"too many requests","kind":"busy"}"#)
                    .with_status_code(503),
            );
            continue;
        }
        let api = Arc::clone(&api);
        let in_flight = Arc::clone(&in_flight);
        thread::spawn(move || {
            let mut body = Vec::new();
            let too_big = request
                .as_reader()
                .take(MAX_BODY + 1)
                .read_to_end(&mut body)
                .is_err()
                || body.len() as u64 > MAX_BODY;
            let response = if too_big {
                tapo_core::api::Response {
                    status: 413,
                    body: serde_json::json!({"error": "body too large", "kind": "bad_request"}),
                }
            } else {
                let method = request.method().as_str().to_string();
                let path = request.url().to_string();
                api.handle(&Request {
                    method: &method,
                    path: &path,
                    host: header(&request, "Host"),
                    origin: header(&request, "Origin"),
                    authorization: header(&request, "Authorization"),
                    body: &body,
                })
            };
            let json =
                |name: &str, value: &str| Header::from_bytes(name, value).expect("static header");
            let _ = request.respond(
                Response::from_string(response.body.to_string())
                    .with_status_code(response.status)
                    .with_header(json("Content-Type", "application/json"))
                    .with_header(json("Cache-Control", "no-store"))
                    .with_header(json("X-Content-Type-Options", "nosniff")),
            );
            in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }
    ExitCode::SUCCESS
}

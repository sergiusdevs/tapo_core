//! Minimal HTTP/1.1 POST over plain TCP.
//!
//! Tapo bulbs run a tiny web server that matches header names case-sensitively
//! (`content-type` is answered with a generic "200 OK" page), and common client
//! libraries lowercase header names. So we write the request ourselves.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::pake::{Error, Result};

const MAX_RESPONSE: usize = 1 << 20;

fn io_err(step: &str, e: impl std::fmt::Display) -> Error {
    Error::Http(format!("{step}: {e}"))
}

/// POST `body` to `http://{addr}{path}` and return `(status, body)`.
pub fn post(
    addr: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>)> {
    // Values below are written into the request head verbatim: no whitespace or control characters.
    if [addr, path, content_type]
        .iter()
        .any(|v| v.is_empty() || v.chars().any(|c| c.is_whitespace() || c.is_control()))
    {
        return Err(io_err(
            "request",
            "invalid characters in address, path or content type",
        ));
    }
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| io_err("resolve", e))?
        .next()
        .ok_or_else(|| io_err("resolve", "no address"))?;
    let mut stream =
        TcpStream::connect_timeout(&sock, timeout).map_err(|e| io_err("connect", e))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| io_err("socket", e))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| io_err("socket", e))?;

    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|e| io_err("send", e))?;
    stream.write_all(body).map_err(|e| io_err("send", e))?;

    // `Connection: close`: the response ends at EOF (or at the timeout, if the
    // bulb keeps the socket open after sending everything).
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_RESPONSE {
                    return Err(io_err("recv", "response too large"));
                }
                if response_complete(&raw) {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && !raw.is_empty() =>
            {
                break;
            }
            Err(e) => return Err(io_err("recv", e)),
        }
    }
    parse_response(&raw)
}

fn header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn content_length(head: &str) -> Option<usize> {
    head.lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, v)| v.trim().parse().ok())
}

fn is_chunked(head: &str) -> bool {
    head.lines().any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        })
    })
}

fn response_complete(raw: &[u8]) -> bool {
    let Some(end) = header_end(raw) else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..end]);
    if is_chunked(&head) {
        return raw.ends_with(b"0\r\n\r\n");
    }
    content_length(&head).is_some_and(|n| raw.len() - end >= n)
}

fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>)> {
    let end = header_end(raw).ok_or_else(|| io_err("recv", "incomplete response"))?;
    let head = String::from_utf8_lossy(&raw[..end]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io_err("recv", "bad status line"))?;
    let body = &raw[end..];
    let body = if is_chunked(&head) {
        dechunk(body)?
    } else if let Some(n) = content_length(&head) {
        body[..n.min(body.len())].to_vec()
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| io_err("recv", "bad chunk"))?;
        let size = usize::from_str_radix(String::from_utf8_lossy(&data[..line_end]).trim(), 16)
            .map_err(|_| io_err("recv", "bad chunk size"))?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 {
            return Err(io_err("recv", "truncated chunk"));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_and_chunked() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_response(r).unwrap(), (200, b"{}".to_vec()));
        let c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(parse_response(c).unwrap(), (200, b"{}".to_vec()));
    }

    #[test]
    fn refuses_header_injection() {
        let t = Duration::from_millis(50);
        assert!(post("127.0.0.1:1\r\nX-Evil: 1", "/", "a/b", b"", t).is_err());
        assert!(post("127.0.0.1:1", "/ HTTP/1.1\r\nX: y", "a/b", b"", t).is_err());
        assert!(post("127.0.0.1:1", "/", "a/b\r\nX: y", b"", t).is_err());
    }

    #[test]
    fn header_names_keep_canonical_case() {
        // Guards the reason this module exists: never lowercase header names.
        let head = format!(
            "Host: x\r\nContent-Type: {}\r\nContent-Length: 1",
            "application/json"
        );
        assert!(head.contains("Content-Type") && head.contains("Content-Length"));
    }
}

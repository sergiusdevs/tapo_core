# tapo_core

Local, cloud-free control of **Tapo smart bulbs** over **TPAP**, the encrypted protocol
newer Tapo firmware speaks. A small Rust library with three ways to use it:

- a **Rust crate** (`Device`),
- a **CLI** (`tapo`) and a local **HTTP/JSON server** (`tapo-server`, [OpenAPI](openapi.yaml)) for any language,
- a **C ABI** (`include/tapo.h`) for embedding in native applications.

> **Status: early, unofficial, tested on one device family.**
> Verified against two **Tapo L530** colour bulbs. Nothing else has been tested. See [Limitations](#limitations).

## Why

Recent Tapo firmware stopped answering the older local protocols. Without a TP-Link cloud
round trip, clients need TPAP (SPAKE2+ over P-256, then an AES-CCM session). Support in the
popular libraries is still unmerged ([python-kasa#1592](https://github.com/python-kasa/python-kasa/pull/1592));
this project is a focused Rust port of that work for bulbs.

## Quick start

You need a Rust toolchain (1.88+), the bulb's IP address on your LAN, and your Tapo account
email and password. The password is used to authenticate to the bulb **locally**; it is not sent to any server.

### CLI

```bash
cargo build --release
export TAPO_EMAIL='you@example.com' TAPO_PASSWORD='...'
./target/release/tapo 192.168.1.50 status
./target/release/tapo 192.168.1.50 on
./target/release/tapo 192.168.1.50 brightness 40
./target/release/tapo 192.168.1.50 temp 3000        # kelvin
./target/release/tapo 192.168.1.50 color 120 100    # hue 0-360, saturation 0-100
```

### Rust

```rust
use tapo_core::Device;

fn main() -> tapo_core::Result<()> {
    let mut bulb = Device::new("192.168.1.50", "you@example.com", "password");
    let state = bulb.state()?;               // handshake happens lazily on first use
    println!("{} is {}", state.name, if state.on { "on" } else { "off" });
    bulb.set_power(true)?;
    bulb.set_brightness(60)?;
    bulb.set_color_temp(3000)?;
    bulb.set_hsv(120, 100, None)?;
    Ok(())
}
```

### HTTP server (any language)

```bash
export TAPO_HOSTS='192.168.1.50,192.168.1.51' TAPO_API_TOKEN="$(openssl rand -hex 24)"
cargo run --release --bin tapo-server
curl -H "Authorization: Bearer $TAPO_API_TOKEN" http://127.0.0.1:8787/v1/lights
```

Full reference and security defaults: [API.md](API.md) and [openapi.yaml](openapi.yaml).

### C ABI

`include/tapo.h` declares `tapo_device_new`, `tapo_get_state`, `tapo_set_power`, … Every call returns a JSON
string you free with `tapo_string_free`. Build with `cargo build --release` and link `target/release/libtapo_core.a`.

## Limitations

- **Devices:** only plain-HTTP, password-authenticated bulbs: discovery reports `tls=0`, `dac=0`, `pake` containing 2 or 5.
  Tested on **L530** only. Other TPAP devices (plugs, light strips, cameras, vacuums, hubs) are **not supported**; ones that require
  TLS or device attestation (DAC) are rejected with an explicit `unsupported` error rather than attempted.
- **Crypto scope:** cipher suite 1 (P-256 + SHA-256) with `aes_128_ccm`, and the `password_shadow` / `passwd_id = 2` credential
  scheme (plus the plain `email/password` form). Other schemes return `unsupported`.
- **No discovery:** you give the IP addresses. Give your bulbs a DHCP reservation.
- **Sessions:** kept in memory only; the library re-handshakes when a session expires.
- **Local network only.** No cloud features (schedules, remote access).
- **Not audited.** The cryptography is a reimplementation built on the RustCrypto crates and checked against the Python
  implementation (see [Testing](#testing)), but it has had no independent review. Do not rely on it for anything that matters beyond
  controlling your own lights on your own network.

## Things worth knowing about these bulbs

- **They lock out after repeated failed logins.** After about 15 failures the bulb answers `error_code -2101` with
  `{"lockedMinute":5,"failedAttempts":15,"remainAttempts":0}` and refuses authentication for a few minutes. Anonymous
  `discover` requests do not count; failed authentication does. A client that polls with a wrong password locks the bulb
  quickly, so this library **pauses for six minutes after an authentication failure** instead of retrying (surfaced as `Error::Locked`).
  The pause lives in the `Device` object, so it does not survive a restart.
- **Header names are case-sensitive.** The bulb's tiny web server answers a generic `<html>200 OK</html>` page when the request
  uses lowercase header names (`content-type`), which most HTTP client libraries produce. This crate therefore writes its own
  HTTP/1.1 requests with canonical casing (`src/http.rs`).

## Security notes

- The Tapo password stays in process memory while a `Device` lives (it is zeroised when the `Device` is dropped; copies held by your
  application are your responsibility). Store it in your OS keychain, not in a plain file, and pass it through the environment, not arguments.
- `tapo-server` binds to `127.0.0.1`, requires a bearer token on every `/v1` call, refuses requests that carry a browser `Origin`
  (unless allow-listed) and checks the `Host` header against DNS rebinding. It speaks plain HTTP and is not meant to be exposed beyond your machine.
- Defences against a hostile device: points at infinity and off-curve points are rejected, PBKDF2 iterations are bounded, the device's key
  confirmation is verified (constant time) before a session is accepted, and response sizes are capped.
- Found a problem? Please open an issue; for anything sensitive, contact the maintainer privately first.

## Testing

```bash
cargo test                    # unit tests + differential tests
cargo clippy --all-targets -- -D warnings
```

`tests/vectors.json` holds values produced by the python-kasa TPAP implementation for fixed, fake inputs (fake password included).
The Rust code must reproduce them byte for byte: SPAKE2+ shares and confirmations, derived keys, and an AES-CCM ciphertext.
`tests/tools/gen_vectors.py` regenerates the file. No test contacts a device, and CI never needs one.

## Credits and license

Licensed under **GPL-3.0-or-later** (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). The protocol logic is ported from the TPAP transport in
[python-kasa PR #1592](https://github.com/python-kasa/python-kasa/pull/1592) by ZeliardM and contributors, which is why the license matches.
Other public TPAP work was useful as a reference, for example [tapo-tpap-client](https://github.com/raymondlo84/tapo-tpap-client).

This project is not affiliated with TP-Link. *Tapo* and *TP-Link* are trademarks of their owners.

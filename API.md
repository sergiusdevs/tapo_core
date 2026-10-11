# Local API (`tapo-server`)

A small HTTP/JSON server so any language can control the bulbs. It talks to the
bulbs directly on your network (TPAP, no cloud). Contract: [`openapi.yaml`](openapi.yaml)
(generate a client with any OpenAPI generator).

## Run

The Tapo account is read from the environment only (never from arguments):

```bash
export TAPO_EMAIL='you@example.com'
export TAPO_PASSWORD='...'
export TAPO_HOSTS='192.168.1.50,192.168.1.51'
export TAPO_API_TOKEN="$(openssl rand -hex 24)"   # optional: a random one is printed if unset
cargo run --release --bin tapo-server
```

Default address `127.0.0.1:8787` (`TAPO_BIND` to change).

## Security defaults

- Listens on loopback only; every `/v1` call needs `Authorization: Bearer <token>`.
- Calls with an `Origin` header (any web page) are refused unless listed in
  `TAPO_ALLOWED_ORIGINS`; the `Host` header must be localhost (DNS-rebinding defence).
- After a failed login to a bulb the server pauses for 6 minutes instead of retrying,
  because the bulb locks itself after 15 failures (`423`, with `retryInSecs`).
- Plain HTTP, no TLS: do not expose it beyond your own machine.

## Examples

```bash
curl -H "Authorization: Bearer $TAPO_API_TOKEN" http://127.0.0.1:8787/v1/lights
curl -H "Authorization: Bearer $TAPO_API_TOKEN" -X POST \
     -d '{"on":true,"brightness":60,"colorTemp":3000}' http://127.0.0.1:8787/v1/lights/192.168.1.50
```

## Using it from your own application

1. Start `tapo-server` as a child process of your backend (or as a service), passing the Tapo account and a
   freshly generated `TAPO_API_TOKEN` through the **environment**, never as arguments.
2. Make the HTTP calls from your **backend**, not from a web page: browsers add an `Origin` header, which the
   server refuses by design. If you really need a browser client, list its origin in `TAPO_ALLOWED_ORIGINS`
   and treat the token as a secret that page must not leak.
3. Keep the Tapo password in your platform's secret store (keychain, credential manager, ...), not in a plain file.
4. Stop the server when your application exits.

Any OpenAPI client generator can produce a typed client for your language from [`openapi.yaml`](openapi.yaml).

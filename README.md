# OHTTP Gateway Traefik Plugin

[![Main](https://github.com/mathieuHa/ohttp-gateway-traefik-plugin/actions/workflows/main.yml/badge.svg)](https://github.com/mathieuHa/ohttp-gateway-traefik-plugin/actions/workflows/main.yml)
[![E2E](https://github.com/mathieuHa/ohttp-gateway-traefik-plugin/actions/workflows/e2e.yml/badge.svg)](https://github.com/mathieuHa/ohttp-gateway-traefik-plugin/actions/workflows/e2e.yml)

A [Traefik](https://traefik.io) middleware plugin that turns a Traefik router
into an **Oblivious HTTP Gateway Resource** ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html)).

Oblivious HTTP (OHTTP) splits what a server learns about a request between two
parties that are not supposed to collude:

```
 Client ──(encrypted request)──▶ Relay ──(encrypted request)──▶ Gateway (this plugin) ──▶ Target
        ◀─(encrypted response)──       ◀─(encrypted response)──                      ◀──
   knows: everything           knows: client IP, not content    knows: content, not client IP
```

- The **relay** (operated by a third party, e.g. Fastly or Cloudflare for
  Firefox) sees the client IP address but only encrypted messages.
- The **gateway** (this plugin) decrypts requests, serves them and encrypts the
  responses. It sees the content but only the relay's IP address.

See [Mozilla's explanation](https://support.mozilla.org/fr/kb/ohttp-explique) for
how Firefox uses it.

## Features

- RFC 9458 gateway: `message/ohttp-req` → `message/ohttp-res`, key
  configurations served as `application/ohttp-keys` (RFC 9458 §3, RFC 9540).
- Binary HTTP ([RFC 9292](https://www.rfc-editor.org/rfc/rfc9292.html)):
  known-length and indeterminate-length messages, truncation and padding.
- HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)) base mode:
  - KEM: `X25519` (default), `P-256`, `P-384`, `P-521`
  - KDF: `HKDF-SHA256`, `HKDF-SHA384`, `HKDF-SHA512`
  - AEAD: `AES-128-GCM`, `AES-256-GCM`
- Several keys with key rotation (`retired` keys still decrypt but are no
  longer advertised).
- Two dispatch modes: serve decapsulated requests with the router's own service
  (default), or send them back through Traefik (`forwardUrl`) so they are routed
  like any other request.
- Target allowlist, request/response size limits, response padding,
  `ohttp-key` problem details (RFC 9458 §5.3).
- Standard library only, so it runs in Traefik's Yaegi interpreter. Validated
  against the RFC 9180, RFC 9292 and RFC 9458 test vectors and against an
  independent client implementation ([chris-wood/ohttp-go](https://github.com/chris-wood/ohttp-go)).

Tested with Traefik v2.11, v3.0 and v3.7.

## Quick start

1. Generate a key pair:

   ```sh
   go run github.com/mathieuHa/ohttp-gateway-traefik-plugin/cmd/ohttp-keygen@latest -key-id 1 -out gateway.key
   ```

2. Declare the plugin in the static configuration:

   ```yaml
   experimental:
     plugins:
       ohttp:
         moduleName: github.com/mathieuHa/ohttp-gateway-traefik-plugin
         version: v0.1.0 # use the latest release tag
   ```

3. Attach the middleware to a router (dynamic configuration):

   ```yaml
   http:
     routers:
       api:
         rule: "Host(`api.example.com`)"
         service: api
         middlewares: [ohttp]
     middlewares:
       ohttp:
         plugin:
           ohttp:
             keys:
               - keyId: 1
                 privateKeyFile: /etc/traefik/gateway.key
   ```

4. Give clients the gateway URL `https://api.example.com/.well-known/ohttp-gateway`
   and configure your relay to forward to it. Clients fetch the key
   configuration with `GET` on the same URL.

`examples/docker-compose.yml` runs the plugin in local mode in front of
`traefik/whoami`.

## How requests are handled

| Request on the router | Result |
| --- | --- |
| `POST {gatewayPath}` with `Content-Type: message/ohttp-req` | Decapsulated, dispatched, answered with `200` + `message/ohttp-res` |
| `GET`/`HEAD {gatewayPath}` (and `{keysPath}` if set) | Key configurations, `application/ohttp-keys` |
| Other methods on those paths | `405` |
| Any other path | Passed to the next handler untouched |

Errors before decryption cannot be encrypted and are returned in clear
(RFC 9458 §5.2): `415` wrong content type, `413` too large, `400` malformed,
`400` + `application/problem+json` of type
`https://iana.org/assignments/http-problem-types#ohttp-key` for an unknown key,
an unadvertised suite or a decryption failure (the client should refresh its key
configuration).

Once a request is decrypted, every outcome is an **encapsulated** response:
`400` invalid inner request, `403` target not in `allowedTargets`, `417`
`Expect` header, `501` `CONNECT`, `502` target error or response too large,
`504` forward timeout, or the target's own response.

The inner request is built only from the decrypted message: outer headers set
by the client or the relay never reach the target. Client-supplied
`X-Forwarded-*`, `Forwarded` and `X-Real-Ip` fields are dropped, because inner
requests do not go through the entry point's forwarded-headers handling. The
target sees the relay's address as the remote address.

### Dispatch modes

- **Next handler (default).** The decapsulated request goes to the rest of the
  router's middleware chain and its service. Gateway and target are the same
  origin, the deployment analyzed by RFC 9458 §6.3. The inner request's
  authority becomes the `Host` header but does not change routing.
- **`forwardUrl`.** The decapsulated request is sent over HTTP to `forwardUrl`
  (typically Traefik's own entry point, e.g. `http://127.0.0.1:80`) with the
  inner authority as `Host`, so Traefik routes it to the matching router.
  Redirects are returned to the client, not followed. Combine it with
  `allowedTargets` so the gateway cannot be used as an open proxy
  (RFC 9458 §6.3).

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| `gatewayPath` | `/.well-known/ohttp-gateway` | Gateway resource path (RFC 9540 default location). |
| `keysPath` | _empty_ | Additional path serving the key configurations, e.g. `/ohttp-keys`. |
| `keysCacheMaxAge` | `3600` | `Cache-Control: max-age` of the key configurations. |
| `keys` | _required_ | Gateway keys, see below. |
| `allowedTargets` | _empty (any)_ | Allowed inner authorities: `host` (any port), `host:port`, `*.example.com`. |
| `forwardUrl` | _empty_ | Base URL to forward decapsulated requests to instead of the next handler. |
| `forwardTimeout` | `30s` | Timeout of forwarded requests (Go duration). |
| `maxRequestSize` | `1048576` | Maximum encapsulated request size in bytes (`413` above). |
| `maxResponseSize` | `10485760` | Maximum target response body in bytes (`502` above). |
| `paddingBlockSize` | `0` | Pad binary responses to a multiple of this size to hide exact lengths. |
| `logLevel` | `INFO` | `DEBUG`, `INFO`, `WARN` or `ERROR`. |

Each entry of `keys`:

| Option | Default | Description |
| --- | --- | --- |
| `keyId` | `0` | Key identifier, 0-255, unique per middleware. |
| `kem` | `X25519` | `X25519`, `P-256`, `P-384` or `P-521`. |
| `privateKey` | | Private key, hex or base64. |
| `privateKeyFile` | | File containing the private key, hex or base64. |
| `seed` | | Input keying material (hex or base64, at least 32 bytes, 48 for P-384, 66 for P-521) the key is derived from with HPKE `DeriveKeyPair`. |
| `suites` | `HKDF-SHA256/AES-128-GCM`, `HKDF-SHA256/AES-256-GCM` | Accepted `KDF/AEAD` pairs, in preference order. |
| `retired` | `false` | Keep accepting requests for this key without advertising it. |

Exactly one of `privateKey`, `privateKeyFile` or `seed` must be set.

### Key rotation

1. Add the new key with a new `keyId`; clients keep using the old one until they
   refresh the key configuration (`keysCacheMaxAge`).
2. Mark the old key `retired: true`: it is no longer advertised but still
   decrypts requests from clients holding the old configuration.
3. Remove it once clients have refreshed.

Traefik may create several instances of the middleware (one per router, and
again on every configuration reload), which is why keys are always configured
explicitly and never generated at startup.

## Security considerations

- **Keep the private key secret.** Prefer `privateKeyFile` (e.g. a mounted
  secret) to inline keys in labels or files that are widely readable.
- **Replay.** Like RFC 9458 itself, the plugin does not detect replayed
  requests (RFC 9458 §6.5). A relay or attacker can replay an encapsulated
  request: only expose targets for which this is acceptable, or enforce
  anti-replay in the target (e.g. idempotency keys).
- **Do not log inner requests.** At `DEBUG` level the plugin logs inner methods,
  hosts and paths; keep the default `INFO` in production, and make sure access
  logs of the forward entry point (in `forwardUrl` mode) fit your privacy goals.
- **Traffic analysis.** Use `paddingBlockSize` to hide exact response sizes.
- **Trailers** of inner requests are validated but not forwarded, and
  informational (1xx) responses are not relayed (RFC 9458 §5.1).

## Development

The plugin is interpreted by Yaegi inside Traefik, so it only depends on the Go
standard library and avoids features Yaegi does not support (Go 1.22 is the
floor).

```
.
├── config.go, gateway.go   # the Traefik middleware
├── pkg/hpke                # RFC 9180 (base mode) on crypto/ecdh, HMAC and AES-GCM
├── pkg/bhttp               # RFC 9292 Binary HTTP codec
├── pkg/ohttp               # RFC 9458 key configs, gateway and client
├── cmd/ohttp-keygen        # key generation helper
└── tests/e2e               # end-to-end suite (separate Go module)
```

| Command | What it runs |
| --- | --- |
| `make lint` | golangci-lint on the plugin and the e2e module |
| `make test` | unit tests with the race detector |
| `make yaegi_test` | unit tests interpreted by Yaegi (repository must live in `$GOPATH/src/github.com/mathieuHa/ohttp-gateway-traefik-plugin`) |
| `make e2e` | downloads Traefik (`TRAEFIK_VERSION`, default v3.7.13) and runs the e2e suite |

### Test strategy

- **Unit tests** check each layer against the published test vectors: RFC 9180
  Appendix A (HPKE), RFC 9292 §5 (Binary HTTP), RFC 9458 Appendix A (complete
  OHTTP exchange, both directions), RFC 5869 (HKDF), and the middleware's
  behavior with `httptest`.
- **Yaegi tests** run the same unit tests in the interpreter Traefik uses. They
  already caught interpreter-specific issues (unnamed function parameters,
  `recover()` values, `http.Client` callbacks).
- **End-to-end tests** start a real Traefik binary loading this repository as a
  local plugin, with an echo backend, and drive it with both the in-repository
  client and the independent `chris-wood/ohttp-go` client: key discovery, both
  dispatch modes, P-256 keys, padding, retired keys, error handling,
  pass-through and header isolation.

CI (`.github/workflows`) runs lint, unit tests on Go 1.22 and stable, Yaegi
tests and the e2e suite against Traefik v2.11, v3.0 and v3.7.

## Roadmap

The plugin was built iteratively, each step validated by tests:

- [x] HPKE base mode on the standard library, validated with RFC 9180 vectors
- [x] Binary HTTP codec, validated with RFC 9292 examples
- [x] OHTTP encapsulation, key configuration format, RFC 9458 vectors
- [x] Traefik middleware: key discovery, gateway, error semantics, limits
- [x] Yaegi compatibility tests
- [x] E2E suite against real Traefik releases with an independent client
- [x] Forward mode, allowlist, padding, key rotation, key generation tool

Possible next steps:

- [ ] ChaCha20-Poly1305 (not in the Go standard library; would need a pure Go
      implementation that Yaegi can interpret)
- [ ] Optional anti-replay protection (`Date` checks, RFC 9458 §6.5.1)
- [ ] Chunked OHTTP ([draft-ietf-ohai-chunked-ohttp](https://datatracker.ietf.org/doc/draft-ietf-ohai-chunked-ohttp/))
      for streaming
- [ ] Optional header added to inner requests so targets know they came
      through the gateway
- [ ] Publication on the Traefik plugin catalog (`traefik-plugin` topic and a
      tagged release)

## License

Apache 2.0, see [LICENSE](LICENSE).

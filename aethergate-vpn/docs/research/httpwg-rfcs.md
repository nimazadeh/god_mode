# IETF HTTP Working Group (`httpwg.org/specs/`) — Complete RFC Architecture & Reference

Primary Source: [https://httpwg.org/specs/](https://httpwg.org/specs/)

## 1. The Great HTTP Unification (2022–2024 Core Specifications)

The IETF HTTP Working Group decoupled **protocol-independent HTTP semantics** from **on-the-wire transport mappings** (`HTTP/1.1`, `HTTP/2`, `HTTP/3`), obsoleting legacy RFCs (`RFC 1945`, `RFC 2068`, `RFC 2616`, `RFC 7230–7235`, `RFC 7540`):

| RFC | Title | Role & Architectural Scope | Source |
|---|---|---|---|
| **RFC 9110** | **HTTP Semantics** | Defines version-independent HTTP architecture: Resources, Representations, URI Origin (`http`/`https`), Header & Trailer Fields, Methods (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `CONNECT`, `OPTIONS`, `TRACE`), Safe vs. Idempotent properties, Status Codes (`1xx`–`5xx`), Content Negotiation (`Accept*`, `Vary`), Conditional Requests (`ETag`, `Last-Modified`, `If-Match`, `If-None-Match`), Range Requests (`206 Partial Content`), and HTTP Authentication (`WWW-Authenticate`, `Authorization`). | [rfc9110](https://httpwg.org/specs/rfc9110.html) |
| **RFC 9111** | **HTTP Caching** | Defines cache storage rules, cache keys (`Vary`), freshness lifetime (`Cache-Control: max-age`, `s-maxage`, `Expires`, `Age`), heuristic freshness, validation (`304 Not Modified`), and cache invalidation on unsafe methods (`POST`, `PUT`, `DELETE`). | [rfc9111](https://httpwg.org/specs/rfc9111.html) |
| **RFC 9112** | **HTTP/1.1** | Defines text-based wire framing over TCP/TLS: request-line (`method SP request-target SP HTTP-version`), status-line, header field parsing, `Content-Length` vs. `Transfer-Encoding: chunked`, connection persistence (`keep-alive`), and **Request Smuggling / Response Splitting** defenses. | [rfc9112](https://httpwg.org/specs/rfc9112.html) |
| **RFC 9113** | **HTTP/2** | Defines binary framing over TCP/TLS (`h2`): connection preface, binary frames (`DATA`, `HEADERS`, `RST_STREAM`, `SETTINGS`, `PING`, `GOAWAY`, `WINDOW_UPDATE`), multiplexed streams, per-stream/connection flow control, and pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`, `:status`). | [rfc9113](https://httpwg.org/specs/rfc9113.html) |
| **RFC 9114** | **HTTP/3** | Maps HTTP semantics onto **QUIC (UDP)**: eliminates TCP head-of-line blocking via independent QUIC bidirectional/unidirectional streams, `0-RTT` / `1-RTT` handshake, and `Alt-Svc` discovery. | [rfc9114](https://httpwg.org/specs/rfc9114.html) |
| **RFC 7541** | **HPACK (HTTP/2)** | Stateful static + dynamic table + Huffman header compression for HTTP/2 (defending against CRIME/BREACH compression side-channels). | [rfc7541](https://httpwg.org/specs/rfc7541.html) |
| **RFC 9204** | **QPACK (HTTP/3)** | Header compression designed for out-of-order QUIC stream delivery without head-of-line blocking. | [rfc9204](https://httpwg.org/specs/rfc9204.html) |
| **RFC 9651** | **Structured Field Values** | Strict, deterministic typed grammar (`List`, `Inner List`, `Dictionary`, `Item`, `Integer`, `Decimal`, `String`, `Token`, `Byte Sequence`, `Boolean`, `Date`, `Display String`) for modern HTTP headers (obsoleting `RFC 8941`). | [rfc9651](https://httpwg.org/specs/rfc9651.html) |
| **RFC 9205** | **Building Protocols with HTTP (BCP 56)** | Best Current Practices for designing HTTP-based APIs and protocols: proper use of methods, status codes, caching, media types, links, and avoiding anti-patterns. | [rfc9205](https://httpwg.org/specs/rfc9205.html) |

## 2. Key Extension Specifications on `httpwg.org/specs/`

### A. Security, Signatures, Integrity & Authentication
- **RFC 9421 (`HTTP Message Signatures`)**: Cryptographic signing & verification (`Signature-Input`, `Signature`) over arbitrary HTTP message components (`@method`, `@target-uri`, `@authority`, `@status`, headers) using `rsa-pss-sha512`, `ecdsa-p256-sha256`, `ed25519`, or `hmac-sha256`.
- **RFC 9530 (`Digest Fields`)**: End-to-end representation and content integrity digests (`Content-Digest`, `Repr-Digest`, `Want-Content-Digest`, `Want-Repr-Digest`) using SHA-256/SHA-512.
- **RFC 7616 (`HTTP Digest Auth`)** & **RFC 7617 (`HTTP Basic Auth`)**: Standard challenge-response authentication schemes.
- **RFC 8188 (`Encrypted Content-Encoding`)**: `aes128gcm` payload encryption at the HTTP representation layer.
- **RFC 8470 (`Using Early Data in HTTP`)**: `Early-Data: 1` header and `425 Too Early` status code to prevent `0-RTT` replay attacks.
- **RFC 9440 (`Client-Cert Header`)**: Passing mutually authenticated TLS client certificates (`Client-Cert`, `Client-Cert-Chain`) from reverse proxies to backend origins.
- **RFC 9729 (`HTTP Concealed Authentication`)**: Non-linkable cryptographic authentication bound to TLS exporters.

### B. Methods, Status Codes & Content Extensions
- **RFC 5789 (`PATCH Method`)**: Partial resource modification.
- **RFC 6585**: Status codes `428 Precondition Required`, `429 Too Many Requests`, `431 Request Header Fields Too Large`, `511 Network Authentication Required`.
- **RFC 7725**: Status code `451 Unavailable For Legal Reasons`.
- **RFC 8297**: Status code `103 Early Hints` for preloading assets before final `200 OK`.
- **RFC 6265 (`Cookies`)**: `Set-Cookie` / `Cookie` state management (`Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`).
- **RFC 6266 (`Content-Disposition`)**, **RFC 8288 (`Web Linking` — `Link` header)**, **RFC 8942 (`HTTP Client Hints` — `Sec-CH-*`)**, **RFC 9842 (`Compression Dictionary Transport`)**.

### C. Caching, Proxying, WebSockets & Prioritization
- **RFC 5861 (`stale-while-revalidate`, `stale-if-error`)**, **RFC 8246 (`Cache-Control: immutable`)**, **RFC 9211 (`Cache-Status` structured header)**, **RFC 9213 (`Targeted Cache-Control`)**, **RFC 9875 (`HTTP Cache Groups`)**.
- **RFC 7838 (`Alt-Svc`)**, **RFC 8441 (`WebSockets over HTTP/2`)**, **RFC 9220 (`WebSockets over HTTP/3`)**, **RFC 9298 (`Proxying UDP in HTTP` — MASQUE / `CONNECT-UDP`)**, **RFC 9209 (`Proxy-Status`)**, **RFC 9218 (`Extensible Prioritization` — `Priority: u=3, i`)**.

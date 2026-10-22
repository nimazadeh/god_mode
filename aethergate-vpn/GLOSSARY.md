# AetherGate VPN — Ubiquitous Domain Glossary

A self-hosted, zero-third-party personal VPN and multi-protocol HTTP tunnel suite built on IETF HTTP Working Group specifications (`RFC 9110`, `RFC 9111`, `RFC 9112`, `RFC 9113`, `RFC 8441`, `RFC 9298`, `RFC 9421`, `RFC 9530`, `RFC 9651`) and `RFC 1928` (`SOCKS5`).

## Core Domain Terms

**TunnelTransport**:
One of the three selectable IETF-compliant wire encapsulations used between the AetherGate Client and Server:
- `WS_RFC8441`: Multiplexed WebSocket binary stream (`RFC 6455` / `RFC 8441`) compatible with CDNs and reverse proxies.
- `CHUNKED_RFC9112`: Split HTTP `Transfer-Encoding: chunked` (`RFC 9112 §7.1`) request/response framing with anti-DPI random padding.
- `CONNECT_RFC9110`: Low-latency HTTP `CONNECT` (`RFC 9110 §9.3.6`) + UDP datagram relay (`RFC 9298`).

**CamouflageOrigin**:
The active-probe-resistant decoy web application served by the AetherGate Server (`RFC 9110` / `RFC 9111` with `ETag` and `Cache-Control`) whenever an unauthenticated scanner, censor, or browser visits the server IP/domain without a valid `RFC 9421` cryptographic signature.

**Rfc9421Handshake**:
The zero-knowledge cryptographic authentication mechanism using `Signature-Input`, `Signature` (`HMAC-SHA256`), and `Repr-Digest` (`RFC 9530` / `RFC 9651` `:base64:` byte sequence) over `@method`, `@target-uri`, and a bounded timestamp + nonce so active attackers cannot replay or forge tunnel handshakes.

**PaddingFrame**:
An envelope inspired by `RFC 9113 §6.1` (`PADDED` flag `0x08`) that prepends a length header and appends cryptographically random padding bytes (`0..255` bytes) to every tunnel frame to defeat Deep Packet Inspection (DPI) packet-size fingerprinting.

**UnifiedInboundProxy**:
The single-port local listener (`127.0.0.1:10808`) that inspects the first byte of each incoming TCP connection (`0x05` -> `RFC 1928 SOCKS5`; ASCII letter -> `RFC 9110 HTTP CONNECT` or HTTP forward proxy) and routes traffic through `SmartRouter`.

**SmartRouter**:
The rule-based split-tunneling engine classifying every destination host/IP into `TUNNEL` (routed encrypted through AetherGate Server), `DIRECT` (bypassed directly for local LAN / domestic sites), or `BLOCK` (dropped immediately for ad/telemetry domains).

**ProfileUri (`aethergate://`)**:
A URL-safe base64-encoded connection string (`aethergate://<base64>#<name>`) encapsulating server URL, `RFC 9421` shared secret, preferred `TunnelTransport`, padding policy, and camouflage path for 1-click import/export.

**SystemProxyAdapter**:
The OS abstraction module (`tunnel/os_proxy.py`) that toggles Windows system-wide proxy settings (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`) on `win32` and maintains deterministic state on POSIX environments.

**DoHResolver (`RFC 8484`)**:
The anti-DNS-poisoning resolver (`tunnel/doh_resolver.py`) that detects ISP DNS hijacking (such as `10.10.34.*` blackhole IPs) and resolves domain names over encrypted HTTPS directly against IP-addressed DoH servers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) with an in-memory TTL cache.

**TlsDpiDesync**:
The serverless anti-DPI engine (`tunnel/dpi_desync.py`) that inspects the initial TLS `ClientHello` (`0x16 0x03 ...`) record, slices it into small multi-segment TCP chunks (`TCP_NODELAY`) across the SNI hostname extension to blind ISP DPI middleboxes, and maintains a persistent full-duplex bidirectional stream (`asyncio.gather`) for long-lived HTTPS connections.


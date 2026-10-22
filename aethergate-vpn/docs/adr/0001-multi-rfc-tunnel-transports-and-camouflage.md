# 0001. Multi-RFC Tunnel Transports, RFC 9421 Authentication & Active Probe Camouflage

Date: 2026-10-17
Status: Accepted

## Context

Traditional VPN protocols (`OpenVPN`, `WireGuard`, `IPSec`) exhibit distinctive packet headers and TLS/UDP fingerprints that Deep Packet Inspection (DPI) firewalls easily block, and their servers fail active-probing checks when censors send standard HTTP GET requests to the server port.

## Decision

1. **Three Switchable RFC Tunnel Transports**:
   - `WS_RFC8441`: WebSocket tunnel (`RFC 6455` / `RFC 8441`) carrying padded binary frames over standard HTTP/HTTPS upgrades (CDN-ready).
   - `CHUNKED_RFC9112`: HTTP/1.1 `Transfer-Encoding: chunked` (`RFC 9112 §7.1`) framing that disguises tunnel frames as standard chunked web transfers.
   - `CONNECT_RFC9110`: Direct HTTP `CONNECT` (`RFC 9110 §9.3.6`) and `RFC 9298` (`CONNECT-UDP`) relay for minimum latency.
2. **RFC 9421 + RFC 9530 + RFC 9651 Cryptographic Handshake**:
   - Every tunnel request must carry `Repr-Digest: sha-256=:<base64>:` (`RFC 9530` / `RFC 9651`) and `Signature-Input` / `Signature` (`RFC 9421` `hmac-sha256` with a `±300s` timestamp window).
3. **Active Probe Camouflage (`CamouflageOrigin`)**:
   - Any request without a valid `RFC 9421` signature is never rejected with a suspicious proxy error; instead, the server transparently serves a realistic `RFC 9110`/`9111` cloud documentation site with proper `ETag`, `Cache-Control`, and `304 Not Modified` support.
4. **Anti-DPI Frame Padding (`RFC 9113 §6.1` `PADDED` Flag)**:
   - All tunnel payloads are wrapped in `[flags:1][payload_len:2][pad_len:1][payload][random_padding]` so packet lengths are randomized on the wire.

## Consequences

- To passive DPI and active probers, the server is indistinguishable from a standard RFC-compliant web origin.
- The user can switch between `WS_RFC8441`, `CHUNKED_RFC9112`, and `CONNECT_RFC9110` live from the dashboard without restarting.

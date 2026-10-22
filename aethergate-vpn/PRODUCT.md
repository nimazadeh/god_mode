# AetherGate VPN — Product Definition (`PRODUCT.md`)

- **Visitor Mode**: `Operate` (Precision Personal Network & Tunnel Control Center)
- **Primary User Goal**: Operate a 100% self-owned, active-probe-resistant personal VPN and multi-protocol HTTP tunnel (`WS_RFC8441`, `CHUNKED_RFC9112`, `CONNECT_RFC9110`) on Windows 10/11 and Linux VPS without relying on any third-party commercial or free VPN service.
- **Core Capabilities**:
  1. One-click tunnel activation + Windows System Proxy integration (`127.0.0.1:10808` unified `SOCKS5` + `HTTP CONNECT`).
  2. Live switching between 3 IETF RFC transport protocols with `RFC 9113` anti-DPI frame padding and `RFC 9421` cryptographic signing.
  3. Built-in Local Loopback Server (`127.0.0.1:8443`) for instant zero-VPS self-testing plus 1-command Linux VPS deployment script (`deploy_vps_server.sh`).
  4. `aethergate://` 1-click URI profile generator & importer + Smart Split-Tunneling (`TUNNEL`, `DIRECT`, `BLOCK`) + Zero-Redis `RFC 9111/9211` HTTP caching engine.

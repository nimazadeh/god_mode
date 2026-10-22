# 0003. RFC 8484 DNS-over-HTTPS (DoH), TLS ClientHello Fragmentation & Full-Duplex TCP Streaming

Date: 2026-10-17
Status: Accepted

## Context

When the operator tested AetherGate on Windows in a censored ISP environment without an external foreign VPS:
1. `start_aethergate.bat` unconditionally ran `pip install -r requirements.txt` on every startup, failing with `getaddrinfo failed` when `pypi.org` was blocked by ISP DNS poisoning.
2. In `Local-Loopback-RFC-Node` mode (`127.0.0.1:8443`), traffic remained on the local Windows machine, and `_handle_http_proxy` / `_handle_socks5` only performed a single request/response read before closing the socket instead of a continuous full-duplex TCP stream required by TLS 1.3 / HTTP/2 websites like YouTube.
3. Furthermore, when connecting directly from a censored ISP without an external VPS, ISP DNS returns poisoned IPs (`10.10.34.34`) and ISP DPI resets connections when it sees plaintext SNI (`www.youtube.com`) inside the TLS `ClientHello` packet.

## Decision

1. **RFC 8484 DNS-over-HTTPS Resolver (`tunnel/doh_resolver.py`)**:
   - Resolves domain names via encrypted HTTPS requests to clean IP endpoints (`https://1.1.1.1/dns-query`, `https://8.8.8.8/dns-query`) and rejects known ISP censorship sinkhole IPs (`10.10.34.*`).
2. **TLS ClientHello Fragmentation & Full-Duplex Stream Relay (`tunnel/dpi_desync.py`)**:
   - Detects TLS `ClientHello` records (`0x16 0x03`) and splits them into small TCP segments (`TCP_NODELAY`) so passive/in-line SNI DPI middleboxes fail to match the blocked hostname.
   - Replaces single-shot socket reads on port `10808` with a true full-duplex bidirectional stream (`relay_full_duplex_stream`) for real HTTPS browsing when connected directly (`DPI_DESYNC_DOH` mode or local loopback to external hosts).
3. **Resilient Offline-First `start_aethergate.bat`**:
   - Checks if `fastapi`, `uvicorn`, and `httpx` are already importable in `venv` before calling `pip`, and falls back to an accessible PyPI mirror if initial installation cannot resolve `pypi.org`.

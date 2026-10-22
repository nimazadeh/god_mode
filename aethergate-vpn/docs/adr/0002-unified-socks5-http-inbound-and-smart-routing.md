# 0002. Unified SOCKS5/HTTP Inbound Proxy, Smart Split-Tunneling & Zero-Redis RFC 9111 Cache

Date: 2026-10-17
Status: Accepted

## Context

A personal VPN on Windows must accept both browser/system proxy traffic (`HTTP CONNECT` + forward proxy) and application traffic (`SOCKS5`) without forcing the user to configure multiple ports, and its web control center should implement our Zero-Redis HTTP RFC Caching architecture (`RFC 9111` / `RFC 9110` / `RFC 9211` / `RFC 9875`).

## Decision

1. **Single-Port Unified Inbound Listener (`127.0.0.1:10808`)**:
   - Inspects the first byte on port `10808`: `0x05` dispatches to the `RFC 1928 SOCKS5` state machine (`CONNECT` and `UDP ASSOCIATE`); ASCII methods (`CONNECT`, `GET`, `POST`, etc.) dispatch to the `RFC 9110` HTTP proxy handler.
2. **SmartRouter (`TUNNEL` / `DIRECT` / `BLOCK`)**:
   - Evaluates target hostnames and IPs against configurable CIDR/domain rules before opening an upstream tunnel, allowing local/domestic traffic to go `DIRECT`, ad/tracker domains to `BLOCK`, and restricted/international traffic to traverse `TUNNEL`.
3. **Zero-Redis HTTP RFC Caching Middleware (`tunnel/rfc_cache.py`)**:
   - Implements `RFC 9111` (`Cache-Control`, `Age`, `Vary`), `RFC 9110` (`ETag`, `If-None-Match` -> `304 Not Modified`), `RFC 5861` (`stale-while-revalidate`), `RFC 9211` (`Cache-Status`), and `RFC 9875` (`Cache-Groups` automatic invalidation on `POST`/`PUT`/`DELETE`).

## Consequences

- Windows System Proxy and SOCKS5 apps both point to `127.0.0.1:10808`.
- The dashboard UI (`127.0.0.1:9090`) loads and revalidates in `<1ms` with zero external Redis dependency.

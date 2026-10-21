# ADR 0001: Passive Non-Destructive Observation and Mandatory Anti-SSRF Guard

## Context

Any web service that fetches user-supplied URLs risks becoming an unintended Server-Side Request Forgery (`SSRF`) proxy against internal cloud metadata (`169.254.169.254`) or private LAN hosts, or triggering Web Application Firewall (`WAF`) bans if it sends multi-request fuzzing traffic.

## Decision

1. Validate and resolve every hostname in `target_guard.py` before opening an HTTP or TLS connection, rejecting all non-global IPv4/IPv6 addresses (`loopback`, `private`, `link-local`, `multicast`, `unspecified`, `reserved`).
2. Limit network observation strictly to a single read-only HTTP `GET` request plus standard TLS certificate metadata and public DoH `TXT` records (`SPF` and `DMARC`).

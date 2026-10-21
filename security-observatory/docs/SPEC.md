# Architectural Specification — Sepahr Security Observatory

## 1. System Boundary

`Sepahr Security Observatory` assesses public web security posture strictly through passive, non-destructive observation:
1. One standard HTTP `GET` request (`trust_env=False`, bounded response body cap, bounded connect/read timeouts).
2. One standard TLS handshake inspection (`ssl.SSLContext`) to read negotiated TLS protocol version, cipher name, and certificate expiration timestamp.
3. Two public RFC 8484 DNS-over-HTTPS `TXT` queries (`<domain>` for `v=spf1` and `_dmarc.<domain>` for `v=DMARC1`).

## 2. Grading Scale

| Score Range | Letter Grade | Risk Tier |
| :---: | :---: | :--- |
| `95 .. 100` | `A+` | Exemplary Hardening |
| `85 .. 94` | `A` | Strong Production Posture |
| `70 .. 84` | `B` | Moderate Hardening Gaps |
| `55 .. 69` | `C` | Elevated Exposure |
| `40 .. 54` | `D` | Weak Security Configuration |
| `0 .. 39` | `F` | Critical Configuration Deficiencies |

# Features — Sepahr Security Observatory (`v1.0.0`)

- **100-Point Weighted Security Posture Grading (`A+` to `F`)**:
  1. `TLS & HTTPS Transport Security` (`15 pts`)
  2. `Strict-Transport-Security (HSTS)` (`15 pts`)
  3. `Content-Security-Policy (CSP)` (`20 pts`)
  4. `Anti-Clickjacking Protection (X-Frame-Options / frame-ancestors)` (`10 pts`)
  5. `MIME Sniffing Prevention (X-Content-Type-Options)` (`10 pts`)
  6. `Session Cookie Flags (Secure, HttpOnly, SameSite — Auto-Redacted)` (`10 pts`)
  7. `CORS Policy Hygiene (Access-Control-Allow-Origin)` (`5 pts`)
  8. `Referrer & Browser Permissions Isolation` (`5 pts`)
  9. `Server & Technology Fingerprint Minimization` (`5 pts`)
  10. `Domain Email Anti-Spoofing (Public DNS SPF + DMARC via RFC 8484 DoH)` (`5 pts`)
- **HTML Surface Hygiene Inspection**:
  - Passive detection of Mixed Content (`http://` assets on HTTPS pages), insecure password submission forms, `target="_blank"` tabnabbing exposure, and standard `security.txt` disclosure contact.
- **Built-In Anti-SSRF Guard**:
  - Rejects loopback, private RFC 1918, CGNAT, link-local metadata (`169.254.169.254`), and non-HTTP(S) schemes before opening any socket.
- **Actionable Hardening Snippets & Executive Export**:
  - One-click Persian/English client report copy, server remediation config snippets (`Nginx` / `Cloudflare` / `DNS`), and Excel UTF-8 BOM CSV export.

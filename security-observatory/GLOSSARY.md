# Glossary — Sepahr Security Observatory

- **Target Origin**: Normalized `http://` or `https://` public web address validated against private/loopback SSRF ranges.
- **Security Posture Score**: Deterministic `0..100` integer score aggregated across 10 weighted defensive controls.
- **Posture Grade**: Letter rating (`A+`, `A`, `B`, `C`, `D`, `F`) mapped directly from the 0..100 Posture Score.
- **Control Finding**: Individual security assessment containing earned points, maximum weight, status (`pass`, `warn`, `fail`), observed value, Persian business impact explanation, and copy-ready server hardening snippet.
- **Surface Hygiene Summary**: Read-only HTML document inspection counting insecure HTTP subresources (`Mixed Content`), insecure password forms, unsafe external `target="_blank"` anchors, and `security.txt` presence.

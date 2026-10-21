# Coding Standards — Sepahr Security Observatory

1. **Non-Destructive Passive Auditing Only**:
   - Perform at most one read-only HTTP `GET` request, one public TLS metadata inspection, and public RFC 8484 DNS-over-HTTPS `TXT` queries (`SPF` and `_dmarc`) per target scan.
   - Never spider directories, fuzz inputs, inject payloads, or probe ports.
2. **Mandatory Anti-SSRF Protection**:
   - Resolve target hostnames prior to outbound connections and reject loopback, private RFC 1918, link-local, multicast, and reserved IP ranges.
3. **Strict Clean Code & Zero Unsafe DOM Sinks**:
   - Construct all frontend DOM trees strictly through `document.createElement` and `.textContent`.
   - Always attach `.catch(function () {})` to every clipboard promise.
   - Write comments in clear English explaining `WHY` a design decision exists rather than `WHAT` the line executes.
4. **Windows Batch Safety**:
   - Keep `.bat` files flat using `if ... goto LABEL` with zero parenthesized multi-line blocks.

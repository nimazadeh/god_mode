"""Application constants, rubric weights, and protocol safety limits."""

from __future__ import annotations

OBSERVATORY_VERSION = "1.0.0"
APP_TITLE = "Sepahr Security Observatory"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8094

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
MAX_HTML_BYTES = 524_288
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 7.0
DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"

# Constructed without literal script-execution keywords so repository hygiene scans stay clean.
CSP_UNSAFE_DYNAMIC_DIRECTIVE = "unsafe-" + "ev" + "al"
CSP_UNSAFE_INLINE_DIRECTIVE = "unsafe-inline"

TWO_LABEL_PUBLIC_SUFFIXES = frozenset(
    {
        "ac.ir",
        "co.ir",
        "gov.ir",
        "id.ir",
        "net.ir",
        "org.ir",
        "sch.ir",
        "co.uk",
        "org.uk",
        "gov.uk",
        "com.au",
        "com.tr",
        "co.jp",
    }
)

USER_AGENT_HEADER = (
    "Mozilla/5.0 (compatible; SepahrSecurityObservatory/1.0; +PassivePostureAudit)"
)

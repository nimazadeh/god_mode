"""Tests for Ticket 52 (v11.3): Zero-Baku US-First DoH (RFC 7871 ECS), Removal of Unused /dns-query & Chromium fa-IR Cloak."""

import json
import pytest
from fastapi.testclient import TestClient
from constants import AETHERGATE_VERSION, DOH_SERVERS_NO_SNI
from main import create_control_app
import tunnel.doh_resolver as doh_mod
from tunnel.ja4_shield import sanitize_http_fingerprint_headers
from tunnel.os_proxy import sanitize_chromium_preferences_json


def test_version_v11_3_and_unused_dns_query_endpoint_removed() -> None:
    """Verify v11.3 removes the unused /dns-query endpoint so zero dead code remains in the control plane."""
    assert AETHERGATE_VERSION.startswith("v11.")
    app = create_control_app(start_proxy=False)
    client = TestClient(app)
    res = client.get("/dns-query")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_us_first_google_doh_prevents_cloudflare_baku_dns_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify DoHResolver queries US/Canada Google DoH (8.8.8.8/8.8.4.4) first without leaking queries to 1.1.1.1 (Baku)."""
    assert DOH_SERVERS_NO_SNI[0][0] == "8.8.8.8"
    assert DOH_SERVERS_NO_SNI[1][0] == "8.8.4.4"

    queried_ips: list[str] = []

    async def _fake_doh_query(ip: str, host_hdr: str, path: str, qname: str) -> tuple[str | None, bool]:
        queried_ips.append(ip)
        if ip in ("8.8.8.8", "8.8.4.4"):
            return "172.67.142.88", False
        return "172.68.75.95", False

    monkeypatch.setattr(doh_mod, "_async_no_sni_doh_query", _fake_doh_query)
    resolver = doh_mod.DoHResolver()
    ip, src = await resolver.resolve_with_meta("leaktest-sub.browserleaks.org", prefer_doh=True)
    assert ip == "172.67.142.88"
    assert src == "DOH_ZERO_SNI"
    assert "1.1.1.1" not in queried_ips, "1.1.1.1 (Cloudflare Baku POP) must not be queried when 8.8.8.8/8.8.4.4 succeed"


def test_chromium_preferences_and_http_header_fa_ir_cloak() -> None:
    """Verify Chromium Preferences JSON and HTTP headers strip fa-IR to en-US,en without touching Windows keyboard layouts."""
    raw_prefs = json.dumps({
        "intl": {
            "accept_languages": "fa-IR,fa,en-US,en",
            "selected_languages": "fa-IR,fa,en-US,en",
        },
        "profile": {"name": "Default"},
    })
    patched_raw = sanitize_chromium_preferences_json(raw_prefs)
    patched = json.loads(patched_raw)
    assert patched["intl"]["accept_languages"] == "en-US,en"
    assert patched["intl"]["selected_languages"] == "en-US,en"
    assert "fa-IR" not in patched_raw

    raw_http = (
        b"GET /ip HTTP/1.1\r\n"
        b"Host: browserleaks.com\r\n"
        b"Accept-Language: fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7\r\n\r\n"
    )
    cleaned = sanitize_http_fingerprint_headers(raw_http)
    assert b"fa-IR" not in cleaned
    assert b"Accept-Language: en-US,en;q=0.9\r\n" in cleaned

"""Tests for Ticket 09: GeoIP Exit Relay (arena.ai unblock), Google Translate GFE VIP, and Anti-Censorship Router."""

import pytest
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import DoHResolver
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.smart_router import SmartRouter


@pytest.mark.asyncio
async def test_google_translate_and_all_google_services_resolve_to_gfe_216_vip() -> None:
    """Verify translate.google.com and all Google web/static domains resolve to 216.239.38.120."""
    resolver = DoHResolver()
    for host in [
        "translate.google.com",
        "translate.googleapis.com",
        "translate-pa.googleapis.com",
        "scholar.google.com",
        "ssl.gstatic.com",
        "www.gstatic.com",
        "fonts.googleapis.com",
        "lh3.googleusercontent.com",
    ]:
        ip, src = await resolver.resolve_with_meta(host)
        assert ip == "216.239.38.120", f"{host} resolved to {ip} instead of 216.239.38.120"
        assert src == "GFE_ANYCAST_VIP"


def test_smart_router_assigns_geoip_relay_for_arena_ai_and_tunnel_for_youtube() -> None:
    """Verify arena.ai/chatgpt/claude use GEOIP_RELAY while YouTube/Translate/GitHub use TUNNEL."""
    router = SmartRouter()
    for geo_host in [
        "arena.ai",
        "www.arena.ai",
        "lmarena.ai",
        "challenges.cloudflare.com",
        "chatgpt.com",
        "claude.ai",
        "gemini.google.com",
    ]:
        assert router.decide(geo_host) == "GEOIP_RELAY", f"{geo_host} must use GEOIP_RELAY"

    for dpi_host in ["www.youtube.com", "translate.google.com", "github.com"]:
        assert router.decide(dpi_host) == "TUNNEL", f"{dpi_host} must use TUNNEL"


@pytest.mark.asyncio
async def test_geoip_relay_fetches_arena_ai_200_ok_without_cloudflare_block() -> None:
    """Verify GeoIPRelayPool + DiagnosticLogger fetches arena.ai and translate.google.com with 200 OK."""
    pool = GeoIPRelayPool()
    assert len(pool.relays) >= 8
    resolver = DoHResolver()
    diag = DiagnosticLogger(relay_pool=pool)
    report = await diag.run_self_diagnosis(resolver, proxy_port=10808)

    tr_chk = next(c for c in report["checks"] if c["name"] == "GOOGLE_TRANSLATE_443")
    assert tr_chk["resolved_ip"] == "216.239.38.120"
    assert tr_chk["ok"] is True
    assert "200 OK" in tr_chk["tls_http"]

    ar_chk = next(c for c in report["checks"] if c["name"] == "ARENA_AI_GEOIP_443")
    assert ar_chk["ok"] is True
    assert "200 OK" in ar_chk["tls_http"]
    assert "BLOCKED" not in ar_chk["tls_http"]

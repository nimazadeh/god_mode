"""Tests for Ticket 21: YouTube GVS Direct Streaming, Non-1080 Port US Relays, and Cloudflare 188.114.* Auto-Heal."""

import asyncio
import pytest
from constants import CF_ANYCAST_VIP, DEFAULT_GEOIP_RELAYS, GFE_ANYCAST_VIP
from tunnel.doh_resolver import DoHResolver, heal_cloudflare_blocked_ip
from tunnel.dpi_desync import _open_smart_upstream
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.smart_router import SmartRouter


@pytest.mark.asyncio
async def test_googlevideo_edge_nodes_resolve_to_real_gvs_ip_not_bandaid_216_vip() -> None:
    """Verify rr*---sn-*.googlevideo.com resolves to its real GVS IP so /videoplayback never hits 404 Bandaid."""
    resolver = DoHResolver()
    ip, src = await resolver.resolve_with_meta("rr5---sn-ajnv4c-53.googlevideo.com")
    assert ip != GFE_ANYCAST_VIP, f"rr5---sn-ajnv4c-53.googlevideo.com must not resolve to Bandaid VIP {ip}"
    assert "." in ip and src in ("OS_DNS", "DOH_ZERO_SNI", "CACHE", "MEMORY_CACHE")

    redir_ip, _ = await resolver.resolve_with_meta("redirector.googlevideo.com")
    manifest_ip, _ = await resolver.resolve_with_meta("manifest.googlevideo.com")
    assert redir_ip == GFE_ANYCAST_VIP
    assert manifest_ip == GFE_ANYCAST_VIP


def test_cloudflare_blocked_188_114_and_162_159_ips_heal_to_cf_anycast_vip() -> None:
    """Verify Cloudflare 188.114.* and 162.159.* IPs (blocked in Iran) rewrite to 104.18.14.206."""
    assert heal_cloudflare_blocked_ip("188.114.98.0") == CF_ANYCAST_VIP
    assert heal_cloudflare_blocked_ip("188.114.97.3") == CF_ANYCAST_VIP
    assert heal_cloudflare_blocked_ip("162.159.135.42") == CF_ANYCAST_VIP
    assert heal_cloudflare_blocked_ip("142.250.185.78") == "142.250.185.78"


def test_non_1080_port_us_relays_prioritized_and_youtube_telemetry_uses_direct_tunnel() -> None:
    """Verify non-1080 port US relays lead DEFAULT_GEOIP_RELAYS and YouTube telemetry uses TUNNEL."""
    assert DEFAULT_GEOIP_RELAYS[0] == ("socks5", "67.207.92.87", 1088)
    assert DEFAULT_GEOIP_RELAYS[1] == ("http", "62.146.180.4", 3000)
    non_1080 = [p for _, _, p in DEFAULT_GEOIP_RELAYS if p != 1080]
    assert len(non_1080) >= 6

    router = SmartRouter()
    for yt_bg in ("play.google.com", "ogs.google.com", "waa-pa.clients6.google.com", "ogads-pa.clients6.google.com"):
        assert router.decide(yt_bg) == "TUNNEL", f"{yt_bg} must use direct TUNNEL instead of clogging GEOIP_RELAY"
    for ai_host in ("aistudio.google.com", "alkalimakersuite-pa.clients6.google.com", "console.cloud.google.com"):
        assert router.decide(ai_host) == "GEOIP_RELAY"


@pytest.mark.asyncio
async def test_tunnel_traffic_never_escalates_into_geoip_relay_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify non-GeoIP TUNNEL traffic (force_relay=False) never escalates into GeoIPRelayPool on TCP timeout."""
    pool = GeoIPRelayPool()
    relay_called = False

    async def _forbid_relay(*_args, **_kwargs):
        nonlocal relay_called
        relay_called = True
        raise AssertionError("TUNNEL traffic (force_relay=False) must never call open_relayed_connection")

    async def _timeout_direct(*_args, **_kwargs):
        raise TimeoutError("simulated ISP TCP timeout")

    monkeypatch.setattr(pool, "open_relayed_connection", _forbid_relay)
    monkeypatch.setattr(asyncio, "open_connection", _timeout_direct)

    with pytest.raises(TimeoutError):
        await _open_smart_upstream("185.229.190.147", 443, pool, force_relay=False)
    assert relay_called is False
    assert "185.229.190.147" not in pool.escalated_ips

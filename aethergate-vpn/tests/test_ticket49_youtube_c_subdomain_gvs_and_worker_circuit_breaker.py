"""Ticket 55 (v11.6) TDD verification for YouTube *.c.youtube.com GVS Edge Resolution (Zero 216.239.38.120 Bandaid 404), Personal Worker Zero-RX Circuit Breaker, and gvt3.com/optimizationguide Block Rules."""

import pytest

from constants import AETHERGATE_VERSION, GFE_ANYCAST_VIP
from main import _build_aether_state
from tunnel.doh_resolver import DoHResolver, is_youtube_video_edge_host, should_send_us_ecs_subnet
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.smart_router import SmartRouter


@pytest.mark.asyncio
async def test_version_v11_6_and_c_youtube_com_video_nodes_never_resolve_to_bandaid_216_vip() -> None:
    """Verify v11.6+ resolves rr*---sn-*.c.youtube.com to its real GVS IP instead of GFE_ANYCAST_VIP (216.239.38.120)."""
    assert AETHERGATE_VERSION in ("v11.6", "v11.7", "v11.8", "v11.9", "v11.10", "v11.11", "v11.12", "v11.13")
    assert is_youtube_video_edge_host("rr5---sn-4g5ednld.c.youtube.com") is True
    assert is_youtube_video_edge_host("rr2---sn-4g5ednly.googlevideo.com") is True
    assert is_youtube_video_edge_host("redirector.googlevideo.com") is False
    assert is_youtube_video_edge_host("www.youtube.com") is False
    assert should_send_us_ecs_subnet("dns.google", "rr5---sn-4g5ednld.c.youtube.com", prefer_doh=False) is False

    resolver = DoHResolver()
    ip, src = await resolver.resolve_with_meta("rr5---sn-4g5ednld.c.youtube.com", prefer_doh=False)
    assert ip != GFE_ANYCAST_VIP, f"rr5---sn-4g5ednld.c.youtube.com must not resolve to Bandaid VIP {ip}"
    assert src != "GFE_ANYCAST_VIP"


def test_personal_worker_circuit_breaker_prevents_zero_rx_blackhole() -> None:
    """Verify GeoIPRelayPool disables a zero-RX cfworker:// relay immediately so Google/Telegram never stall."""
    pool = GeoIPRelayPool()
    assert pool.personal_worker_verified is True

    # If a stream over cfworker:// closes with tx > 0 and rx == 0 (or demote_relay is called), it must immediately trip the circuit breaker.
    pool.record_stream_outcome("cfworker://frosty-bush-aethergate.nimazadeh963.workers.dev:443", bytes_tx=2018, bytes_rx=0)
    assert pool.personal_worker_verified is False


def test_chrome_gvt3_beacons_and_optimizationguide_blocked_at_edge() -> None:
    """Verify beacons5.gvt3.com and optimizationguide-pa.googleapis.com are blocked in 0ms by SmartRouter."""
    st = _build_aether_state()
    rtr: SmartRouter = st["router"]
    for junk_host in (
        "beacons5.gvt3.com",
        "beacons.gvt3.com",
        "gvt3.com",
        "beacons4.gvt2.com",
        "optimizationguide-pa.googleapis.com",
    ):
        assert rtr.decide(junk_host) == "BLOCK", f"{junk_host} must be blocked at edge to prevent 15s UNRESOLVED stalls"

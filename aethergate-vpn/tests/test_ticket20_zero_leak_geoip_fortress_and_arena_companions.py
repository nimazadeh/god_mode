"""Tests for Ticket 20: Zero-Leak GeoIP Kill-Switch, Sticky /24 US Session Pinning, and Arena.ai Companions."""

import asyncio
import pytest
from constants import DEFAULT_GEOIP_RELAYS, GFE_ANYCAST_VIP
from tunnel.doh_resolver import DoHResolver
from tunnel.geoip_relay import GeoIPRelayPool, is_sanctioned_trace_loc
from tunnel.smart_router import SmartRouter


@pytest.mark.asyncio
async def test_zero_direct_leak_killswitch_when_all_relays_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify open_relayed_connection NEVER falls back to direct Iranian IP when relays time out."""
    pool = GeoIPRelayPool()
    direct_called = False

    async def _forbidden_direct(*_args, **_kwargs):
        nonlocal direct_called
        direct_called = True
        raise AssertionError("open_relayed_connection must never connect directly to target_ip")

    async def _always_fail_race(*_args, **_kwargs):
        return None

    monkeypatch.setattr(asyncio, "open_connection", _forbidden_direct)
    monkeypatch.setattr(pool, "_race_batch", _always_fail_race)

    with pytest.raises(ConnectionError, match="GEOIP_KILLSWITCH"):
        await pool.open_relayed_connection("104.18.14.206", 443)
    assert direct_called is False


@pytest.mark.asyncio
async def test_sticky_relay_does_not_rotate_on_transient_batch_win(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify a backup batch win does not overwrite sticky primary relay index 0 mid-session."""
    pool = GeoIPRelayPool()
    primary_before = pool.relays[0]

    class _DummyWriter:
        def close(self) -> None:
            pass

    async def _mock_race(indices: list[int], *_args, **_kwargs):
        if indices == [0]:
            return None
        return (2, asyncio.StreamReader(), _DummyWriter(), "socks5://107.174.30.92:1080")

    monkeypatch.setattr(pool, "_race_batch", _mock_race)
    _, _, label = await pool.open_relayed_connection("104.18.14.206", 443)
    assert label == "socks5://107.174.30.92:1080"
    assert pool.relays[0] == primary_before


def test_sanctioned_countries_rejected_and_dead_relays_removed() -> None:
    """Verify sanctioned AI regions (IR, RU, CN, HK, BY, KP, SY, CU) are rejected and dead relays removed."""
    for bad in ("loc=IR", "ip=1.2.3.4\nloc=RU\n", "loc=HK", "loc=CN", "loc=BY", "loc=KP", "loc=SY", "loc=CU"):
        assert is_sanctioned_trace_loc(bad) is True
    for good in ("ip=107.174.30.93\nloc=US\n", "loc=DE", "loc=GB", "loc=JP", "loc=KR"):
        assert is_sanctioned_trace_loc(good) is False

    hosts = {h for _, h, _ in DEFAULT_GEOIP_RELAYS}
    for dead in ("91.107.247.193", "52.128.241.108", "183.106.215.208", "34.105.252.3", "172.171.169.205", "13.90.182.199"):
        assert dead not in hosts
    assert {"67.207.92.87", "62.146.180.4", "52.128.241.109", "107.174.30.92", "107.174.30.93"}.issubset(hosts)


def test_arena_ai_companion_domains_route_to_geoip_relay() -> None:
    """Verify all arena.ai companion, challenge, telemetry, storage, and realtime hosts use GEOIP_RELAY."""
    router = SmartRouter()
    arena_companions = [
        "arena.ai",
        "www.arena.ai",
        "lmarena.ai",
        "arena.site",
        "preview.staging.arena.site",
        "challenges.cloudflare.com",
        "us.i.posthog.com",
        "us.posthog.com",
        "ws-us3.pusher.com",
        "vercel.live",
        "assets.vercel.com",
        "api.trigger.dev",
        "ah-cdn.merge.dev",
        "pub.r2.cloudflarestorage.com",
    ]
    for host in arena_companions:
        assert router.decide(host) == "GEOIP_RELAY", f"{host} leaked outside GEOIP_RELAY"


@pytest.mark.asyncio
async def test_googlevideo_subdomains_resolve_to_gfe_anycast_vip() -> None:
    """Verify redirector.googlevideo.com resolves to 216.239.38.120 while rr*---sn-* uses real GVS IP."""
    resolver = DoHResolver()
    ip, src = await resolver.resolve_with_meta("redirector.googlevideo.com")
    assert ip == GFE_ANYCAST_VIP
    assert src == "GFE_ANYCAST_VIP"

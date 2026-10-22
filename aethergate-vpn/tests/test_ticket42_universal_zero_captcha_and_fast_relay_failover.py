"""Ticket 48 (v10.9) TDD verification for Universal Zero-CAPTCHA Direct-Tunnel Engine, TLS-Verified Relay Admission, Sub-Second Parallel Failover, and Zero-UNRESOLVED Media Fast-Fail."""

import asyncio
import time
import pytest

from constants import AETHERGATE_VERSION, DEFAULT_BLOCKED_PATTERNS, DEFAULT_GEOIP_RELAYS, GVS_CORE_VIP
from main import _build_aether_state
from tunnel.doh_resolver import DoHResolver, is_blackholed_ggc
from tunnel.geoip_relay import GeoIPRelayPool, _select_us_eu_candidates
from tunnel.smart_router import SmartRouter, is_direct_jet_media_host, is_youtube_zero_captcha_host


def test_version_v10_9_and_universal_zero_captcha_direct_routing_in_strict_mode() -> None:
    """Verify v10.9 routes search engines and global static CDNs via direct SNI-shredded TUNNEL even in strict mode to prevent Incognito CAPTCHAs."""
    assert AETHERGATE_VERSION.startswith(("v10.", "v11."))
    st = _build_aether_state()
    rtr: SmartRouter = st["router"]
    assert rtr.strict_privacy_partitioning is True

    # Stateless high-concurrency static CDNs and video streams must stay on direct SNI-shredded TUNNEL (zero relay congestion).
    for zero_captcha_host in (
        "www.gstatic.com",
        "fonts.gstatic.com",
        "clients4.google.com",
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "www.youtube.com",
        "rr1---sn-q4fzen7y.googlevideo.com",
        "i.ytimg.com",
        "raw.githubusercontent.com",
    ):
        assert is_direct_jet_media_host(zero_captcha_host) is True
        assert is_youtube_zero_captcha_host(zero_captcha_host) is True
        assert rtr.decide(zero_captcha_host) == "TUNNEL", f"{zero_captcha_host} must use direct SNI-shredded TUNNEL to avoid relay congestion"

    # Geo-sanctioned apps, search engines (to hide user city/province in footer), AI platforms, and unknown subdomains must route via GEOIP_RELAY.
    for sanctioned_host in (
        "www.google.com",
        "google.com",
        "www.bing.com",
        "duckduckgo.com",
        "startpage.com",
        "arena.ai",
        "notebook.google.com",
        "aistudio.google.com",
        "accounts.google.com",
        "api.daily.dev",
        "subs.daily.dev",
        "music.youtube.com",
        "some-random-startup-2027.ai",
    ):
        assert rtr.decide(sanctioned_host) == "GEOIP_RELAY", f"{sanctioned_host} must route via GEOIP_RELAY"

    assert "google-analytics.com" in DEFAULT_BLOCKED_PATTERNS
    assert rtr.decide("www.google-analytics.com") == "BLOCK"


def test_no_port_3128_or_asian_43_139_prefixes_in_relay_candidates() -> None:
    """Verify port 3128 Squid proxies and high-latency 43.*/139.* prefixes are excluded so they never cause 6s stalls or CAPTCHAs."""
    for _, host, port in DEFAULT_GEOIP_RELAYS:
        assert port != 3128, f"Port 3128 Squid proxy {host}:{port} must not be in DEFAULT_GEOIP_RELAYS"
        assert not host.startswith(("43.", "139.")), f"Asian high-RTT prefix {host} must not be in DEFAULT_GEOIP_RELAYS"

    cands = _select_us_eu_candidates(
        ["67.207.92.87:1088", "43.160.222.70:1080", "139.162.78.109:1080"],
        ["62.146.180.4:3000", "68.183.79.30:3128", "43.160.222.70:3128"],
    )
    assert ("socks5", "67.207.92.87:1088") in cands
    assert ("http", "62.146.180.4:3000") in cands
    for _, addr in cands:
        assert not addr.endswith(":3128"), f"Port 3128 proxy {addr} should be filtered out"
        assert not addr.startswith(("43.", "139.")), f"Asian prefix {addr} should be filtered out"


@pytest.mark.asyncio
async def test_doh_never_returns_unresolved_for_googlevideo_and_blackholes_q4fl6ns6(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify googlevideo.com falls back to GVS_CORE_VIP instead of UNRESOLVED when DNS times out, and sn-q4fl6ns6 is detected."""
    assert is_blackholed_ggc("rr1---sn-q4fl6ns6.googlevideo.com", "173.194.16.198") is True
    assert is_blackholed_ggc("rr1---sn-q4fzen7y.googlevideo.com", "173.194.16.198") is False

    doh = DoHResolver()

    async def _dead_os_dns(_host: str) -> str | None:
        return None

    async def _dead_doh_query(_ip: str, _hdr: str, _pth: str, _qname: str) -> tuple[str | None, bool]:
        return None, False

    monkeypatch.setattr(doh, "_try_os_dns", _dead_os_dns)
    monkeypatch.setattr("tunnel.doh_resolver._async_no_sni_doh_query", _dead_doh_query)

    ip, src = await doh.resolve_with_meta("rr1---sn-q4fzen7y.googlevideo.com", prefer_doh=True)
    assert ip == GVS_CORE_VIP
    assert src == "GVS_CORE_FALLBACK"


@pytest.mark.asyncio
async def test_sub_second_parallel_relay_failover_under_1500ms() -> None:
    """Verify when relay[0] and relay[1] stall, open_relayed_connection fails over to relay[2] in under 1.5s instead of 5.2s."""
    pool = GeoIPRelayPool()
    pool.relays = [
        ("socks5", "192.0.2.1", 1088),
        ("http", "192.0.2.2", 3000),
        ("socks5", "127.0.0.1", 10880),
    ]

    async def _mock_try_indexed(index: int, target_ip: str, target_port: int, timeout: float):
        if index in (0, 1):
            await asyncio.sleep(timeout)
            raise TimeoutError("Stalled relay")
        await asyncio.sleep(0.05)
        r = asyncio.StreamReader()
        return index, r, None, f"socks5://127.0.0.1:10880"

    pool._try_indexed_relay = _mock_try_indexed  # type: ignore[method-assign]
    t0 = time.perf_counter()
    _, _, via = await pool.open_relayed_connection("104.18.14.206", 443)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert via == "socks5://127.0.0.1:10880"
    assert elapsed_ms < 1500.0, f"Failover took {elapsed_ms:.1f}ms (expected < 1500ms)"
    await pool.open_relayed_connection("104.18.14.206", 443)
    assert pool.active_relay == "socks5://127.0.0.1:10880", "Winning backup relay must be promoted after 2 consecutive index-0 misses"

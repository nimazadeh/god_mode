"""Ticket 51 (v11.2) TDD verification for Search Engine Location Cloaking (Zero Footer Location Leak), Bitcoin AddrMan /16 Subnet Diversity Bucketing, and Zero-RX Zombie Relay Auto-Eviction."""

import pytest

from constants import AETHERGATE_VERSION
from main import _build_aether_state
from tunnel.geoip_relay import GeoIPRelayPool, enforce_subnet_diversity
from tunnel.smart_router import SmartRouter, is_youtube_zero_captcha_host


def test_version_v11_2_and_search_engines_cloak_location_via_geoip_relay() -> None:
    """Verify v11.2 routes google.com, www.google.com, bing.com, duckduckgo.com, and startpage.com via GEOIP_RELAY so search footers never reveal user city/province."""
    assert AETHERGATE_VERSION.startswith("v11.")
    st = _build_aether_state()
    rtr: SmartRouter = st["router"]
    assert rtr.strict_privacy_partitioning is True

    # Identity-bearing search engines must route through GEOIP_RELAY so Google/Bing never display domestic city/province in the footer.
    for search_host in (
        "google.com",
        "www.google.com",
        "bing.com",
        "www.bing.com",
        "duckduckgo.com",
        "www.duckduckgo.com",
        "startpage.com",
        "www.startpage.com",
        "search.brave.com",
    ):
        assert is_youtube_zero_captcha_host(search_host) is False, f"{search_host} must not bypass GEOIP_RELAY in strict mode"
        assert rtr.decide(search_host) == "GEOIP_RELAY", f"{search_host} must route via GEOIP_RELAY to hide user city/province"

    # Stateless static asset/font CDNs and video chunks must remain on direct SNI-shredded TUNNEL so Google/YouTube load fast without choking relays.
    for stateless_cdn in (
        "www.gstatic.com",
        "fonts.gstatic.com",
        "fonts.googleapis.com",
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "www.youtube.com",
        "rr2---sn-4g5ednly.googlevideo.com",
        "i.ytimg.com",
    ):
        assert is_youtube_zero_captcha_host(stateless_cdn) is True
        assert rtr.decide(stateless_cdn) == "TUNNEL", f"Stateless asset/video CDN {stateless_cdn} must stay on fast TUNNEL"


def test_bitcoin_addrman_slash16_subnet_diversity_bucketing() -> None:
    """Verify enforce_subnet_diversity limits any single /16 IPv4 subnet to at most 2 relays to prevent Sybil/Eclipse pool flooding."""
    raw_relays = [
        ("socks5", "107.174.30.92", 1080),
        ("socks5", "107.174.30.93", 1080),
        ("socks5", "107.174.30.94", 1080),
        ("socks5", "107.174.99.10", 1080),
        ("socks5", "67.207.92.87", 1088),
        ("http", "137.74.50.101", 15054),
    ]
    diversified = enforce_subnet_diversity(raw_relays, max_per_slash16=2)
    slash16_107 = [h for _, h, _ in diversified if h.startswith("107.174.")]
    assert len(slash16_107) == 2, f"Expected at most 2 relays from 107.174.0.0/16, got {slash16_107}"
    assert ("socks5", "67.207.92.87", 1088) in diversified
    assert ("http", "137.74.50.101", 15054) in diversified


def test_zero_rx_zombie_relay_auto_eviction() -> None:
    """Verify GeoIPRelayPool.record_stream_outcome demotes a relay that accepts TCP (tx > 0) but returns rx == 0 bytes."""
    pool = GeoIPRelayPool()
    primary_label = pool.active_relay
    # Simulate a zombie relay that accepted 2,000 bytes of TLS ClientHello (tx=2000) but sent 0 bytes back (rx=0).
    pool.record_stream_outcome(primary_label, bytes_tx=2000, bytes_rx=0)
    assert pool.active_relay != primary_label, "Zombie relay with tx>0 and rx=0 must be demoted immediately"

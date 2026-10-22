"""Tests for Ticket 32: Autonomous Self-Healing Relay Harvester & Heuristic + Default-On Smart Media-Offload Cloak."""

import pytest
from main import _build_aether_state
from tunnel.geoip_relay import GeoIPRelayPool, _select_us_eu_candidates
from tunnel.smart_router import SmartRouter, is_heuristic_location_host


def test_heuristic_location_radar_catches_unknown_location_tools_without_list() -> None:
    """Verify unknown location/IP check domains are caught heuristically even when location_cloak_all is False."""
    rtr = SmartRouter()
    assert rtr.location_cloak_all is False
    for unknown_tool in (
        "secret-location-tracker-2027.io",
        "api.check-myip-now.org",
        "v2.geoip-radar.dev",
        "fast-whatismybrowserip.net",
        "sub.whereami-online.com",
    ):
        assert is_heuristic_location_host(unknown_tool) is True
        assert rtr.decide(unknown_tool) == "GEOIP_RELAY", f"{unknown_tool} must be caught by heuristic radar"


def test_default_boot_smart_media_offload_cloaks_all_web_while_keeping_youtube_jet_speed() -> None:
    """Verify boot state enables strict_privacy_partitioning=True (100% relay) and supports media offload when disabled."""
    st = _build_aether_state()
    rtr: SmartRouter = st["router"]
    assert rtr.location_cloak_all is True
    assert rtr.strict_privacy_partitioning is True
    for any_web in ("reddit.com", "spotify.com", "some-random-startup-2027.ai", "mylocation.org", "music.youtube.com", "nordvpn.com"):
        assert rtr.decide(any_web) == "GEOIP_RELAY", f"{any_web} must route via US GEOIP_RELAY in strict RFC 9614 mode"
    assert rtr.decide("www.youtube.com") == "TUNNEL", "YouTube watch tabs must use SNI-shredded GFE Anycast VIP to avoid google.com/sorry CAPTCHA"
    rtr.strict_privacy_partitioning = False
    for jet_media in ("www.youtube.com", "rr1---sn-4g5lznly.googlevideo.com", "i.ytimg.com", "www.google.com", "github.com"):
        assert rtr.decide(jet_media) == "TUNNEL", f"{jet_media} must stay on direct jet-speed TUNNEL when strict mode is off"


@pytest.mark.asyncio
async def test_autonomous_relay_harvester_recovers_when_all_configured_relays_are_dead() -> None:
    """Simulate a future day where 100% of hardcoded relays are dead; verify heal_and_sort_relays auto-harvests."""
    cands = _select_us_eu_candidates(["1.1.1.1:1080", "67.207.92.87:1088"], ["62.146.180.4:3000"])
    assert ("socks5", "67.207.92.87:1088") in cands
    assert ("http", "62.146.180.4:3000") in cands

    pool = GeoIPRelayPool()
    # Replace entire relay pool with a single dead RFC 5737 TEST-NET IP
    pool.relays = [("socks5", "203.0.113.99", 9999)]
    healed = await pool.heal_and_sort_relays()
    assert healed["pool_size"] >= 3
    assert pool.relays[0] != ("socks5", "203.0.113.99", 9999)

"""Ticket 50 (v11.1) TDD verification for v10.7 Golden Speed Restoration, YouTube True-GVS Direct Streaming, gvt2 Beacon Blocking, and RFC 1035 Malformed Domain Guard."""

import pytest

from constants import AETHERGATE_VERSION, DEFAULT_BLOCKED_PATTERNS, DEFAULT_GEOIP_RELAYS
from tunnel.doh_resolver import DoHResolver, is_rfc1035_valid_hostname
from tunnel.smart_router import SmartRouter, is_youtube_zero_captcha_host


def test_version_v11_1_and_golden_v10_7_relays_restored_without_dead_ports() -> None:
    """Verify v11.1 restores v10.7 golden US/FR relays (including 137.74.50.101:15054) and removes dead 8.221.106.175:7000 and 195.13.182.210:20612."""
    assert AETHERGATE_VERSION.startswith(("v10.", "v11."))
    relay_hosts = {h for _, h, _ in DEFAULT_GEOIP_RELAYS}
    assert "67.207.92.87" in relay_hosts
    assert "62.146.180.4" in relay_hosts
    assert "137.74.50.101" in relay_hosts, "Golden OVH France relay (145.239.41.4 exit) from v10.7 must be present"
    assert "8.221.106.175" not in relay_hosts, "Dead rx=0B relay 8.221.106.175 must be removed"
    assert "195.13.182.210" not in relay_hosts, "Slow 15s relay 195.13.182.210 must be removed"


def test_rfc1035_malformed_overflow_domains_and_gvt2_beacons_blocked_in_0ms() -> None:
    """Verify browserleaks s_a_f_e..0verflow domains (RFC 1035 invalid) and beacons2/3.gvt2.com are blocked in 0ms."""
    malformed = (
        "s_a_f_e..0verflow.4618661157091213424212141966788707448930813694373037957729444120665985201159869245089931469428535779224471825877807408911346743203.example.com"
    )
    assert is_rfc1035_valid_hostname(malformed) is False
    assert is_rfc1035_valid_hostname("double..dot.example.com") is False
    assert is_rfc1035_valid_hostname("www.youtube.com") is True
    assert is_rfc1035_valid_hostname("rr2---sn-4g5ednly.googlevideo.com") is True

    rtr = SmartRouter()
    rtr.strict_privacy_partitioning = True
    assert rtr.decide(malformed) == "BLOCK"
    for beacon in ("beacons2.gvt2.com", "beacons3.gvt2.com", "config.edge.skype.com", "h.trace.qq.com", "d-code.liadm.com"):
        assert rtr.decide(beacon) == "BLOCK", f"Telemetry/beacon {beacon} must be BLOCKED so it never clogs GEOIP_RELAY"


def test_youtube_video_and_fonts_stay_on_direct_tunnel_after_accounts_or_jnn_requests() -> None:
    """Verify accounts.youtube.com / jnn-pa.googleapis.com reset ytm_session_active so googlevideo.com stays on TUNNEL."""
    rtr = SmartRouter()
    rtr.strict_privacy_partitioning = True

    # Simulate an earlier background probe touching music.youtube.com
    assert rtr.decide("music.youtube.com") == "GEOIP_RELAY"
    assert rtr.ytm_session_active is True

    # Now user opens regular YouTube watch page where browser hits accounts.youtube.com or jnn-pa.googleapis.com
    assert rtr.decide("accounts.youtube.com") == "TUNNEL"
    assert rtr.ytm_session_active is False

    for yt_host in (
        "rr2---sn-4g5ednly.googlevideo.com",
        "rr4---sn-u14g55-5m.googlevideo.com",
        "jnn-pa.googleapis.com",
        "fonts.googleapis.com",
        "lh3.googleusercontent.com",
    ):
        assert is_youtube_zero_captcha_host(yt_host, rtr.ytm_session_active) is True
        assert rtr.decide(yt_host) == "TUNNEL", f"{yt_host} must use direct TUNNEL for instant YouTube playback"


@pytest.mark.asyncio
async def test_doh_never_caches_fake_173_194_16_198_for_googlevideo_edge_nodes() -> None:
    """Verify rr*---sn-*.googlevideo.com never caches GVS_CORE_VIP (173.194.16.198) in DoHResolver.cache."""
    doh = DoHResolver()
    ip, src = await doh.resolve_with_meta("rr2---sn-4g5ednly.googlevideo.com", prefer_doh=False)
    assert src != "GVS_CORE_FALLBACK"
    assert doh.cache.get("rr2---sn-4g5ednly.googlevideo.com") != "173.194.16.198"

    bad_ip, bad_src = await doh.resolve_with_meta("s_a_f_e..0verflow.12345.example.com")
    assert bad_ip == "0.0.0.0"
    assert bad_src == "RFC1035_INVALID"

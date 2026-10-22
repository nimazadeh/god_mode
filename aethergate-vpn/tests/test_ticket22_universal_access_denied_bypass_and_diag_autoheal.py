"""Ticket 22 TDD tests: Universal Access-Denied Auto-Bypass (CNAME Radar + 403 Healer) & Diag Auto-Heal."""

import asyncio
import pytest
from constants import DEFAULT_BLOCKED_PATTERNS, GEOIP_RELAY_SUFFIXES, GFE_YOUTUBE_SUFFIXES
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import DoHResolver, extract_doh_answer_ip_and_cname_flag
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.inbound_proxy import detect_access_denied_signature
from tunnel.smart_router import SmartRouter


def test_enterprise_hardware_domains_and_recaptcha_offload_in_constants() -> None:
    """Verify intel.com, amd.com, nvidia.com, oracle.com use GEOIP_RELAY while recaptcha uses TUNNEL."""
    router = SmartRouter()
    for host in ("www.intel.com", "www.amd.com", "www.nvidia.com", "www.oracle.com", "www.cisco.com", "www.dell.com"):
        assert router.decide(host) == "GEOIP_RELAY", f"{host} must route via GEOIP_RELAY"
    assert "recaptcha.net" not in GEOIP_RELAY_SUFFIXES
    assert "recaptcha.net" in GFE_YOUTUBE_SUFFIXES
    assert router.decide("www.recaptcha.net") == "TUNNEL"
    assert router.decide("editor.svc.cloud.microsoft") == "BLOCK"
    assert router.decide("c.aps.amazon-adsystem.com") == "BLOCK"


def test_doh_cname_radar_flags_akamai_edgekey_edgesuite_and_cloudflare_enterprise() -> None:
    """Verify DoH JSON parser detects Akamai/Cloudflare/Imperva CNAME chains and flags host for GEOIP_RELAY."""
    sample_amd_doh = {
        "Answer": [
            {"name": "www.amd.com", "type": 5, "data": "tccdn.amd.akadns.net."},
            {"name": "tccdn.amd.akadns.net", "type": 5, "data": "e2897.b.akamaiedge.net."},
            {"name": "e2897.b.akamaiedge.net", "type": 1, "data": "184.30.152.84"},
        ]
    }
    ip, is_sanctioned_cdn = extract_doh_answer_ip_and_cname_flag(sample_amd_doh)
    assert ip == "184.30.152.84"
    assert is_sanctioned_cdn is True

    resolver = DoHResolver()
    resolver.flag_geoip_host("unknown-enterprise-chip.com")
    assert resolver.is_geoip_flagged("sub.unknown-enterprise-chip.com") is True


def test_detect_access_denied_signature_catches_intel_export_and_akamai_edgesuite() -> None:
    """Verify detect_access_denied_signature catches Intel EAR, Akamai Reference #18, and HTTP 403/451."""
    intel_page = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        b"Your request has been denied because we have reason to believe that you are located in a country subject to US export restrictions."
    )
    amd_page = (
        b"HTTP/1.1 403 Forbidden\r\nServer: AkamaiGHost\r\n\r\n"
        b"<TITLE>Access Denied</TITLE> Reference #18.80d7b5c.1792271034.23d74413 https://errors.edgesuite.net/"
    )
    normal_page = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome to OpenSource</body></html>"
    assert detect_access_denied_signature(intel_page) is True
    assert detect_access_denied_signature(amd_page) is True
    assert detect_access_denied_signature(normal_page) is False


@pytest.mark.asyncio
async def test_relay_pool_promotes_winner_when_index_0_times_out_and_diag_auto_heals(tmp_path) -> None:
    """Verify index-0 failure promotes winning backup relay and live GEOIP success heals ARENA_AI_GEOIP_443."""
    pool = GeoIPRelayPool()
    pool.relays = [
        ("socks5", "198.51.100.1", 3000),
        ("socks5", "172.171.169.205", 3000),
    ]

    async def _mock_race(indices, _ip, _port, timeout):
        if indices == [0]:
            return None
        return (1, "R", "W", "socks5://172.171.169.205:3000")

    pool._race_batch = _mock_race  # type: ignore[method-assign]
    await pool.open_relayed_connection("104.18.14.206", 443)
    _, _, via = await pool.open_relayed_connection("104.18.14.206", 443)
    assert via == "socks5://172.171.169.205:3000"
    assert pool.relays[0] == ("socks5", "172.171.169.205", 3000)

    diag = DiagnosticLogger(log_path=tmp_path / "diag.log", relay_pool=pool)
    diag.last_checks = [
        {"name": "ARENA_AI_GEOIP_443", "host": "arena.ai", "resolved_ip": "104.18.14.206", "dns_source": "CF_ANYCAST_VIP", "dns_ms": 0.1, "tcp_ms": -1, "tls_http": "FAIL", "ok": False, "error": "ConnectionError: all relays unreachable"}
    ]
    cid = diag.start_conn("HTTP_CONNECT", "arena.ai", 443, "GEOIP_RELAY")
    diag.log_stage(cid, "CLOSED_OK", tx=40422, rx=15386)
    assert diag.last_checks[0]["ok"] is True
    assert "ERR:" not in diag.build_text_report().splitlines()[1]

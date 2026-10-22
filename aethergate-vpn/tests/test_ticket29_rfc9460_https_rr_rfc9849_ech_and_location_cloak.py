"""Tests for Ticket 29: Satoshi Apex (v9.0) — RFC 9460 Type-65 HTTPS RR, RFC 9849 (0xfe0d) ECH & Location Cloak."""

import pytest
from tunnel.ech_rfc9849 import (
    build_rfc9849_outer_ech_extension,
    has_rfc9849_ech_extension,
    parse_rfc9460_https_rdata,
    query_rfc9460_https_record,
    strip_geoleak_headers,
)
from tunnel.smart_router import SmartRouter

_SAMPLE_HTTPS_RDATA = (
    "1 . alpn=h3,h2 ipv4hint=104.18.14.206,104.18.15.206 "
    "ech=AEX+DQBBGQAgACC7m7JCpWgK1VLIlROWlFWgUBgD0lBQhZRSiMF+gGkqWAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= "
    "ipv6hint=2606:4700::6812:ece"
)


def test_parse_rfc9460_https_rdata_and_rfc9849_ech_config_0xfe0d() -> None:
    """Verify RFC 9460 Type-65 RDATA parser extracts ipv4hint and RFC 9849 0xfe0d ECHConfig."""
    parsed = parse_rfc9460_https_rdata(_SAMPLE_HTTPS_RDATA)
    assert parsed["rr_type"] == 65
    assert parsed["alpn"] == ["h3", "h2"]
    assert parsed["ipv4hint"] == ["104.18.14.206", "104.18.15.206"]
    ech = parsed["ech_config"]
    assert ech is not None
    assert ech["version"] == "0xfe0d"
    assert ech["config_id"] == 25
    assert ech["kem_id"] == 0x0020
    assert len(ech["public_key_hex"]) == 64
    assert ech["public_name"] == "cloudflare-ech.com"


def test_build_rfc9849_outer_ech_extension_hides_inner_sni() -> None:
    """Verify RFC 9849 Section 5 0xfe0d extension encapsulates X25519 key and encrypts inner_sni."""
    ech = parse_rfc9460_https_rdata(_SAMPLE_HTTPS_RDATA)["ech_config"]
    assert ech is not None
    ext = build_rfc9849_outer_ech_extension(ech, "arena.ai")
    assert has_rfc9849_ech_extension(ext) is True
    assert ext[:2] == b"\xfe\x0d"
    assert b"arena.ai" not in ext


@pytest.mark.asyncio
async def test_live_query_rfc9460_https_record_for_arena_ai() -> None:
    """Verify Zero-SNI DoH queries Type-65 HTTPS RR for arena.ai and decodes RFC 9849 ECHConfig."""
    rec = await query_rfc9460_https_record("arena.ai")
    assert rec is not None
    assert "104.18.14.206" in rec["ipv4hint"]
    assert rec["ech_config"] is not None
    assert rec["ech_config"]["version"] == "0xfe0d"
    assert rec["ech_config"]["public_name"] == "cloudflare-ech.com"


def test_location_cloak_and_anti_geoleak_header_stripping() -> None:
    """Verify IP/location check domains route to US GEOIP_RELAY, Global Location Cloak works, and headers strip."""
    rtr = SmartRouter()
    for loc_site in ("ipinfo.io", "ipleak.net", "whoer.net", "browserleaks.com", "whatismyipaddress.com", "ifconfig.me", "api.ipify.org", "icanhazip.com"):
        assert rtr.decide(loc_site) == "GEOIP_RELAY", f"{loc_site} must route via US GEOIP_RELAY to cloak location"

    assert rtr.decide("en.wikipedia.org") == "TUNNEL"
    rtr.location_cloak_all = True
    assert rtr.decide("en.wikipedia.org") == "GEOIP_RELAY"
    assert rtr.decide("r1---sn-4g5lznly.googlevideo.com") == "TUNNEL"

    raw_http = (
        b"GET / HTTP/1.1\r\nHost: ipinfo.io\r\n"
        b"X-Forwarded-For: 5.120.10.20\r\nCF-Connecting-IP: 5.120.10.20\r\n"
        b"True-Client-IP: 5.120.10.20\r\nX-Real-IP: 5.120.10.20\r\n\r\n"
    )
    cleaned = strip_geoleak_headers(raw_http)
    assert b"5.120.10.20" not in cleaned
    assert b"Host: ipinfo.io" in cleaned

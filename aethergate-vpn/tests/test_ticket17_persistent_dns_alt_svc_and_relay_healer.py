"""Tests for Ticket 17: Persistent Disk DNS Cache, RFC 7838 Alt-Svc Shield, and Relay Country Auto-Healer."""

from pathlib import Path
import pytest
from tunnel.doh_resolver import DoHResolver
from tunnel.dpi_desync import strip_alt_svc_header
from tunnel.geoip_relay import GeoIPRelayPool, get_relay_country_meta


@pytest.mark.asyncio
async def test_persistent_disk_dns_cache_roundtrip(tmp_path: Path) -> None:
    """Verify DoHResolver persists resolved IPs to disk and reloads them on a new instance."""
    cache_file = tmp_path / "dns_cache.json"
    r1 = DoHResolver(cache_path=cache_file)
    r1.cache["custom-dev.example.org"] = "93.184.216.34"
    r1.save_disk_cache()
    assert cache_file.exists()

    r2 = DoHResolver(cache_path=cache_file)
    ip, src = await r2.resolve_with_meta("custom-dev.example.org")
    assert ip == "93.184.216.34"
    assert src == "MEMORY_CACHE"


def test_strip_alt_svc_header_removes_udp_quic_upgrade() -> None:
    """Verify RFC 7838 Alt-Svc: h3 header is removed so browsers do not leak or stall on UDP QUIC."""
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b'Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000\r\n'
        b"Content-Length: 2\r\n\r\nOK"
    )
    cleaned = strip_alt_svc_header(raw)
    assert b"Alt-Svc:" not in cleaned
    assert b"Content-Type: text/html" in cleaned
    assert cleaned.endswith(b"\r\n\r\nOK")


@pytest.mark.asyncio
async def test_relay_country_svg_flag_meta_and_auto_healer() -> None:
    """Verify get_relay_country_meta returns SVG flag data URI and heal_and_sort_relays promotes fastest relay."""
    meta_us = get_relay_country_meta("socks5://107.174.30.93:1080")
    assert meta_us["country_code"] == "US"
    assert "Virginia" in meta_us["location"]
    assert meta_us["flag_svg"].startswith("data:image/svg+xml")

    pool = GeoIPRelayPool()
    res = await pool.heal_and_sort_relays()
    assert res["active_relay"].startswith(("socks5://", "http://"))
    assert res["country_meta"]["flag_svg"].startswith("data:image/svg+xml")

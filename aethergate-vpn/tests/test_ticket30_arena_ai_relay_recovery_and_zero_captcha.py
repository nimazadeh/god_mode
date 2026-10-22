"""Tests for Ticket 30: Arena.ai Relay Pool Recovery, Chrome Sync Offload, and Zero-CAPTCHA 2-Record Relay TLS."""

import asyncio
import ssl
import pytest
from tunnel.dpi_desync import _send_first_packet
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.smart_router import SmartRouter


def _build_client_hello(hostname: str) -> bytes:
    """Create a real TLS 1.3 ClientHello using Python ssl.MemoryBIO."""
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    sobj = ctx.wrap_bio(inc, out, server_hostname=hostname)
    try:
        sobj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def test_chrome_sync_clients4_routes_to_direct_tunnel_while_cloudflareinsights_uses_relay() -> None:
    """Verify clients4.google.com/clients5.google.com use TUNNEL while static.cloudflareinsights.com uses GEOIP_RELAY."""
    rtr = SmartRouter()
    assert rtr.decide("clients4.google.com") == "TUNNEL"
    assert rtr.decide("clients5.google.com") == "TUNNEL"
    assert rtr.decide("static.cloudflareinsights.com") == "GEOIP_RELAY"
    assert rtr.decide("challenges.cloudflare.com") == "GEOIP_RELAY"
    assert rtr.decide("arena.ai") == "GEOIP_RELAY"


@pytest.mark.asyncio
async def test_relay_clean_2rec_mode_avoids_11rec_ja4_captcha_penalty() -> None:
    """Verify _send_first_packet uses RELAY_CLEAN_2REC when via_relay=True and POLY_PRIME_SHREDDER when direct."""
    ch = _build_client_hello("arena.ai")
    written: list[bytes] = []

    class _DummyWriter:
        def get_extra_info(self, _name: str):
            return None

        def write(self, data: bytes) -> None:
            written.append(data)

        async def drain(self) -> None:
            pass

    mode_relay = await _send_first_packet(_DummyWriter(), ch, desync_tls=True, via_relay=True)  # type: ignore[arg-type]
    assert mode_relay == "RELAY_CLEAN_2REC"
    assert len(written) == 1
    assert b"arena.ai" not in written[0]

    written.clear()
    mode_direct = await _send_first_packet(_DummyWriter(), ch, desync_tls=True, via_relay=False)  # type: ignore[arg-type]
    assert mode_direct.startswith("POLY_PRIME_SHREDDER_")
    assert len(written) == 2


@pytest.mark.asyncio
async def test_live_heal_and_open_relayed_connection_to_arena_ai() -> None:
    """Verify GeoIPRelayPool heals on startup and connects to arena.ai (104.18.14.206:443) in < 2.5s."""
    pool = GeoIPRelayPool()
    healed = await pool.heal_and_sort_relays()
    assert healed["pool_size"] >= 8
    r, w, via = await pool.open_relayed_connection("104.18.14.206", 443)
    w.close()
    assert "://" in via
    assert pool.last_rtt_ms < 2500.0

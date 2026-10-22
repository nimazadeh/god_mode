"""Ticket 59 (v11.10) TDD verification for Satoshi Google AI Studio Session Monogamy (Zero .google.com Cookie Split-Brain), MemoryBIO TLS EOF Spin-Loop Guard, and US Relay Pool Primary Priority."""

import asyncio
import pytest

from constants import AETHERGATE_VERSION
from main import _build_aether_state
from tunnel.doh_resolver import _query_shredded_cf_anycast_doh
from tunnel.dpi_desync import _open_smart_upstream
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.smart_router import SmartRouter


def test_version_v11_10_and_satoshi_google_ai_session_monogamy() -> None:
    """Verify opening aistudio.google.com flips google_ai_session_active so all *.google.com companion APIs route via GEOIP_RELAY."""
    assert AETHERGATE_VERSION.startswith("v11.1")
    state = _build_aether_state()
    rtr: SmartRouter = state["router"]
    assert rtr.strict_privacy_partitioning is True
    assert rtr.google_ai_session_active is False

    # Before opening AI Studio (e.g. during YouTube playback), companion hosts stay on TUNNEL.
    assert rtr.decide("waa-pa.clients6.google.com") == "TUNNEL"
    assert rtr.decide("apis.google.com") == "TUNNEL"

    # Once the user opens aistudio.google.com or alkalimakersuite-pa.clients6.google.com, ALL *.google.com companions must route via GEOIP_RELAY!
    assert rtr.decide("aistudio.google.com") == "GEOIP_RELAY"
    assert rtr.google_ai_session_active is True

    for companion in (
        "waa-pa.clients6.google.com",
        "signaler-pa.clients6.google.com",
        "ogads-pa.clients6.google.com",
        "ogs.google.com",
        "apis.google.com",
        "play.google.com",
        "clients6.google.com",
        "clients4.google.com",
        "consent.google.com",
        "alkalimakersuite-pa.clients6.google.com",
        "generativelanguage.googleapis.com",
    ):
        assert rtr.decide(companion) == "GEOIP_RELAY", f"{companion} must route via GEOIP_RELAY during active AI Studio session to prevent Iranian IP cookie poisoning"

    # Switching back to www.youtube.com resets google_ai_session_active so YouTube stays fast on TUNNEL.
    assert rtr.decide("www.youtube.com") == "TUNNEL"
    assert rtr.google_ai_session_active is False
    assert rtr.decide("waa-pa.clients6.google.com") == "TUNNEL"


@pytest.mark.asyncio
async def test_memory_bio_handshake_eof_raises_immediately_without_infinite_spin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify TCP EOF (b'') during _query_shredded_cf_anycast_doh raises ConnectionError in <50ms instead of spinning forever."""
    class _EofReader:
        async def read(self, _n: int = -1) -> bytes:
            return b""

    class _DummyWriter:
        def write(self, _d: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            pass

    async def _fake_open(*_a, **_kw):
        return _EofReader(), _DummyWriter()

    monkeypatch.setattr(asyncio, "open_connection", _fake_open)
    with pytest.raises(ConnectionError):
        await asyncio.wait_for(_query_shredded_cf_anycast_doh("example.com"), timeout=0.3)


@pytest.mark.asyncio
async def test_open_initial_stream_prioritizes_us_relay_pool_over_cloudflare_geofeed_worker() -> None:
    """Verify _open_initial_stream requests allow_worker=False first so Google AI Studio sees a real US IP instead of 104.28.* Cloudflare Geofeed."""
    pool = GeoIPRelayPool()
    calls: list[bool] = []

    async def _fake_open_relayed(ip: str, port: int, allow_worker: bool = True):
        calls.append(allow_worker)
        return None, None, "socks5://67.207.92.87:1088"

    pool.open_relayed_connection = _fake_open_relayed  # type: ignore[method-assign]
    _, _, via = await _open_smart_upstream("216.239.38.120", 443, pool, force_relay=True)
    assert via == "socks5://67.207.92.87:1088"
    assert calls == [False], "Live browser streams must try US SOCKS5/HTTP relays (allow_worker=False) first to avoid 104.28.* Cloudflare Geofeed blocks"


@pytest.mark.asyncio
async def test_verify_relay_tls_passthrough_rejects_socks5_rst_traps() -> None:
    """Verify _verify_relay_tls_passthrough actually sends a TLS ClientHello and rejects SOCKS5 proxies that reset on TLS."""
    from tunnel.geoip_relay import _is_clean_relay_addr, _verify_relay_tls_passthrough

    assert _is_clean_relay_addr("52.128.241.106:1080") is False
    assert _is_clean_relay_addr("52.128.241.107:1080") is False

    written: list[bytes] = []

    class _RstReader:
        def at_eof(self) -> bool:
            return False

        async def read(self, _n: int = -1) -> bytes:
            raise ConnectionResetError(104, "Connection reset by peer")

    class _RecordingWriter:
        def is_closing(self) -> bool:
            return False

        def write(self, data: bytes) -> None:
            written.append(data)

        async def drain(self) -> None:
            pass

    ok = await _verify_relay_tls_passthrough(_RstReader(), _RecordingWriter(), timeout=0.5)  # type: ignore[arg-type]
    assert len(written) > 0, "_verify_relay_tls_passthrough must actually send a TLS ClientHello over the relay"
    assert ok is False, "Relay that resets on TLS ClientHello must be rejected so background refresh never kills internet after 2 minutes"


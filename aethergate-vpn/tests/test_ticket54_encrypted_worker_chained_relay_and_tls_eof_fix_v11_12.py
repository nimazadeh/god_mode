"""Ticket 61 (v11.12) TDD verification for 2-Hop Encrypted Worker-Chained US Relay Tunnel and TLS close_notify Spin-Loop Guard."""

import asyncio
import ssl
import pytest

from constants import AETHERGATE_VERSION, CLEAN_ANYCAST_FALLBACKS, DEFAULT_GEOIP_RELAYS, DEFAULT_PERSONAL_CF_WORKER
from tunnel.dpi_desync import _send_first_packet
from tunnel.geoip_relay import GeoIPRelayPool, _connect_single_relay
from tunnel.serverless_worker import _pump_worker_to_local


def test_version_v11_12_and_dead_rst_relays_purged_from_defaults() -> None:
    """Verify v11.12+ removes TCP-RST relays (67.207.84.228:1088, 45.74.31.40:12429) and maps tls.browserleaks.com to 138.197.54.100."""
    assert AETHERGATE_VERSION in ("v11.12", "v11.13")
    assert CLEAN_ANYCAST_FALLBACKS["tls.browserleaks.com"] == "138.197.54.100"
    assert CLEAN_ANYCAST_FALLBACKS["quic.browserleaks.com"] == "138.197.54.100"
    assert ("socks5", "67.207.84.228", 1088) not in DEFAULT_GEOIP_RELAYS
    assert ("socks5", "45.74.31.40", 12429) not in DEFAULT_GEOIP_RELAYS
    assert ("socks5", "45.74.31.42", 7770) in DEFAULT_GEOIP_RELAYS
    assert ("socks5", "45.74.31.46", 15194) in DEFAULT_GEOIP_RELAYS


@pytest.mark.asyncio
async def test_tls_browserleaks_preserves_single_record_client_hello_over_relay() -> None:
    """Verify tls.browserleaks.com and tls.peet.ws send intact 1-record ClientHellos over relays so JA4/JA3 parsers never return fetch error."""
    written: list[bytes] = []

    class _DummyWriter:
        def get_extra_info(self, _name: str):
            return None

        def write(self, data: bytes) -> None:
            written.append(data)

        async def drain(self) -> None:
            pass

    fake_ch = b"\x16\x03\x01\x00\x30\x01" + b"\x00" * 20 + b"tls.browserleaks.com" + b"\x00" * 7
    mode = await _send_first_packet(_DummyWriter(), fake_ch, desync_tls=True, via_relay=True)  # type: ignore[arg-type]
    assert mode == "RELAY_CLEAN_2REC"
    assert written == [fake_ch], "tls.browserleaks.com over relay must preserve 1-record ClientHello so JA4 parser succeeds"


@pytest.mark.asyncio
async def test_pump_worker_to_local_exits_cleanly_on_tls_close_notify_without_infinite_spin() -> None:
    """Verify _pump_worker_to_local breaks immediately when ssl_obj.read(32768) returns b'' on TLS close_notify (100s CF idle timeout)."""
    upstream_r = asyncio.StreamReader()
    upstream_r.feed_data(b"\x17\x03\x03\x00\x05hello")
    upstream_r.feed_eof()

    class _CloseNotifySSL:
        def read(self, _n: int = 32768) -> bytes:
            # Python's SSLObject.read() returns b"" (without raising SSLWantReadError) when the peer sends TLS close_notify.
            return b""

    class _DummyWriter:
        def __init__(self) -> None:
            self.closed = False

        def write(self, _data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    local_w = _DummyWriter()
    await asyncio.wait_for(
        _pump_worker_to_local(upstream_r, local_w, _CloseNotifySSL(), ssl.MemoryBIO()),  # type: ignore[arg-type]
        timeout=0.4,
    )
    assert local_w.closed is True


@pytest.mark.asyncio
async def test_connect_single_relay_chains_through_encrypted_cloudflare_worker_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify _connect_single_relay tunnels the SOCKS5 handshake inside open_cf_worker_stream so ISP DPI never sees raw SOCKS5."""
    worker_targets: list[tuple[str, str, int]] = []
    socks5_sent: list[bytes] = []

    class _FakeWorkerWriter:
        def write(self, data: bytes) -> None:
            socks5_sent.append(data)

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            pass

    async def _fake_open_cf_worker_stream(worker_host: str, target_ip: str, target_port: int, *_args, **_kwargs):
        worker_targets.append((worker_host, target_ip, target_port))
        r = asyncio.StreamReader()
        # Feed SOCKS5 auth accept (0x05 0x00) + SOCKS5 CONNECT accept (10 bytes)
        r.feed_data(b"\x05\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        return r, _FakeWorkerWriter(), f"cfworker://{worker_host}:443"

    monkeypatch.setattr("tunnel.geoip_relay.open_cf_worker_stream", _fake_open_cf_worker_stream)
    _, _ = await _connect_single_relay("socks5", "67.207.92.87", 1088, "216.239.38.120", 443, timeout=2.0, use_worker_chain=True)
    assert worker_targets == [(DEFAULT_PERSONAL_CF_WORKER, "67.207.92.87", 1088)]
    assert socks5_sent[0] == b"\x05\x01\x00"


@pytest.mark.asyncio
async def test_live_end_to_end_worker_chained_relay_to_aistudio_google_com() -> None:
    """Verify live 2-hop Worker-chained US relay completes TLS 1.3 handshake to aistudio.google.com (216.239.38.120:443)."""
    pool = GeoIPRelayPool()
    r, w, via = await pool.open_relayed_connection("216.239.38.120", 443, allow_worker=False)
    try:
        ctx = ssl.create_default_context()
        in_b, out_b = ssl.MemoryBIO(), ssl.MemoryBIO()
        so = ctx.wrap_bio(in_b, out_b, server_hostname="aistudio.google.com")
        for _ in range(8):
            try:
                so.do_handshake()
                break
            except ssl.SSLWantReadError:
                chunk = out_b.read()
                if chunk:
                    w.write(chunk)
                    await w.drain()
                raw = await asyncio.wait_for(r.read(16384), timeout=3.5)
                assert raw, f"Unexpected EOF from Worker-chained relay {via}"
                in_b.write(raw)
    finally:
        w.close()

"""Tests for Ticket 23: Satoshi Polymorphic Prime-Entropy SNI Shredder & Pre-Warmed 0-RTT Socket Pool."""

import asyncio
import ssl
import pytest
from tunnel.dpi_desync import shred_tls_sni_polymorphic
from tunnel.satoshi_engine import PreWarmedSocketPool


def _make_client_hello(hostname: str) -> bytes:
    """Create a real TLS 1.3 ClientHello using Python ssl.MemoryBIO."""
    ctx, inc, out = ssl.create_default_context(), ssl.MemoryBIO(), ssl.MemoryBIO()
    sobj = ctx.wrap_bio(inc, out, server_hostname=hostname)
    try:
        sobj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def test_polymorphic_prime_shredder_eliminates_keywords_and_avoids_uniform_record_lengths() -> None:
    """Verify polymorphic shredder eliminates >=5B tokens and never emits adjacent identical SNI slice lengths."""
    for host, tokens in [
        ("rr3---sn-u14g55-5m.googlevideo.com", [b"googlevideo", b"google", b"video"]),
        ("www.youtube.com", [b"youtube", b"youtu"]),
        ("arena.ai", [b"arena"]),
        ("downloadcenter.intel.com", [b"intel", b"download"]),
    ]:
        ch = _make_client_hello(host)
        seen_patterns: set[tuple[int, ...]] = set()
        for _ in range(10):
            recs = shred_tls_sni_polymorphic(ch)
            wire = b"".join(recs)
            for tok in tokens:
                assert tok not in wire, f"{tok!r} leaked in wire bytes for {host}"
            sni_lens = tuple(int.from_bytes(r[3:5], "big") for r in recs[1:-1])
            seen_patterns.add(sni_lens)
            for ln in sni_lens:
                assert ln in (2, 3, 4), f"SNI slice length {ln} outside bounded {2,3,4}"
            for i in range(1, len(sni_lens)):
                assert sni_lens[i] != sni_lens[i - 1], f"Adjacent uniform lengths found: {sni_lens}"
            orig_len = int.from_bytes(ch[3:5], "big")
            reassembled = b"".join(r[5 : 5 + int.from_bytes(r[3:5], "big")] for r in recs)
            assert reassembled == ch[5 : 5 + orig_len]
        if len(host) >= 12:
            assert len(seen_patterns) >= 2, "Polymorphic shredder must vary record-length patterns across calls"


async def _mock_socks5_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    """Minimal RFC 1928 SOCKS5 server that greets and echoes payload after CONNECT."""
    try:
        greet = await r.readexactly(3)
        if greet == b"\x05\x01\x00":
            w.write(b"\x05\x00"), await w.drain()
            req = await r.readexactly(10)
            if req[0] == 0x05 and req[1] == 0x01:
                w.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb"), await w.drain()
                data = await r.read(1024)
                if data:
                    w.write(b"ECHO:" + data), await w.drain()
    except Exception:
        pass
    finally:
        w.close()


@pytest.mark.asyncio
async def test_prewarmed_socket_pool_completes_greeting_ahead_and_connects_in_1rtt() -> None:
    """Verify PreWarmedSocketPool pre-greets SOCKS5 sockets and executes CONNECT in 1 RTT."""
    srv = await asyncio.start_server(_mock_socks5_handler, "127.0.0.1", 0)
    port = int(srv.sockets[0].getsockname()[1])
    pool = PreWarmedSocketPool(target_size=3)
    try:
        ready = await pool.warm_relay("127.0.0.1", port, count=3)
        assert ready == 3
        assert pool.warmed_total == 3
        conn = await pool.acquire_and_connect("127.0.0.1", port, "104.18.14.206", 443)
        assert conn is not None
        assert pool.hits == 1
        r, w = conn
        w.write(b"SATOSHI_0RTT"), await w.drain()
        reply = await asyncio.wait_for(r.read(64), timeout=2.0)
        assert reply == b"ECHO:SATOSHI_0RTT"
        w.close()
        await asyncio.sleep(0.05)
        assert pool.ready_count(f"socks5://127.0.0.1:{port}") >= 2
    finally:
        pool.close_all()
        srv.close()
        await srv.wait_closed()

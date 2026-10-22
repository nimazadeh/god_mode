"""Tests for Ticket 37/38: RFC 9614 2-Hop Privacy Partitioning, RFC 9230 Oblivious DoH, RFC 7685 TLS Padding, and RFC 6797 HSTS Guard."""

import asyncio
import socket
import struct
import pytest
from main import _build_aether_state
from tunnel.privacy_rfc9614 import (
    RFC7685_EXT_PADDING,
    audit_rfc9614_privacy_posture,
    build_rfc6797_https_upgrade_response,
    build_rfc7685_padding_extension,
    compute_anti_correlation_jitter_ms,
    is_cleartext_http_leak,
    open_2hop_partitioned_stream,
    pack_rfc9230_odoh_query,
    verify_rfc9230_odoh_message,
)


def test_rfc7685_tls_padding_and_anti_correlation_jitter() -> None:
    """Verify RFC 7685 (0x0015) pads TLS ClientHello to uniform buckets and CSPRNG jitter stays in [1.0, 4.5]ms."""
    ext = build_rfc7685_padding_extension(current_hello_len=310, bucket_size=512)
    ext_type, ext_len = struct.unpack("!HH", ext[:4])
    assert ext_type == RFC7685_EXT_PADDING
    assert len(ext) == 512 - 310
    assert ext[4:] == b"\x00" * ext_len

    for _ in range(10):
        j = compute_anti_correlation_jitter_ms()
        assert 1.0 <= j <= 4.5


def test_rfc9230_oblivious_doh_hpke_query_encapsulation() -> None:
    """Verify RFC 9230 ObliviousDoHMessage (0x01) encapsulates queries with X25519 HPKE and zero-padding."""
    pkt = pack_rfc9230_odoh_query("arena.ai", qtype=1, pad_len=48)
    assert pkt["msg_type"] == 0x01
    assert pkt["kem_id"] == 0x0020
    assert pkt["padding_zeros"] == 48
    assert b"arena.ai" not in pkt["wire_bytes"]

    parsed = verify_rfc9230_odoh_message(pkt["wire_bytes"])
    assert parsed["valid"] is True
    assert parsed["msg_type"] == 0x01
    assert parsed["key_id"] == "aether-odoh-k1"


def test_rfc6797_plaintext_http_leak_guard_and_strict_partitioning_boot() -> None:
    """Verify cleartext HTTP is detected and upgraded to HTTPS via 307 HSTS, while TLS 1.3 passes untouched."""
    assert is_cleartext_http_leak(b"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n", 80) is True
    assert is_cleartext_http_leak(b"\x16\x03\x01\x02\x00\x01\x00", 443) is False

    resp = build_rfc6797_https_upgrade_response("example.com", b"GET /secret?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert b"HTTP/1.1 307 Temporary Redirect" in resp
    assert b"Location: https://example.com/secret?x=1" in resp
    assert b"Strict-Transport-Security: max-age=31536000" in resp

    st = _build_aether_state()
    rtr = st["router"]
    posture = audit_rfc9614_privacy_posture(rtr, st["inbound_proxy"].relay_pool)
    assert posture["rfc9614_privacy_partitioning"] is True
    assert posture["strict_all_traffic_cloaked"] is True
    for global_target in ("shaparak.ir", "digikala.ir", "arena.ai", "nordvpn.com", "github.com", "140.82.4.34", "any-tld.jp"):
        assert rtr.decide(global_target) == "GEOIP_RELAY", f"{global_target} must be quarantined to GEOIP_RELAY in Zero-Trust mode"
    assert rtr.decide("www.youtube.com") == "TUNNEL"
    for local_lan in ("localhost", "127.0.0.1", "192.168.1.1", "10.0.0.5", "nas.local"):
        assert rtr.decide(local_lan) == "DIRECT", f"{local_lan} RFC 1918 LAN address must remain DIRECT"


@pytest.mark.asyncio
async def test_rfc9614_2hop_partitioned_stream_isolates_entry_and_exit_contexts() -> None:
    """Prove mathematically that Hop 1 only sees Hop 2 IP, and Hop 2 only sees Target IP over a real 2-hop SOCKS5 chain."""
    hop1_seen_targets: list[tuple[str, int]] = []
    hop2_seen_targets: list[tuple[str, int]] = []

    async def _handle_target(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        data = await r.read(128)
        w.write(b"RFC9614_2HOP_ACK:" + data)
        await w.drain()
        w.close()

    target_srv = await asyncio.start_server(_handle_target, "127.0.0.1", 0)
    target_port = int(target_srv.sockets[0].getsockname()[1])

    async def _socks5_hop(r: asyncio.StreamReader, w: asyncio.StreamWriter, log_list: list[tuple[str, int]]) -> None:
        await r.readexactly(3)
        w.write(b"\x05\x00"), await w.drain()
        hdr = await r.readexactly(10)
        dst_ip = socket.inet_ntoa(hdr[4:8])
        dst_port = int.from_bytes(hdr[8:10], "big")
        log_list.append((dst_ip, dst_port))
        up_r, up_w = await asyncio.open_connection(dst_ip, dst_port)
        w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"), await w.drain()

        async def _pipe(sr: asyncio.StreamReader, dw: asyncio.StreamWriter) -> None:
            try:
                while buf := await sr.read(4096):
                    dw.write(buf), await dw.drain()
            except Exception:
                pass
            finally:
                dw.close()

        await asyncio.gather(_pipe(r, up_w), _pipe(up_r, w))

    hop2_srv = await asyncio.start_server(lambda r, w: _socks5_hop(r, w, hop2_seen_targets), "127.0.0.1", 0)
    hop2_port = int(hop2_srv.sockets[0].getsockname()[1])
    hop1_srv = await asyncio.start_server(lambda r, w: _socks5_hop(r, w, hop1_seen_targets), "127.0.0.1", 0)
    hop1_port = int(hop1_srv.sockets[0].getsockname()[1])

    try:
        r, w, label = await open_2hop_partitioned_stream(
            ("socks5", "127.0.0.1", hop1_port),
            ("socks5", "127.0.0.1", hop2_port),
            "127.0.0.1",
            target_port,
        )
        assert "2HOP[" in label
        w.write(b"TLS13_ENCRYPTED_CLIENT_HELLO")
        await w.drain()
        reply = await r.read(128)
        w.close()
        assert reply == b"RFC9614_2HOP_ACK:TLS13_ENCRYPTED_CLIENT_HELLO"
        # Hop 1 ONLY saw Hop 2's port (never target_port!), and Hop 2 ONLY saw target_port!
        assert hop1_seen_targets == [("127.0.0.1", hop2_port)]
        assert hop2_seen_targets == [("127.0.0.1", target_port)]
    finally:
        hop1_srv.close(), hop2_srv.close(), target_srv.close()

"""RFC 8446 Section 5.1 polymorphic SNI record shredder and full-duplex TCP engine to blind stateful DPI without breaking TLS."""

import asyncio
import os
import socket
import time
from typing import Any
from constants import BLACKHOLED_GGC_PREFIXES, GVS_CORE_VIP, TLS_FRAGMENT_CHUNK_SIZE, TLS_FRAGMENT_HEADER_WINDOW
from tunnel.ech_rfc9849 import strip_geoleak_headers
from tunnel.frontier_2026 import sample_daita_v2_ephemeral_machine
from tunnel.ja4_shield import compute_ja4_fingerprint


def is_tls_client_hello(data: bytes) -> bool:
    """Identify TLS Handshake (0x16) ClientHello (0x01) packets so only initial handshakes undergo record-layer shredding."""
    return len(data) >= 6 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01


def strip_alt_svc_header(http_bytes: bytes) -> bytes:
    """Strip RFC 7838 Alt-Svc headers so browsers never upgrade to UDP QUIC/HTTP3 where ISP middleboxes drop packets."""
    if b"Alt-Svc:" not in http_bytes and b"alt-svc:" not in http_bytes:
        return http_bytes
    hdr, sep, body = http_bytes.partition(b"\r\n\r\n")
    kept = [ln for ln in hdr.split(b"\r\n") if not ln.lower().startswith(b"alt-svc:")]
    return b"\r\n".join(kept) + sep + body


def _scan_sni_bounds(body: bytes, idx: int, exts_end: int) -> tuple[int, int]:
    """Locate the exact byte range of extension 0x0000 (server_name) so record splits cut strictly inside the plaintext domain."""
    while idx + 4 <= exts_end:
        ext_type, ext_len = int.from_bytes(body[idx : idx + 2], "big"), int.from_bytes(body[idx + 2 : idx + 4], "big")
        if ext_type == 0x0000 and idx + 9 < exts_end:
            return idx + 9, min(len(body), idx + 9 + int.from_bytes(body[idx + 7 : idx + 9], "big"))
        idx += 4 + ext_len
    mid = max(6, min(len(body) // 2, 32))
    return mid - 3, mid + 3


def find_sni_bounds(body: bytes) -> tuple[int, int]:
    """Skip variable-length SessionID, CipherSuites, and Compression fields to reach the TLS extensions block accurately."""
    idx = 38
    if len(body) > idx:
        idx += 1 + body[idx]
    if len(body) > idx + 2:
        idx += 2 + int.from_bytes(body[idx : idx + 2], "big")
    if len(body) > idx + 1:
        idx += 1 + body[idx]
    if len(body) > idx + 2:
        return _scan_sni_bounds(body, idx + 2, min(len(body), idx + 2 + int.from_bytes(body[idx : idx + 2], "big")))
    return 8, min(len(body), 16)


def find_sni_midpoint(body: bytes) -> int:
    """Cut 6 bytes before the end of the SNI so the root domain (.com/.ai) is split across two separate TLS records."""
    s_start, s_end = find_sni_bounds(body)
    return max(s_start + 2, min(s_end - 6, (s_start + s_end) // 2))


def _polymorphic_sni_slices(body: bytes, s_start: int, s_end: int) -> list[bytes]:
    """Use non-repeating {2, 3, 4}-byte strides so fixed-stride DPI signature detectors cannot fingerprint our record boundaries."""
    out, pos, prev, rand_bytes = [], s_start, 0, os.urandom(32)
    r_idx = 0
    while pos < s_end:
        rem = s_end - pos
        if rem <= 4 and rem != prev:
            step = rem
        else:
            cands = [c for c in (2, 3, 4) if c != prev and rem - c >= 2 and (rem - c > 4 or rem - c != c)]
            if not cands:
                cands = [c for c in (2, 3, 4) if c < rem and c != prev] or [min(rem, 3)]
            step = cands[rand_bytes[r_idx % len(rand_bytes)] % len(cands)]
            r_idx += 1
        out.append(body[pos : pos + step])
        pos, prev = pos + step, step
    return out


def shred_tls_sni_polymorphic(data: bytes) -> list[bytes]:
    """Wrap each polymorphic SNI slice in its own RFC 8446 Section 5.1 record header so stateless DPI never sees the full hostname."""
    if len(data) < 6 or data[0] != 0x16:
        return [data]
    rec_hdr, total_len = data[:3], int.from_bytes(data[3:5], "big")
    body, rem = data[5 : 5 + total_len], data[5 + total_len :]
    s_start, s_end = find_sni_bounds(body)
    parts = [body[:s_start]] + _polymorphic_sni_slices(body, s_start, s_end) + [body[s_end:]]
    recs = [rec_hdr + len(p).to_bytes(2, "big") + p for p in parts if p]
    if rem and recs:
        recs[-1] = recs[-1] + rem
    return recs


def shred_tls_sni_daita_ephemeral(data: bytes, connection_seed: bytes | None = None) -> tuple[list[bytes], dict[str, Any]]:
    """Slice a ClientHello using a PETS 2026 DAITA v2 ephemeral state machine so each connection presents a unique record-size distribution."""
    machine = sample_daita_v2_ephemeral_machine(connection_seed)
    if len(data) < 6 or data[0] != 0x16:
        return [data], machine
    rec_hdr, total_len = data[:3], int.from_bytes(data[3:5], "big")
    body, rem = data[5 : 5 + total_len], data[5 + total_len :]
    s_start, s_end = find_sni_bounds(body)
    strides = machine["stride_tuple"]
    slices: list[bytes] = []
    pos = s_start
    idx = 0
    while pos < s_end:
        step = min(s_end - pos, int(strides[idx % len(strides)]))
        slices.append(body[pos : pos + step])
        pos += step
        idx += 1
    parts = [body[:s_start]] + slices + [body[s_end:]]
    recs = [rec_hdr + len(p).to_bytes(2, "big") + p for p in parts if p]
    if rem and recs:
        recs[-1] = recs[-1] + rem
    return recs, machine


def shred_tls_sni_records(data: bytes, step: int = 4) -> list[bytes]:
    """Provide deterministic 4-byte SNI record shredding so unit tests can assert exact record counts and reassembly."""
    if len(data) < 6 or data[0] != 0x16:
        return [data]
    rec_hdr, total_len = data[:3], int.from_bytes(data[3:5], "big")
    body, rem = data[5 : 5 + total_len], data[5 + total_len :]
    s_start, s_end = find_sni_bounds(body)
    parts = [body[:s_start]] + [body[p : min(p + step, s_end)] for p in range(s_start, s_end, step)] + [body[s_end:]]
    recs = [rec_hdr + len(p).to_bytes(2, "big") + p for p in parts if p]
    if rem and recs:
        recs[-1] = recs[-1] + rem
    return recs


def split_tls_record_layer(data: bytes, split_pos: int = 0) -> tuple[bytes, bytes]:
    """Split a ClientHello into 2 clean records for relayed connections because multi-record shredding triggers Cloudflare Turnstile on SOCKS5."""
    if len(data) < 6 or data[0] != 0x16:
        return data, b""
    rec_hdr, total_len = data[:3], int.from_bytes(data[3:5], "big")
    body, remainder = data[5 : 5 + total_len], data[5 + total_len :]
    cut = max(2, min(split_pos if split_pos > 0 else find_sni_midpoint(body), len(body) - 1))
    part1, part2 = body[:cut], body[cut:]
    return rec_hdr + len(part1).to_bytes(2, "big") + part1, rec_hdr + len(part2).to_bytes(2, "big") + part2 + remainder


def fragment_tls_client_hello(data: bytes, chunk_size: int = TLS_FRAGMENT_CHUNK_SIZE) -> list[bytes]:
    """Slice raw TCP segments across the ClientHello header window to defeat legacy DPI boxes that do not reassemble TCP streams."""
    if not data:
        return []
    step = max(2, min(chunk_size, 16))
    head, tail = data[:TLS_FRAGMENT_HEADER_WINDOW], data[TLS_FRAGMENT_HEADER_WINDOW:]
    return [head[i : i + step] for i in range(0, len(head), step)] + ([tail] if tail else [])


def _enable_tcp_nodelay(writer: asyncio.StreamWriter) -> None:
    """Disable Nagle's algorithm so the OS kernel transmits split TLS records as distinct TCP segments instead of coalescing them."""
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass


def _configure_client_socket(writer: asyncio.StreamWriter) -> bool:
    """Use 256KB socket buffers for Wi-Fi LAN peers to prevent mobile radio frame starvation while keeping TCP_NODELAY on loopback."""
    peer = writer.get_extra_info("peername")
    peer_ip = str(peer[0]).removeprefix("::ffff:") if isinstance(peer, tuple) and peer else "127.0.0.1"
    if peer_ip.startswith("127.") or peer_ip == "::1":
        _enable_tcp_nodelay(writer)
        return False
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        except Exception:
            pass
    return True


async def _send_first_packet(rem_w: asyncio.StreamWriter, first_data: bytes, desync_tls: bool, via_relay: bool = False) -> str:
    """Use 2-record split over relays to avoid WAF bot scores, and 2-wave micro-jitter polymorphic shredding on direct ISP links."""
    if desync_tls and is_tls_client_hello(first_data):
        _enable_tcp_nodelay(rem_w)
        if via_relay:
            if b"tls.browserleaks.com" in first_data or b"tls.peet.ws" in first_data:
                rem_w.write(first_data), await rem_w.drain()
            else:
                r1, r2 = split_tls_record_layer(first_data)
                rem_w.write(r1 + r2), await rem_w.drain()
            return "RELAY_CLEAN_2REC"
        recs = shred_tls_sni_polymorphic(first_data)
        half = max(1, len(recs) // 2)
        rem_w.write(b"".join(recs[:half])), await rem_w.drain()
        await asyncio.sleep(0.002)
        rem_w.write(b"".join(recs[half:])), await rem_w.drain()
        return f"POLY_PRIME_SHREDDER_{len(recs)}REC"
    rem_w.write(first_data), await rem_w.drain()
    return "DIRECT_PASSTHROUGH"


async def _pipe_direction(src_r: asyncio.StreamReader, dst_w: asyncio.StreamWriter) -> int:
    """Sanitize Alt-Svc and GeoLeak headers in-flight so neither QUIC upgrades nor proxy IP headers leak during bidirectional streaming."""
    total = 0
    try:
        while True:
            buf = await src_r.read(131072)
            if not buf:
                break
            clean = strip_geoleak_headers(strip_alt_svc_header(buf))
            dst_w.write(clean), await dst_w.drain()
            total += len(clean)
    except Exception:
        pass
    finally:
        dst_w.close()
    return total


async def _open_smart_upstream(target_ip: str, target_port: int, relay_pool: Any | None, force_relay: bool, target_host_hint: str = "") -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    """Route through the US/EU relay pool first (avoiding 104.28.* Cloudflare Geofeed blocks) and fall back to personal Worker.
    target_host_hint is forwarded so the relay pool can refuse to use the CF Worker for Google AI Studio endpoints.
    """
    if relay_pool is not None and (force_relay or relay_pool.is_escalated(target_ip)):
        try:
            return await relay_pool.open_relayed_connection(target_ip, target_port, allow_worker=False, target_host_hint=target_host_hint)
        except TypeError:
            return await relay_pool.open_relayed_connection(target_ip, target_port, target_host_hint=target_host_hint)
        except Exception:
            return await relay_pool.open_relayed_connection(target_ip, target_port, allow_worker=True, target_host_hint=target_host_hint)
    r, w = await asyncio.wait_for(asyncio.open_connection(target_ip, target_port), timeout=3.5)
    return r, w, target_ip


async def _failover_and_replay(peer_ip: str, first: bytes, desync_tls: bool, target_ip: str, target_port: int, via: str, relay_pool: Any, force_relay: bool, target_host_hint: str = "") -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bytes, str]:
    """Replay the captured ClientHello over a fresh socket or backup relay so mid-handshake DPI resets never surface to the browser."""
    if not force_relay and target_ip != "127.0.0.1":
        if peer_ip.startswith(BLACKHOLED_GGC_PREFIXES):
            raise TimeoutError(f"GGC_BLACKHOLE_FASTFAIL:{peer_ip}")
        r2, w2 = await asyncio.wait_for(asyncio.open_connection(peer_ip, target_port), timeout=2.5)
        await _send_first_packet(w2, first, desync_tls=desync_tls)
        return r2, w2, b"", f"REPLAYED_DIRECT_{target_ip}"
    relay_pool.escalate_ip(target_ip) if via == target_ip else relay_pool.demote_relay(via)
    try:
        r2, w2, via2 = await relay_pool.open_relayed_connection(target_ip, target_port, allow_worker=not str(via).startswith("cfworker://"), target_host_hint=target_host_hint)
    except TypeError:
        r2, w2, via2 = await relay_pool.open_relayed_connection(target_ip, target_port, target_host_hint=target_host_hint)
    await _send_first_packet(w2, first, desync_tls=desync_tls, via_relay=True)
    return r2, w2, b"", f"REPLAYED_VIA_{via2}"


async def _send_and_verify_server_hello(rem_r: asyncio.StreamReader, rem_w: asyncio.StreamWriter, first: bytes, desync_tls: bool, target_ip: str, target_port: int, via: str, relay_pool: Any | None, force_relay: bool = False, target_host_hint: str = "") -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bytes, str]:
    """Verify the upstream returns a ServerHello (except on client-first MTProto) so silent DPI blackholes trigger instant replay."""
    is_tg_mtproto = bool(first and not is_tls_client_hello(first) and target_ip.startswith(("149.154.", "91.108.")))
    is_relayed = via != target_ip
    if not first or relay_pool is None or is_tg_mtproto:
        mode = await _send_first_packet(rem_w, first, desync_tls=desync_tls, via_relay=is_relayed) if first else "EMPTY"
        return rem_r, rem_w, b"", mode
    try:
        mode = await _send_first_packet(rem_w, first, desync_tls=desync_tls, via_relay=is_relayed)
        peek = await asyncio.wait_for(rem_r.read(65536), timeout=2.5)
        if peek:
            return rem_r, rem_w, peek, mode
    except Exception:
        pass
    peer = rem_w.get_extra_info("peername")
    peer_ip = peer[0] if isinstance(peer, tuple) and peer else target_ip
    rem_w.close()
    return await _failover_and_replay(peer_ip, first, desync_tls, target_ip, target_port, via, relay_pool, force_relay, target_host_hint=target_host_hint)


async def relay_full_duplex_stream(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter, target_ip: str, target_port: int, desync_tls: bool = True, diag: Any | None = None, cid: int = 0, relay_pool: Any | None = None, force_relay: bool = False, target_host_hint: str = "") -> tuple[int, int]:
    """Coordinate upstream connection, SNI desync, JA4 telemetry logging, and bidirectional piping with guaranteed socket cleanup."""
    t0 = time.perf_counter()
    rem_r, rem_w, via = await _open_smart_upstream(target_ip, target_port, relay_pool, force_relay, target_host_hint=target_host_hint)
    if diag and cid:
        diag.log_stage(cid, "TCP_CONNECT", ip=via, port=target_port, tcp_ms=round((time.perf_counter() - t0) * 1000.0, 1))
    _enable_tcp_nodelay(rem_w), _configure_client_socket(client_w)
    try:
        first = await asyncio.wait_for(client_r.read(32768), timeout=5.0)
        rem_r, rem_w, peek, mode = await _send_and_verify_server_hello(rem_r, rem_w, first, desync_tls, target_ip, target_port, via, relay_pool, force_relay, target_host_hint=target_host_hint)
        if peek:
            client_w.write(peek), await client_w.drain()
        if diag and cid and first:
            ja4_vec = compute_ja4_fingerprint(first)["ja4"] if is_tls_client_hello(first) else ""
            diag.log_stage(cid, "TLS_HANDSHAKE", mode=mode, bytes=len(first), ja4=ja4_vec)
        tx, rx = await asyncio.gather(_pipe_direction(client_r, rem_w), _pipe_direction(rem_r, client_w))
        return len(first) + tx, len(peek) + rx
    finally:
        rem_w.close()

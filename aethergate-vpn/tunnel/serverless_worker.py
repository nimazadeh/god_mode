"""Personal Serverless Cloudflare Worker relay engine using cloudflare:sockets and SNI-shredded Anycast TLS to eliminate shared public proxies."""

import asyncio
import base64
import os
import socket
import ssl
from typing import Any
from constants import CF_ANYCAST_VIP, DEFAULT_PERSONAL_CF_WORKER, DEFAULT_SECRET_KEY
from tunnel.dpi_desync import shred_tls_sni_polymorphic
from tunnel.satoshi_engine import create_unverified_tls_client_context, spawn_background_task

_CF_LOOPBACK_PREFIXES = (
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.",
    "162.158.", "162.159.", "188.114.", "198.41.", "141.101.", "108.162.", "173.245.",
    "103.21.", "103.22.", "103.31.", "190.93.", "197.234.", "131.0.72.", "1.1.1.", "1.0.0.",
)
NAT64_US_FREMONT_PREFIX = "2602:fc59:b0:64::"


def is_cloudflare_anycast_ip(ip_str: str) -> bool:
    """Detect Cloudflare-owned Anycast IPs because cloudflare:sockets connect() requires RFC 6052 NAT64 translation for Cloudflare targets."""
    return ip_str.strip().startswith(_CF_LOOPBACK_PREFIXES)


def ipv4_to_rfc6052_nat64(ipv4_str: str, prefix: str = NAT64_US_FREMONT_PREFIX) -> str:
    """Embed an IPv4 address into an IETF RFC 6052 Section 2.2 /96 IPv6 NAT64 prefix so Cloudflare Workers can reach 104.18.* targets."""
    clean = ipv4_str.strip()
    parts = clean.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return clean
    b0, b1, b2, b3 = (int(p) for p in parts)
    return f"[{prefix}{(b0 << 8) | b1:04x}:{(b2 << 8) | b3:04x}]"


def build_cloudflare_worker_script(secret_token: str = DEFAULT_SECRET_KEY) -> str:
    """Generate a zero-dependency Cloudflare Worker script using cloudflare:sockets connect() and RFC 6052 NAT64 so users have a private exit relay."""
    clean_secret = secret_token.strip() or DEFAULT_SECRET_KEY
    return (
        'import { connect } from "cloudflare:sockets";\n\n'
        f'const AETHER_SECRET = "{clean_secret}";\n'
        f'const NAT64_US_PREFIX = "{NAT64_US_FREMONT_PREFIX}";\n\n'
        "function ipv4ToNat64(ipv4) {\n"
        '  const parts = ipv4.trim().split(".");\n'
        "  if (parts.length !== 4) return ipv4;\n"
        "  const nums = parts.map((p) => Number(p));\n"
        "  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return ipv4;\n"
        '  const hi = ((nums[0] << 8) | nums[1]).toString(16).padStart(4, "0");\n'
        '  const lo = ((nums[2] << 8) | nums[3]).toString(16).padStart(4, "0");\n'
        "  return `[${NAT64_US_PREFIX}${hi}:${lo}]`;\n"
        "}\n\n"
        "async function toBytes(data) {\n"
        '  if (typeof data === "string") return new TextEncoder().encode(data);\n'
        "  if (data instanceof ArrayBuffer) return new Uint8Array(data);\n"
        "  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);\n"
        '  if (data && typeof data.arrayBuffer === "function") return new Uint8Array(await data.arrayBuffer());\n'
        "  return new Uint8Array(0);\n"
        "}\n\n"
        "export default {\n"
        "  async fetch(request, env) {\n"
        '    const expectedToken = (env && env.AETHER_SECRET) ? env.AETHER_SECRET : AETHER_SECRET;\n'
        '    const clientToken = request.headers.get("x-aether-token") || "";\n'
        "    if (clientToken !== expectedToken) {\n"
        '      return new Response("AetherGate Personal Serverless Node v11.7 Ready", { status: 200 });\n'
        "    }\n"
        '    const targetHeader = request.headers.get("x-aether-target") || "";\n'
        '    const splitIndex = targetHeader.lastIndexOf(":");\n'
        '    if (splitIndex <= 0) return new Response("Missing X-Aether-Target", { status: 400 });\n'
        "    const rawHost = targetHeader.slice(0, splitIndex);\n"
        "    const port = Number(targetHeader.slice(splitIndex + 1)) || 443;\n"
        '    const useNat64 = request.headers.get("x-aether-nat64") === "1";\n'
        "    const hostname = useNat64 ? ipv4ToNat64(rawHost) : rawHost;\n"
        "    let tcpSocket;\n"
        "    try { tcpSocket = connect({ hostname, port }); } catch { tcpSocket = connect({ hostname: ipv4ToNat64(rawHost), port }); }\n"
        "    if (tcpSocket.opened) tcpSocket.opened.catch(() => {});\n"
        "    if (tcpSocket.closed) tcpSocket.closed.catch(() => {});\n"
        "    const [clientWs, serverWs] = Object.values(new WebSocketPair());\n"
        '    serverWs.binaryType = "arraybuffer";\n'
        "    serverWs.accept();\n"
        "    const tcpWriter = tcpSocket.writable.getWriter();\n"
        '    serverWs.addEventListener("message", async (event) => {\n'
        "      try { const chunk = await toBytes(event.data); if (chunk.byteLength > 0) await tcpWriter.write(chunk); } catch { try { serverWs.close(); } catch {} }\n"
        "    });\n"
        '    serverWs.addEventListener("close", () => { try { tcpSocket.close(); } catch {} });\n'
        "    (async () => {\n"
        "      const reader = tcpSocket.readable.getReader();\n"
        "      try { while (true) { const { done, value } = await reader.read(); if (done) break; serverWs.send(value); } } catch {} finally { try { serverWs.close(); } catch {} }\n"
        "    })();\n"
        "    return new Response(null, { status: 101, webSocket: clientWs });\n"
        "  }\n"
        "};\n"
    )


def build_worker_upgrade_headers(
    worker_host: str,
    target_ip: str,
    target_port: int,
    secret_token: str = DEFAULT_SECRET_KEY,
) -> bytes:
    """Synthesize IETF RFC 6052 NAT64 IPv6 targets for Cloudflare IPs and attach X-Aether-Token so the Worker routes all destinations."""
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    clean_worker = worker_host.strip().lower()
    use_nat64 = is_cloudflare_anycast_ip(target_ip)
    effective_target = ipv4_to_rfc6052_nat64(target_ip) if use_nat64 else target_ip.strip()
    nat64_hdr = "X-Aether-Nat64: 1\r\n" if use_nat64 else ""
    header_lines = (
        f"GET /_aether/stream HTTP/1.1\r\n"
        f"Host: {clean_worker}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"X-Aether-Token: {secret_token.strip()}\r\n"
        f"X-Aether-Target: {effective_target}:{target_port}\r\n"
        f"{nat64_hdr}"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0\r\n\r\n"
    )
    return header_lines.encode("latin1")


def encode_rfc6455_client_frame(payload: bytes) -> bytes:
    """Wrap raw TCP bytes in a masked RFC 6455 Section 5.2 binary frame (opcode 0x82) because Cloudflare rejects unmasked client frames."""
    mask_key = os.urandom(4)
    masked = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
    n = len(payload)
    if n < 126:
        return bytes([0x82, 0x80 | n]) + mask_key + masked
    if n < 65536:
        return bytes([0x82, 0x80 | 126]) + n.to_bytes(2, "big") + mask_key + masked
    return bytes([0x82, 0x80 | 127]) + n.to_bytes(8, "big") + mask_key + masked


def decode_rfc6455_server_frames(buffer: bytes) -> tuple[list[bytes], bytes, bool]:
    """Extract complete RFC 6455 server frames from a byte buffer so split TLS records reassemble cleanly without corrupting inner TLS."""
    chunks: list[bytes] = []
    pos, total, closed = 0, len(buffer), False
    while pos + 2 <= total:
        opcode = buffer[pos] & 0x0F
        length = buffer[pos + 1] & 0x7F
        hdr_len = 2
        if length == 126:
            if pos + 4 > total:
                break
            length, hdr_len = int.from_bytes(buffer[pos + 2 : pos + 4], "big"), 4
        elif length == 127:
            if pos + 10 > total:
                break
            length, hdr_len = int.from_bytes(buffer[pos + 2 : pos + 10], "big"), 10
        if pos + hdr_len + length > total:
            break
        body = buffer[pos + hdr_len : pos + hdr_len + length]
        pos += hdr_len + length
        if opcode == 0x08:
            closed = True
            break
        if opcode in (0x01, 0x02) and body:
            chunks.append(body)
    return chunks, buffer[pos:], closed


async def _complete_shredded_worker_tls(
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    ssl_object: ssl.SSLObject,
    incoming_bio: ssl.MemoryBIO,
    outgoing_bio: ssl.MemoryBIO,
) -> None:
    """Shred the initial TLS ClientHello SNI to bypass ISP blocking of *.workers.dev while connecting to Cloudflare Anycast VIP."""
    try:
        ssl_object.do_handshake()
    except ssl.SSLWantReadError:
        pass
    shredded_hello = shred_tls_sni_polymorphic(outgoing_bio.read())
    upstream_writer.write(b"".join(shredded_hello))
    await upstream_writer.drain()
    while True:
        try:
            ssl_object.do_handshake()
            break
        except ssl.SSLWantReadError:
            pending_out = outgoing_bio.read()
            if pending_out:
                upstream_writer.write(pending_out)
                await upstream_writer.drain()
            raw_in = await asyncio.wait_for(upstream_reader.read(16384), timeout=2.5)
            if not raw_in:
                raise ConnectionError("Worker TLS EOF during handshake")
            incoming_bio.write(raw_in)


async def _pump_local_to_worker(
    local_r: asyncio.StreamReader,
    upstream_w: asyncio.StreamWriter,
    ssl_obj: ssl.SSLObject,
    out_bio: ssl.MemoryBIO,
) -> None:
    """Encode outbound TCP bytes into RFC 6455 masked binary frames so the Cloudflare Worker forwards them to the remote host."""
    try:
        while True:
            data = await local_r.read(32768)
            if not data:
                break
            ssl_obj.write(encode_rfc6455_client_frame(data))
            upstream_w.write(out_bio.read())
            await upstream_w.drain()
    except Exception:
        pass
    finally:
        upstream_w.close()


async def _pump_worker_to_local(
    upstream_r: asyncio.StreamReader,
    local_w: asyncio.StreamWriter,
    ssl_obj: ssl.SSLObject,
    in_bio: ssl.MemoryBIO,
    initial_buf: bytes = b"",
) -> None:
    """Decrypt incoming TLS records and strip RFC 6455 frame headers so the local caller receives raw inner TCP bytes."""
    ws_buf = initial_buf
    try:
        while True:
            cipher = await upstream_r.read(32768)
            if not cipher:
                break
            in_bio.write(cipher)
            tls_eof = False
            while True:
                try:
                    dec_chunk = ssl_obj.read(32768)
                    if not dec_chunk:
                        tls_eof = True
                        break
                    ws_buf += dec_chunk
                except ssl.SSLWantReadError:
                    break
            frames, ws_buf, closed = decode_rfc6455_server_frames(ws_buf)
            for chunk in frames:
                local_w.write(chunk)
            if frames:
                await local_w.drain()
            if closed or tls_eof:
                break
    except Exception:
        pass
    finally:
        local_w.close()


async def open_cf_worker_stream(
    worker_host: str = DEFAULT_PERSONAL_CF_WORKER,
    target_ip: str = "",
    target_port: int = 443,
    secret_token: str = DEFAULT_SECRET_KEY,
    edge_ip: str = CF_ANYCAST_VIP,
    timeout: float = 2.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    """Open an SNI-shredded TLS WebSocket tunnel to the user's Cloudflare Worker so callers get a standard asyncio stream pair."""
    tls_ctx = create_unverified_tls_client_context()
    in_bio, out_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
    ssl_obj = tls_ctx.wrap_bio(in_bio, out_bio, server_hostname=worker_host.strip())
    up_r, up_w = await asyncio.wait_for(asyncio.open_connection(edge_ip, 443), timeout=timeout)
    try:
        await _complete_shredded_worker_tls(up_r, up_w, ssl_obj, in_bio, out_bio)
        dest_ip = "104.18.32.47" if target_ip.strip() == edge_ip else target_ip
        ssl_obj.write(build_worker_upgrade_headers(worker_host, dest_ip, target_port, secret_token))
        up_w.write(out_bio.read())
        await up_w.drain()
        reply = b""
        for _ in range(6):
            if b"\r\n\r\n" in reply:
                break
            raw_in = await asyncio.wait_for(up_r.read(8192), timeout=timeout)
            if not raw_in:
                raise ConnectionError("Worker upgrade EOF")
            in_bio.write(raw_in)
            try:
                reply += ssl_obj.read(8192)
            except ssl.SSLWantReadError:
                continue
        if b" 101 " not in reply.split(b"\r\n", 1)[0]:
            raise ConnectionError("Worker rejected WebSocket upgrade")
    except Exception:
        up_w.close()
        raise
    s_caller, s_bridge = socket.socketpair()
    caller_r, caller_w = await asyncio.open_connection(sock=s_caller)
    bridge_r, bridge_w = await asyncio.open_connection(sock=s_bridge)
    leftover = reply.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in reply else b""
    rem_buf = b""
    if leftover:
        frames, rem_buf, _ = decode_rfc6455_server_frames(leftover)
        for f in frames:
            bridge_w.write(f)
    spawn_background_task(_pump_local_to_worker(bridge_r, up_w, ssl_obj, out_bio))
    spawn_background_task(_pump_worker_to_local(up_r, bridge_w, ssl_obj, in_bio, rem_buf))
    return caller_r, caller_w, f"cfworker://{worker_host.strip()}:443"

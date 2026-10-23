"""Single-port SOCKS5 and HTTP CONNECT listener with autonomous 403/451 detection so any geo-blocked website self-heals."""

import asyncio
import socket
import ssl
import time
from typing import Any

from constants import (
    ACCESS_DENIED_SIGNATURES,
    GFE_YOUTUBE_SUFFIXES,
    INBOUND_PROXY_PORT,
    SOCKS5_ATYP_DOMAIN,
    SOCKS5_ATYP_IPV4,
    SOCKS5_ATYP_IPV6,
    SOCKS5_NO_AUTH,
    SOCKS5_REP_SUCCEEDED,
    SOCKS5_VERSION,
)
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import DoHResolver, is_blackholed_ggc, is_poisoned_ip, is_youtube_video_edge_host
from tunnel.dpi_desync import relay_full_duplex_stream, shred_tls_sni_polymorphic
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.privacy_rfc9614 import build_rfc6797_https_upgrade_response
from tunnel.satoshi_engine import (
    CleanIPMiner,
    SovereignLanGateway,
    close_stream_writer,
    create_unverified_tls_client_context,
    spawn_background_task,
)
from tunnel.smart_router import SmartRouter, is_direct_jet_media_host
from tunnel.geoip_relay import _is_google_sensitive_target

# Known-clean public static asset CDNs that never enforce geo-sanctions, allowing 0ms pre-flight probe bypass.
_DIRECT_CLEAN_SUFFIXES = (
    "cloudflareinsights.com",
    "cdnjs.cloudflare.com",
    "daily.dev",
    "s-msn.com",
    "live.com",
    "microsoft.com",
    "qq.com",
)


def detect_access_denied_signature(payload: bytes) -> bool:
    """Detect HTTP 403/451/406/423 status codes, geo-redirect Location headers, and WAF block bodies to auto-trigger US relay."""
    if not payload:
        return False
    lower_window = payload[:8192].lower()
    status_line = lower_window.split(b"\r\n", 1)[0]
    if any(code in status_line for code in (b" 403 ", b" 451 ", b" 406 ", b" 423 ")):
        return True
    # Many regional blocks return 301/302 redirects to /sorry, /blocked, or /unsupported instead of a direct 403 status.
    if any(code in status_line for code in (b" 301 ", b" 302 ", b" 303 ", b" 307 ", b" 308 ")):
        header_lines = lower_window.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
        redirect_markers = (b"/sorry", b"blocked", b"unsupported", b"restricted", b"unavailable", b"region", b"denied")
        if any(line.startswith(b"location:") and any(tok in line for tok in redirect_markers) for line in header_lines):
            return True
    return any(signature in lower_window for signature in ACCESS_DENIED_SIGNATURES)


async def _read_probe_bio_verdict(
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    ssl_object: ssl.SSLObject,
    incoming_bio: ssl.MemoryBIO,
    outgoing_bio: ssl.MemoryBIO,
    target_host: str,
) -> bool:
    """Read the initial HTTP response over MemoryBIO so we can spot regional WAF rejections before forwarding the browser stream."""
    for _ in range(4):
        try:
            ssl_object.do_handshake()
            break
        except ssl.SSLWantReadError:
            upstream_writer.write(outgoing_bio.read())
            await upstream_writer.drain()
            incoming_bio.write(await asyncio.wait_for(upstream_reader.read(16384), timeout=1.4))
    upstream_writer.write(outgoing_bio.read())
    http_probe_req = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Mozilla/5.0 Chrome/131.0.0.0\r\nConnection: close\r\n\r\n"
    ssl_object.write(http_probe_req.encode("latin1"))
    upstream_writer.write(outgoing_bio.read())
    await upstream_writer.drain()
    for _ in range(3):
        try:
            return detect_access_denied_signature(ssl_object.read(4096))
        except ssl.SSLWantReadError:
            incoming_bio.write(await asyncio.wait_for(upstream_reader.read(16384), timeout=1.4))
    return False


async def probe_https_access_denied(target_host: str, target_ip: str, target_port: int = 443) -> bool:
    """Force ALPN http/1.1 during pre-flight probing so CDNs cannot HPACK-compress 403 headers into opaque HTTP/2 binary frames."""
    tls_context = create_unverified_tls_client_context()
    incoming_bio = ssl.MemoryBIO()
    outgoing_bio = ssl.MemoryBIO()
    # Negotiating HTTP/1.1 ensures the status line and Location header arrive in readable ASCII rather than HTTP/2 binary frames.
    tls_context.set_alpn_protocols(["http/1.1"])
    ssl_object = tls_context.wrap_bio(incoming_bio, outgoing_bio, server_hostname=target_host)
    try:
        ssl_object.do_handshake()
    except ssl.SSLWantReadError:
        pass
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(target_ip, target_port), timeout=1.4)
        try:
            upstream_writer.write(b"".join(shred_tls_sni_polymorphic(outgoing_bio.read())))
            await upstream_writer.drain()
            return await _read_probe_bio_verdict(upstream_reader, upstream_writer, ssl_object, incoming_bio, outgoing_bio, target_host)
        finally:
            upstream_writer.close()
    except Exception:
        return False


async def _forward_plain_http(
    target_ip: str,
    target_port: int,
    request_head: bytes,
    relay_pool: GeoIPRelayPool | None = None,
) -> bytes:
    """Return a clean 502 response on upstream failure so plain HTTP clients do not hang waiting on dropped sockets."""
    try:
        if relay_pool is not None:
            upstream_reader, upstream_writer, _ = await relay_pool.open_relayed_connection(target_ip, target_port)
        else:
            upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(target_ip, target_port), timeout=3.5)
        try:
            upstream_writer.write(request_head)
            await upstream_writer.drain()
            return await asyncio.wait_for(upstream_reader.read(32768), timeout=4.5)
        finally:
            upstream_writer.close()
    except Exception:
        return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"


async def _parse_socks5_target(client_reader: asyncio.StreamReader) -> tuple[str, int]:
    """Support IPv4, domain, and IPv6 address types per RFC 1928 so both socks5:// and socks5h:// clients work seamlessly."""
    socks_header = await client_reader.readexactly(4)
    address_type = socks_header[3]
    if address_type == SOCKS5_ATYP_IPV4:
        target_host = socket.inet_ntoa(await client_reader.readexactly(4))
    elif address_type == SOCKS5_ATYP_DOMAIN:
        domain_len = (await client_reader.readexactly(1))[0]
        target_host = (await client_reader.readexactly(domain_len)).decode("utf-8", errors="ignore")
    elif address_type == SOCKS5_ATYP_IPV6:
        target_host = socket.inet_ntop(socket.AF_INET6, await client_reader.readexactly(16))
    else:
        raise ValueError("Unsupported SOCKS5 ATYP")
    target_port = int.from_bytes(await client_reader.readexactly(2), "big")
    return target_host, target_port


def _parse_http_target(request_head: bytes) -> tuple[str, int, bool]:
    """Distinguish HTTP CONNECT tunnels from plain HTTP forward requests on the same port so one listener serves all proxy modes."""
    request_line_parts = request_head.split(b"\r\n", 1)[0].decode("latin1", errors="ignore").split()
    http_method = request_line_parts[0].upper() if request_line_parts else "GET"
    raw_target = request_line_parts[1] if len(request_line_parts) > 1 else "localhost:80"
    if http_method == "CONNECT":
        target_host, _, port_str = raw_target.partition(":")
        return target_host, int(port_str or "443"), True
    target_host, _, port_str = raw_target.split("://", 1)[-1].split("/", 1)[0].partition(":")
    return target_host or "localhost", int(port_str or "80"), False


class UnifiedInboundProxy:
    """Demultiplex SOCKS5 and HTTP CONNECT on a single port so browsers and CLI tools share one anti-censorship listener."""

    def __init__(
        self,
        dispatcher: Any,
        router: SmartRouter,
        host: str = "0.0.0.0",
        port: int = INBOUND_PROXY_PORT,
        diag: DiagnosticLogger | None = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.router = router
        self.doh = DoHResolver()
        self.relay_pool = GeoIPRelayPool()
        self.miner = CleanIPMiner()
        self.lan_gateway = SovereignLanGateway(port=port, enabled=True)
        self.diag = diag or DiagnosticLogger(relay_pool=self.relay_pool)
        self.host = host
        self.port = port
        self.bound_port = port
        self.active_transport = "DPI_DESYNC_DOH"
        self.padding_enabled = True
        self._probed_clean_hosts: set[str] = set()
        self._active_client_tasks: set[asyncio.Task[Any]] = set()
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        """Enable TCP keep_alive per Python 3.13 asyncio-stream docs (with SO_KEEPALIVE fallback for uvloop) and record bound_port."""
        try:
            self._server = await asyncio.start_server(self._handle_client, self.host, self.port, keep_alive=True)
        except TypeError:
            # Cython uvloop.Loop.create_server does not yet accept Python 3.13's keep_alive keyword argument; fall back and set SO_KEEPALIVE directly.
            self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
            for server_sock in self._server.sockets or ():
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if self._server.sockets:
            self.bound_port = int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        """Await wait_closed() on shutdown so port 10808 is released immediately before the next process binds it."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def _should_probe_unknown_https(self, target_host: str, resolved_ip: str, target_port: int) -> bool:
        """Skip pre-flight 403 probing on known-clean CDNs and media streams so video and static assets connect with zero extra RTT."""
        normalized_host = target_host.lower().strip().rstrip(".")
        if target_port != 443 or normalized_host in self._probed_clean_hosts or is_poisoned_ip(resolved_ip) or is_direct_jet_media_host(normalized_host):
            return False
        return not any(normalized_host == suffix or normalized_host.endswith("." + suffix) for suffix in _DIRECT_CLEAN_SUFFIXES)

    async def _bg_scout_probe(self, target_host: str, clean_ip: str, target_port: int) -> None:
        """Run 403 detection in the background for LAN peers or suspiciously short streams so active sockets never block."""
        if await probe_https_access_denied(target_host, clean_ip, target_port):
            self.doh.flag_geoip_host(target_host)
            self.router.add_rule(target_host, "GEOIP_RELAY")
        else:
            self._probed_clean_hosts.add(target_host.lower())

    async def _evaluate_auto_geoip(
        self,
        connection_id: int,
        target_host: str,
        clean_ip: str,
        target_port: int,
        decision: str,
        is_lan_peer: bool = False,
    ) -> str:
        """Escalate TUNNEL to GEOIP_RELAY automatically when CNAME radar or 403 probing detects regional access restrictions."""
        if decision != "TUNNEL":
            return decision
        if not self.doh.is_geoip_flagged(target_host) and self._should_probe_unknown_https(target_host, clean_ip, target_port):
            if is_lan_peer:
                spawn_background_task(self._bg_scout_probe(target_host, clean_ip, target_port))
            elif await probe_https_access_denied(target_host, clean_ip, target_port):
                self.doh.flag_geoip_host(target_host)
            else:
                self._probed_clean_hosts.add(target_host.lower())
        if self.doh.is_geoip_flagged(target_host):
            root_domain = ".".join(target_host.lower().strip(".").split(".")[-2:])
            self.router.add_rule(root_domain if root_domain in self.doh.geoip_flagged_hosts else target_host, "GEOIP_RELAY")
            self.diag.promote_route(connection_id, "GEOIP_RELAY")
            return "GEOIP_RELAY"
        return decision

    async def _run_live_stream(
        self,
        connection_id: int,
        target_host: str,
        target_port: int,
        decision: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Trigger a background 403 scout probe if a direct TLS stream closes with rx<=3400B so encrypted WAF blocks self-heal."""
        start_time = time.perf_counter()
        peer_info = client_writer.get_extra_info("peername")
        peer_ip = str(peer_info[0]).removeprefix("::ffff:") if isinstance(peer_info, tuple) and peer_info else "127.0.0.1"
        is_lan_peer = not peer_ip.startswith("127.") and peer_ip != "::1"
        clean_ip, dns_source = await self.doh.resolve_with_meta(target_host, prefer_doh=(decision == "GEOIP_RELAY"))
        decision = await self._evaluate_auto_geoip(connection_id, target_host, clean_ip, target_port, decision, is_lan_peer=is_lan_peer)
        dns_elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 1)
        self.diag.log_stage(connection_id, "DNS", host=target_host, resolved_ip=clean_ip, source=dns_source, dns_ms=dns_elapsed_ms)
        via_label = self.relay_pool.active_relay if decision == "GEOIP_RELAY" else decision
        try:
            bytes_tx, bytes_rx = await relay_full_duplex_stream(
                client_reader,
                client_writer,
                clean_ip,
                target_port,
                desync_tls=(decision != "DIRECT"),
                diag=self.diag,
                cid=connection_id,
                relay_pool=(None if decision == "DIRECT" else self.relay_pool),
                force_relay=(decision == "GEOIP_RELAY"),
                target_host_hint=target_host,
            )
            self.dispatcher.bytes_tx += bytes_tx
            self.dispatcher.bytes_rx += bytes_rx
            self.dispatcher.packets_relayed += 1
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 1)
            actual_via = self.diag.get_actual_via(connection_id, via_label) if decision == "GEOIP_RELAY" else via_label
            if decision == "TUNNEL" and target_port == 443 and bytes_tx >= 180 and bytes_rx <= 3400 and not is_direct_jet_media_host(target_host):
                self._probed_clean_hosts.discard(target_host.lower())
                spawn_background_task(self._bg_scout_probe(target_host, clean_ip, target_port))
            # Auto-demote a GEOIP relay that returns a tiny body to Google AI Studio / Gemini / OAuth (Google's 403 page is ~1-3 KB).
            if decision == "GEOIP_RELAY" and target_port == 443 and _is_google_sensitive_target(clean_ip, target_host) and bytes_rx <= 6000 and bytes_tx >= 300:
                self.diag.log_stage(connection_id, "RELAY_403_DETECTED", target=target_host, via=actual_via, bytes_rx=bytes_rx)
                self.relay_pool.demote_relay(actual_via)
                spawn_background_task(self.relay_pool.heal_and_sort_relays(probe_google_ai=True))
            if decision == "GEOIP_RELAY" and bytes_tx >= 1800 and not str(actual_via).startswith("cfworker://"):
                self.relay_pool.record_stream_outcome(actual_via, bytes_tx, bytes_rx)
            self.diag.log_stage(connection_id, "CLOSED_OK", tx=bytes_tx, rx=bytes_rx, dur_ms=duration_ms, via=actual_via)
        except Exception as exc:
            actual_via = self.diag.get_actual_via(connection_id, via_label) if decision == "GEOIP_RELAY" else via_label
            self.diag.log_stage(connection_id, "STREAM_ERROR", target=f"{target_host}:{target_port}", ip=clean_ip, via=actual_via, error=f"{type(exc).__name__}: {exc}")

    async def _relay_session(
        self,
        protocol_name: str,
        target_host: str,
        target_port: int,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Short-circuit BLOCK rules and port-80 cleartext at the socket edge so plaintext and telemetry never enter public relays."""
        decision = self.router.decide(target_host)
        if decision == "BLOCK":
            client_writer.write(b"HTTP/1.1 403 Forbidden (Blocked by SmartRouter)\r\n\r\n")
            await client_writer.drain()
            return
        connection_id = self.diag.start_conn(protocol_name, target_host, target_port, decision)
        # Public SOCKS5/HTTP relays reject port 80 CONNECT requests; intercept cleartext at the edge and upgrade to HTTPS.
        if self.router.strict_privacy_partitioning and target_port == 80 and decision == "GEOIP_RELAY" and not target_host.endswith(".aether.internal"):
            self.diag.log_stage(connection_id, "RFC6797_HSTS_GUARD", target=f"{target_host}:80", mode="PORT80_CLEARTEXT_UPGRADED_TO_443")
            client_writer.write(build_rfc6797_https_upgrade_response(target_host, b"GET / HTTP/1.1\r\n\r\n"))
            await client_writer.drain()
            return
        if not target_host.endswith(".aether.internal"):
            await self._run_live_stream(connection_id, target_host, target_port, decision, client_reader, client_writer)
            return
        payload = await asyncio.wait_for(client_reader.read(16384), timeout=3.0)
        relay_result = await self.dispatcher.relay_payload(self.active_transport, target_host, target_port, payload, self.padding_enabled)
        client_writer.write(relay_result.get("response_bytes", b""))
        await client_writer.drain()

    async def _handle_socks5(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        """Complete RFC 1928 no-auth negotiation before handing the stream to _relay_session so SOCKS5 clients enter full-duplex mode."""
        method_count = (await client_reader.readexactly(1))[0]
        await client_reader.readexactly(method_count)
        client_writer.write(bytes([SOCKS5_VERSION, SOCKS5_NO_AUTH]))
        await client_writer.drain()
        target_host, target_port = await _parse_socks5_target(client_reader)
        client_writer.write(bytes([SOCKS5_VERSION, SOCKS5_REP_SUCCEEDED, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        await client_writer.drain()
        await self._relay_session("SOCKS5", target_host, target_port, client_reader, client_writer)

    async def _handle_http_proxy(self, first_byte: bytes, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        """Return an instant 502 on blackholed GGC nodes during direct YouTube video playback so the player switches to fallback_host in 0ms."""
        request_head = first_byte + (await client_reader.readuntil(b"\r\n\r\n"))
        target_host, target_port, is_connect = _parse_http_target(request_head)
        if is_connect:
            if is_youtube_video_edge_host(target_host) and not self.router.ytm_session_active:
                resolved_ggc_ip = (await self.doh.resolve_with_meta(target_host))[0]
                if is_blackholed_ggc(target_host, resolved_ggc_ip):
                    client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    await client_writer.drain()
                    return
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            await self._relay_session("HTTP_CONNECT", target_host, target_port, client_reader, client_writer)
            return
        if self.router.strict_privacy_partitioning and target_port == 80 and target_host not in ("localhost", "127.0.0.1"):
            client_writer.write(build_rfc6797_https_upgrade_response(target_host, request_head))
            await client_writer.drain()
            return
        clean_ip, _ = await self.doh.resolve_with_meta(target_host)
        use_relay = target_port == 443 and (self.router.decide(target_host) == "GEOIP_RELAY" or self.doh.is_geoip_flagged(target_host))
        upstream_reply = await _forward_plain_http(clean_ip, target_port, request_head, self.relay_pool if use_relay else None)
        client_writer.write(upstream_reply)
        await client_writer.drain()

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        """Retain a strong task reference and close synchronously on GeneratorExit so Python 3.14 GC never logs coroutine errors."""
        current_task = asyncio.current_task()
        if current_task is not None:
            self._active_client_tasks.add(current_task)
        generator_closing = False
        try:
            peer_info = client_writer.get_extra_info("peername")
            peer_ip = str(peer_info[0]) if isinstance(peer_info, tuple) and peer_info else "127.0.0.1"
            if not self.lan_gateway.register_peer(peer_ip):
                return
            first_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=3.0)
            if first_byte[0] == SOCKS5_VERSION:
                await self._handle_socks5(client_reader, client_writer)
            else:
                await self._handle_http_proxy(first_byte, client_reader, client_writer)
        except GeneratorExit:
            generator_closing = True
            client_writer.close()
            raise
        except BaseException:
            pass
        finally:
            if current_task is not None:
                self._active_client_tasks.discard(current_task)
            if not generator_closing:
                await close_stream_writer(client_writer)

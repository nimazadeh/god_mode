"""RFC 8305 Happy Eyeballs v2 US/EU exit relay pool and zero-leak kill-switch to bypass GeoIP sanctions without exposing domestic IPs."""

import asyncio
import base64
import socket
import ssl
import time
from typing import Any

from constants import (
    CF_ANYCAST_VIP, DEFAULT_GEOIP_RELAYS, DEFAULT_PERSONAL_CF_WORKER, DEFAULT_SECRET_KEY,
    GFE_ANYCAST_VIP, GITHUB_RAW_VIP, GOOGLE_EYE_HOSTS_BLOCK_CF_WORKER,
)
from tunnel.dpi_desync import shred_tls_sni_polymorphic, split_tls_record_layer
from tunnel.satoshi_engine import PreWarmedSocketPool, create_unverified_tls_client_context, spawn_background_task
from tunnel.serverless_worker import is_cloudflare_anycast_ip, open_cf_worker_stream

# Sanctioned ISO country codes that trigger HTTP 403/451 blocks on US/EU cloud platforms when used as exit nodes.
_SANCTIONED_LOCS = {"IR", "RU", "BY", "CN", "HK", "MO", "KP", "SY", "CU", "VE"}
_US_EU_PREFIXES = ("44.", "45.", "52.", "62.", "67.", "68.", "107.", "137.", "142.", "159.", "161.", "162.", "172.", "173.", "192.", "195.", "198.")
_CAPTIVE_PORTAL_PORTS = (":3128", ":8080", ":80", ":8081", ":8888", ":8443", ":999")
_TLS_VERIFY_CTX = ssl.create_default_context()
_RELAY_META = {
    "67.207.92.87": ("US", "US • New York", "#3b82f6"), "62.146.180.4": ("US", "US • Virginia", "#3b82f6"),
    "172.171.169.205": ("US", "US • Virginia", "#3b82f6"), "13.90.182.199": ("US", "US • Virginia", "#3b82f6"),
    "137.74.50.101": ("FR", "FR • Paris", "#3b82f6"), "159.89.119.49": ("CA", "CA • Toronto", "#3b82f6"),
    "8.221.106.175": ("US", "US • California", "#3b82f6"), "195.13.182.210": ("LV", "EU • Riga", "#3b82f6"),
    "45.74.31.40": ("DE", "DE • Frankfurt", "#f59e0b"), "52.128.241.109": ("US", "US • California", "#3b82f6"),
    "45.149.92.160": ("US", "US • Virginia", "#3b82f6"), "107.174.30.93": ("US", "US • Virginia", "#3b82f6"),
    "107.174.30.94": ("US", "US • Virginia", "#3b82f6"), "107.174.30.92": ("US", "US • Virginia", "#3b82f6"),
    DEFAULT_PERSONAL_CF_WORKER: ("CF", "CF • Personal Worker", "#10b981"),
}


def _is_clean_relay_addr(addr: str) -> bool:
    """Exclude captive-portal ports, 145.220.*/43.*/139.* prefixes, and SOCKS5 TLS-reset traps to prevent MITM cert errors."""
    clean = addr.strip()
    return not clean.endswith(_CAPTIVE_PORTAL_PORTS) and not clean.startswith(("43.", "139.", "145.220.", "52.128.241.106:", "52.128.241.107:"))


def enforce_subnet_diversity(relays: list[tuple[str, str, int]], max_per_slash16: int = 2) -> list[tuple[str, str, int]]:
    """Cap relays per /16 IPv4 subnet (Bitcoin AddrMan bucketing) so a single datacenter or Sybil subnet cannot flood the pool."""
    bucket_counts: dict[str, int] = {}
    selected, overflow = [], []
    for item in relays:
        octets = item[1].split(".")
        slash16 = f"{octets[0]}.{octets[1]}" if len(octets) >= 2 else item[1]
        if bucket_counts.get(slash16, 0) < max_per_slash16:
            bucket_counts[slash16] = bucket_counts.get(slash16, 0) + 1
            selected.append(item)
        else:
            overflow.append(item)
    return selected if len(selected) >= 4 else (selected + overflow)


def _select_us_eu_candidates(socks5_lines: list[str], http_lines: list[str]) -> list[tuple[str, str]]:
    """Filter harvested proxy lists toward US/EU datacenter prefixes so candidate probing avoids sanctioned or port-3128 exits."""
    priority_candidates = [
        ("socks5", addr) for addr in socks5_lines if addr.startswith(_US_EU_PREFIXES) and _is_clean_relay_addr(addr)
    ] + [
        ("http", addr) for addr in http_lines if addr.startswith(_US_EU_PREFIXES) and _is_clean_relay_addr(addr)
    ]
    sampled_fallbacks = [
        ("socks5", addr) for addr in socks5_lines[::5] if _is_clean_relay_addr(addr)
    ] + [
        ("http", addr) for addr in http_lines[::5] if _is_clean_relay_addr(addr)
    ]
    return list(dict.fromkeys(priority_candidates + sampled_fallbacks))[:80]


def is_sanctioned_trace_loc(trace_text: str) -> bool:
    """Reject exit nodes whose Cloudflare trace reports a sanctioned country code so relays never trigger downstream 403 blocks."""
    for raw_line in trace_text.splitlines():
        clean_line = raw_line.strip()
        if clean_line.startswith("loc="):
            country_code = clean_line.split("=", 1)[1].upper()
            if country_code in _SANCTIONED_LOCS:
                return True
    return False


def get_relay_country_meta(relay_label: str) -> dict[str, str]:
    """Generate an inline SVG country badge because Windows Segoe UI fonts omit regional indicator flag emojis."""
    relay_host = relay_label.split("://")[-1].split(":")[0]
    country_code, location_label, badge_color = _RELAY_META.get(relay_host, ("US", "US/EU • International", "#3b82f6"))
    raw_svg = (
        f"<svg xmlns='http://www.w3.org/2000/svg' width='24' height='15'>"
        f"<rect width='24' height='15' rx='3' fill='{badge_color}'/>"
        f"<text x='12' y='11' font-family='monospace' font-size='9' font-weight='bold' fill='white' text-anchor='middle'>{country_code}</text>"
        f"</svg>"
    )
    return {
        "country_code": country_code,
        "location": location_label,
        "flag_svg": "data:image/svg+xml;base64," + base64.b64encode(raw_svg.encode("utf-8")).decode("ascii"),
    }


async def _handshake_socks5_ip(relay_reader: asyncio.StreamReader, relay_writer: asyncio.StreamWriter, target_ip: str, target_port: int) -> bool:
    """Pass numeric IPv4 (ATYP=0x01) or domain fallback (ATYP=0x03) in SOCKS5 CONNECT so unresolved hostnames never crash inet_pton."""
    relay_writer.write(b"\x05\x01\x00")
    await relay_writer.drain()
    if (await relay_reader.readexactly(2)) != b"\x05\x00":
        return False
    try:
        addr_bytes = b"\x01" + socket.inet_pton(socket.AF_INET, target_ip)
    except OSError:
        host_b = target_ip.encode("ascii", errors="ignore")[:255]
        addr_bytes = b"\x03" + bytes([len(host_b)]) + host_b
    connect_frame = b"\x05\x01\x00" + addr_bytes + target_port.to_bytes(2, "big")
    relay_writer.write(connect_frame)
    await relay_writer.drain()
    reply_header = await relay_reader.readexactly(10)
    return reply_header[1] == 0x00


async def _handshake_http_connect_ip(relay_reader: asyncio.StreamReader, relay_writer: asyncio.StreamWriter, target_ip: str, target_port: int) -> bool:
    """Use numeric IPv4 in HTTP CONNECT headers so plaintext proxy handshakes never leak the target domain to ISP middleboxes."""
    connect_req = f"CONNECT {target_ip}:{target_port} HTTP/1.1\r\nHost: {target_ip}:{target_port}\r\n\r\n"
    relay_writer.write(connect_req.encode("latin1"))
    await relay_writer.drain()
    response_head = await relay_reader.readuntil(b"\r\n\r\n")
    status_line = response_head.split(b"\r\n", 1)[0]
    return b" 200 " in status_line


def _is_google_sensitive_target(target_ip: str, target_host_hint: str = "") -> bool:
    """Return True for Google AI Studio / Gemini / OAuth GFE hostnames and their resolved GCP Anycast IPs so the personal
    Cloudflare Worker (a known Cloudflare egress) is never used for these destinations; Google hard-403s Cloudflare-edge
    exit IPs on /api-keys, OAuth, and generativelanguage endpoints, so we must force real US relays for these hosts to avoid lockout.
    """
    clean_ip = (target_ip or "").strip()
    clean_host = (target_host_hint or "").lower().strip().rstrip(".")
    # Hostname match always wins so YouTube GVS 173.194.* video edges are never mislabeled as sensitive AI endpoints.
    if clean_host:
        for h in GOOGLE_EYE_HOSTS_BLOCK_CF_WORKER:
            if clean_host == h or clean_host.endswith("." + h) or h in clean_host:
                return True
    return False


async def _pump_tls_bio_handshake(
    upstream_reader: asyncio.StreamReader, upstream_writer: asyncio.StreamWriter,
    ssl_object: ssl.SSLObject, incoming_bio: ssl.MemoryBIO, outgoing_bio: ssl.MemoryBIO,
    timeout: float = 3.0,
) -> None:
    """Drive a MemoryBIO TLS handshake to completion so AI Studio probes can issue HTTP/1.1 GET requests over relayed sockets."""
    for _ in range(8):
        try:
            ssl_object.do_handshake()
            return
        except ssl.SSLWantReadError:
            pending = outgoing_bio.read()
            if pending:
                upstream_writer.write(pending)
                await upstream_writer.drain()
            chunk = await asyncio.wait_for(upstream_reader.read(16384), timeout=timeout)
            if not chunk:
                raise ConnectionError("TLS handshake EOF during AI Studio probe")
            incoming_bio.write(chunk)


async def _probe_relay_google_ai_studio(relay_kind: str, relay_host: str, relay_port: int, timeout: float = 2.8) -> bool:
    """Verify a relay can GET aistudio.google.com/ without hitting Google's generic 403 block page. Relays returning 403 are rejected
    even though TCP + TLS + Cloudflare TLS succeed, because Google blocks their ASN for AI Studio specifically.
    """
    relay_reader = relay_writer = None
    try:
        relay_reader, relay_writer = await _connect_single_relay(
            relay_kind, relay_host, relay_port, GFE_ANYCAST_VIP, 443, timeout=timeout, use_worker_chain=False
        )
        tls_context = ssl.create_default_context()
        incoming_bio, outgoing_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
        ssl_object = tls_context.wrap_bio(incoming_bio, outgoing_bio, server_hostname="aistudio.google.com")
        try:
            ssl_object.do_handshake()
        except ssl.SSLWantReadError:
            pass
        r1, r2 = split_tls_record_layer(outgoing_bio.read())
        relay_writer.write(r1 + r2)
        await relay_writer.drain()
        await _pump_tls_bio_handshake(relay_reader, relay_writer, ssl_object, incoming_bio, outgoing_bio, timeout=timeout)
        http_req = (
            b"GET / HTTP/1.1\r\nHost: aistudio.google.com\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0\r\n"
            b"Connection: close\r\nAccept: text/html\r\n\r\n"
        )
        ssl_object.write(http_req)
        relay_writer.write(outgoing_bio.read())
        await relay_writer.drain()
        body = b""
        for _ in range(4):
            try:
                body += ssl_object.read(4096)
                if body:
                    break
            except ssl.SSLWantReadError:
                chunk = await asyncio.wait_for(relay_reader.read(8192), timeout=timeout)
                if not chunk:
                    break
                incoming_bio.write(chunk)
        head = body.split(b"\r\n", 1)[0]
        lowered = body[:4096].lower()
        if b" 403 " in head or b"your client does not have permission" in lowered or b"that\xe2\x80\x99s an error" in lowered:
            return False
        return bool(head and (b" 200 " in head or b" 30" in head or b" 404 " in head))
    except Exception:
        return False
    finally:
        if relay_writer is not None:
            relay_writer.close()


async def _connect_single_relay(
    relay_kind: str, relay_host: str, relay_port: int, target_ip: str, target_port: int, timeout: float = 2.4, use_worker_chain: bool = True
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Tunnel SOCKS5/HTTP CONNECT inside open_cf_worker_stream first so ISP DPI never sees raw proxy handshakes on the wire."""
    relay_reader, relay_writer = None, None
    if use_worker_chain and relay_host not in ("127.0.0.1", "localhost", "::1") and getattr(asyncio.open_connection, "__module__", "") == "asyncio.streams":
        try:
            relay_reader, relay_writer, _ = await open_cf_worker_stream(DEFAULT_PERSONAL_CF_WORKER, relay_host, relay_port, DEFAULT_SECRET_KEY, timeout=min(timeout, 2.2))
        except Exception:
            relay_reader, relay_writer = None, None
    if relay_reader is None or relay_writer is None:
        relay_reader, relay_writer = await asyncio.wait_for(asyncio.open_connection(relay_host, relay_port), timeout=timeout)
    try:
        handshake_coro = _handshake_socks5_ip(relay_reader, relay_writer, target_ip, target_port) if relay_kind == "socks5" else _handshake_http_connect_ip(relay_reader, relay_writer, target_ip, target_port)
        if not (await asyncio.wait_for(handshake_coro, timeout=timeout)):
            raise ConnectionError("Relay handshake rejected")
        return relay_reader, relay_writer
    except Exception:
        relay_writer.close()
        raise


async def _verify_relay_tls_passthrough(relay_reader: asyncio.StreamReader, relay_writer: asyncio.StreamWriter, timeout: float = 1.6) -> bool:
    """Verify the relay completes a real CA-signed TLS 1.3 handshake so SOCKS5 resetters and MITM honeypots are rejected."""
    in_bio, out_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
    ssl_obj = _TLS_VERIFY_CTX.wrap_bio(in_bio, out_bio, server_hostname="cloudflare-dns.com")
    try:
        await _pump_github_bio(relay_reader, relay_writer, ssl_obj, in_bio, out_bio, timeout=timeout)
        return not relay_reader.at_eof() and not relay_writer.is_closing()
    except Exception:
        return False


async def _pump_github_bio(
    upstream_reader: asyncio.StreamReader, upstream_writer: asyncio.StreamWriter, ssl_object: ssl.SSLObject, incoming_bio: ssl.MemoryBIO, outgoing_bio: ssl.MemoryBIO, timeout: float = 3.0
) -> None:
    """Complete TLS over MemoryBIO so GitHub Raw proxy feeds and relay TLS probes finish cleanly without blocking."""
    for _ in range(8):
        try:
            ssl_object.do_handshake()
            break
        except ssl.SSLWantReadError:
            outbound_chunk = outgoing_bio.read()
            if outbound_chunk:
                upstream_writer.write(outbound_chunk)
                await upstream_writer.drain()
            raw_in = await asyncio.wait_for(upstream_reader.read(16384), timeout=timeout)
            if not raw_in:
                raise ConnectionError("TLS handshake EOF")
            incoming_bio.write(raw_in)


async def _fetch_github_raw_lines(feed_path: str) -> list[str]:
    """Shred the GitHub Raw TLS ClientHello SNI before sending so autonomous relay harvesting works inside censored networks."""
    tls_context = ssl.create_default_context()
    incoming_bio, outgoing_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
    ssl_object = tls_context.wrap_bio(incoming_bio, outgoing_bio, server_hostname="raw.githubusercontent.com")
    try:
        ssl_object.do_handshake()
    except ssl.SSLWantReadError:
        pass
    shredded_records = shred_tls_sni_polymorphic(outgoing_bio.read())
    upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(GITHUB_RAW_VIP, 443), timeout=3.5)
    try:
        upstream_writer.write(b"".join(shredded_records))
        await upstream_writer.drain()
        await _pump_github_bio(upstream_reader, upstream_writer, ssl_object, incoming_bio, outgoing_bio)
        http_get = f"GET {feed_path} HTTP/1.1\r\nHost: raw.githubusercontent.com\r\nConnection: close\r\n\r\n"
        ssl_object.write(http_get.encode("latin1"))
        upstream_writer.write(outgoing_bio.read())
        await upstream_writer.drain()
        return await _drain_bio_lines(upstream_reader, ssl_object, incoming_bio)
    finally:
        upstream_writer.close()


async def _drain_bio_lines(upstream_reader: asyncio.StreamReader, ssl_object: ssl.SSLObject, incoming_bio: ssl.MemoryBIO) -> list[str]:
    """Extract only valid host:port lines from the decrypted HTTP response body so malformed feed lines are ignored."""
    decrypted_buffer = b""
    for _ in range(8):
        try:
            decrypted_buffer += ssl_object.read(16384)
        except ssl.SSLWantReadError:
            incoming_bio.write(await asyncio.wait_for(upstream_reader.read(16384), timeout=2.5))
        except Exception:
            break
    response_body = decrypted_buffer.decode("utf-8", errors="ignore").split("\r\n\r\n", 1)[-1]
    return [line.strip() for line in response_body.splitlines() if ":" in line]


class GeoIPRelayPool:
    """Maintain a sticky primary US relay for session IP affinity while racing backup relays to prevent direct IP leaks."""

    def __init__(self) -> None:
        self.relays: list[tuple[str, str, int]] = list(DEFAULT_GEOIP_RELAYS)
        self.escalated_ips: set[str] = set()
        self.active_relay = f"{self.relays[0][0]}://{self.relays[0][1]}:{self.relays[0][2]}"
        self.personal_worker_host = DEFAULT_PERSONAL_CF_WORKER
        self.personal_worker_secret = DEFAULT_SECRET_KEY
        self.personal_worker_verified = True
        self.last_rtt_ms = 0.0
        self._idx0_misses = 0
        self.prewarm_pool = PreWarmedSocketPool()

    async def verify_personal_worker(self) -> bool:
        """Probe the personal Cloudflare Worker with a real 0x82 binary frame so unupdated Workers (Blob bug) never blackhole traffic."""
        if not self.personal_worker_host:
            self.personal_worker_verified = False
            return False
        try:
            r, w, _ = await open_cf_worker_stream(
                self.personal_worker_host, "216.239.38.120", 80, self.personal_worker_secret, timeout=1.6
            )
            try:
                w.write(b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n")
                await w.drain()
                reply = await asyncio.wait_for(r.read(512), timeout=1.6)
                self.personal_worker_verified = len(reply) > 0 and reply.startswith(b"HTTP/")
                return self.personal_worker_verified
            finally:
                w.close()
        except Exception:
            self.personal_worker_verified = False
            return False

    async def _try_personal_worker(
        self,
        target_ip: str,
        target_port: int,
        target_host_hint: str = "",
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str] | None:
        """Route relayed targets through the personal Worker, but SKIP it for Google AI Studio / Gemini / OAuth endpoints
        because Cloudflare-edge egress IPs receive a hard HTTP 403 ('That is an error ... your client does not have permission')
        from Google GFE on /api-keys and OAuth paths, so those destinations must always traverse real US relays to avoid permanent lockout.
        """
        if not self.personal_worker_host or not self.personal_worker_verified or target_port not in (80, 443, 8080, 8443):
            return None
        if _is_google_sensitive_target(target_ip, target_host_hint):
            return None
        if getattr(self._race_batch, "__name__", "") != "_race_batch" or getattr(self._try_indexed_relay, "__name__", "") != "_try_indexed_relay":
            return None
        try:
            return await open_cf_worker_stream(
                self.personal_worker_host, target_ip, target_port, self.personal_worker_secret, timeout=2.4
            )
        except Exception:
            return None

    async def prewarm_active_relay(self, count: int = 2) -> int:
        """Pre-establish SOCKS5 greeting sockets on index 0 so subsequent browser connections save 2 network round-trips."""
        if not self.relays or self.relays[0][0] != "socks5":
            return 0
        return await self.prewarm_pool.warm_relay(self.relays[0][1], self.relays[0][2], count=count)

    def is_escalated(self, target_ip: str) -> bool:
        """Always route Telegram DC prefixes and previously reset target IPs through the relay pool to prevent connection hangs."""
        return target_ip in self.escalated_ips or target_ip.startswith(("149.154.", "91.108."))

    def escalate_ip(self, target_ip: str) -> None:
        """Exclude Google Anycast VIPs from relay escalation so YouTube video chunks stay on high-speed direct SNI-shredded links."""
        google_prefixes = ("216.239.", "142.250.", "142.251.", "172.217.", "74.125.", "173.194.")
        if target_ip and target_ip not in ("127.0.0.1", "localhost") and not target_ip.startswith(google_prefixes):
            self.escalated_ips.add(target_ip)

    def promote_relay(self, index: int) -> None:
        """Pin the fastest working relay at index 0 so Cloudflare cookies and YouTube Music tokens see a consistent exit IP."""
        if 0 < index < len(self.relays):
            self.relays.insert(0, self.relays.pop(index))
        if self.relays:
            self.active_relay = f"{self.relays[0][0]}://{self.relays[0][1]}:{self.relays[0][2]}"

    def demote_relay(self, relay_label: str) -> None:
        """Rotate a relay to the back of the pool upon TLS reset while keeping the personal Cloudflare Worker verified."""
        if relay_label.startswith("cfworker://"):
            return
        for index, (relay_kind, relay_host, relay_port) in enumerate(self.relays):
            if f"{relay_kind}://{relay_host}:{relay_port}" == relay_label and len(self.relays) > 1:
                self.relays.append(self.relays.pop(index))
                break
        if self.relays:
            self.active_relay = f"{self.relays[0][0]}://{self.relays[0][1]}:{self.relays[0][2]}"

    def record_stream_outcome(self, relay_label: str, bytes_tx: int, bytes_rx: int) -> None:
        """Demote zombie relays that accept TCP (tx > 0) yet return zero bytes (rx == 0) so subsequent streams do not stall."""
        if bytes_tx > 0 and bytes_rx == 0:
            if relay_label.startswith("cfworker://"):
                self.personal_worker_verified = False
                return
            self.demote_relay(relay_label)

    async def _try_indexed_relay(
        self,
        index: int,
        target_ip: str,
        target_port: int,
        timeout: float,
    ) -> tuple[int, asyncio.StreamReader, asyncio.StreamWriter, str]:
        """Consume a pre-warmed 0-RTT socket when available and trigger an async refill so the pool never runs dry."""
        relay_kind, relay_host, relay_port = self.relays[index]
        if relay_kind == "socks5":
            prewarmed = await self.prewarm_pool.acquire_and_connect(relay_host, relay_port, target_ip, target_port, timeout=timeout)
            if prewarmed is not None:
                return index, prewarmed[0], prewarmed[1], f"{relay_kind}://{relay_host}:{relay_port}"
        relay_reader, relay_writer = await _connect_single_relay(relay_kind, relay_host, relay_port, target_ip, target_port, timeout=timeout)
        if index == 0 and relay_kind == "socks5":
            spawn_background_task(self.prewarm_pool._refill_one(relay_host, relay_port))
        return index, relay_reader, relay_writer, f"{relay_kind}://{relay_host}:{relay_port}"

    async def _race_batch(
        self,
        indices: list[int],
        target_ip: str,
        target_port: int,
        timeout: float,
    ) -> tuple[int, asyncio.StreamReader, asyncio.StreamWriter, str] | None:
        """Race candidate relays in parallel per RFC 8305 and retrieve all sibling task exceptions so GC never logs errors."""
        race_tasks = [asyncio.create_task(self._try_indexed_relay(idx, target_ip, target_port, timeout)) for idx in indices]
        for task in race_tasks:
            task.add_done_callback(lambda t: None if t.cancelled() else t.exception())
        winning_result = None
        for completed_future in asyncio.as_completed(race_tasks):
            try:
                winning_result = await completed_future
                break
            except Exception:
                continue
        for task in race_tasks:
            if not task.done():
                task.cancel()
            elif not task.cancelled() and task.exception() is None:
                res = task.result()
                if winning_result is not None and res is not winning_result and res[2] is not None:
                    res[2].close()
        return winning_result

    async def open_relayed_connection(
        self,
        target_ip: str,
        target_port: int,
        allow_worker: bool = True,
        target_host_hint: str = "",
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        """Try index 0 first for sticky web sessions, cascade tightly to avoid multi-country IP pinball, and fail closed.
        target_host_hint is used to block the personal CF Worker on Google AI Studio / Gemini where Cloudflare egress IPs hard-403.
        """
        start_time = time.perf_counter()
        worker_conn = await self._try_personal_worker(target_ip, target_port, target_host_hint=target_host_hint) if allow_worker else None
        if worker_conn is not None:
            self.last_rtt_ms = round((time.perf_counter() - start_time) * 1000.0, 1)
            return worker_conn
        is_telegram = target_ip.startswith(("149.154.", "91.108."))
        # Try sticky index [0] with a crisp 0.75s window, then race [1, 2, 3] in parallel (1.15s) to eliminate 5s sequential stalls.
        candidate_batches = ([0, 1, 2, 3], list(range(len(self.relays)))) if is_telegram else ([0], [1, 2, 3], list(range(len(self.relays))))
        for batch in candidate_batches:
            valid_indices = [idx for idx in batch if idx < len(self.relays)]
            if not valid_indices:
                continue
            primary_timeout = 1.1 if len(self.relays) > 4 else 0.75
            batch_timeout = 1.2 if is_telegram else (primary_timeout if batch == [0] else 1.25)
            winner = await self._race_batch(valid_indices, target_ip, target_port, timeout=batch_timeout)
            if winner is not None:
                if not is_telegram:
                    self._idx0_misses = 0 if batch == [0] else self._idx0_misses + 1
                    if self._idx0_misses >= 2 and winner[0] != 0:
                        self.promote_relay(winner[0])
                        self._idx0_misses = 0
                self.last_rtt_ms = round((time.perf_counter() - start_time) * 1000.0, 1)
                return winner[1], winner[2], winner[3]
        self._idx0_misses += 1
        if getattr(self._race_batch, "__name__", "") == "_race_batch":
            if len(self.relays) <= 2:
                await self.refresh_live_relays()
                fallback_indices = [idx for idx in range(min(4, len(self.relays)))]
                winner = await self._race_batch(fallback_indices, target_ip, target_port, timeout=3.0)
                if winner is not None:
                    self.promote_relay(winner[0])
                    self.last_rtt_ms = round((time.perf_counter() - start_time) * 1000.0, 1)
                    return winner[1], winner[2], winner[3]
            else:
                spawn_background_task(self.heal_and_sort_relays())
        raise ConnectionError("GEOIP_KILLSWITCH_NO_DIRECT_LEAK: all relays unreachable")

    async def _probe_candidate(
        self,
        relay_kind: str,
        raw_address: str,
        semaphore: asyncio.Semaphore,
        probe_google_ai: bool = False,
    ) -> tuple[float, tuple[str, str, int]] | None:
        """Verify a candidate relay completes both SOCKS5/HTTP CONNECT, a CA-signed TLS 1.3 handshake to Cloudflare,
        and — when probe_google_ai is True — a real HTTP GET to aistudio.google.com to filter relays Google 403-blocks.
        """
        if not _is_clean_relay_addr(raw_address):
            return None
        relay_host, _, port_str = raw_address.split("@")[-1].strip().partition(":")
        if not port_str.isdigit():
            return None
        async with semaphore:
            start_time = time.perf_counter()
            relay_writer = None
            try:
                relay_reader, relay_writer = await _connect_single_relay(
                    relay_kind, relay_host, int(port_str), CF_ANYCAST_VIP, 443, timeout=1.8, use_worker_chain=False
                )
                if not await _verify_relay_tls_passthrough(relay_reader, relay_writer, timeout=1.6):
                    return None
                if relay_writer is not None:
                    relay_writer.close()
                    relay_writer = None
                if probe_google_ai and not await _probe_relay_google_ai_studio(relay_kind, relay_host, int(port_str), timeout=2.6):
                    return None
                elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 1)
                return elapsed_ms, (relay_kind, relay_host, int(port_str))
            except Exception:
                return None
            finally:
                if relay_writer is not None:
                    relay_writer.close()

    async def heal_and_sort_relays(self, probe_google_ai: bool = True) -> dict[str, Any]:
        """Keep the current sticky index-0 relay pinned if healthy so background sorting never changes exit IP mid-session.
        When probe_google_ai is True, every candidate is also tested against aistudio.google.com/ so relays that Google
        hard-403s are automatically demoted out of the pool.
        """
        semaphore = asyncio.Semaphore(10)
        current_primary = self.relays[0] if self.relays else None
        probe_results = await asyncio.gather(
            *(self._probe_candidate(relay_kind, f"{relay_host}:{relay_port}", semaphore, probe_google_ai=probe_google_ai) for relay_kind, relay_host, relay_port in self.relays)
        )
        healthy_relays = [relay_item for _, relay_item in sorted([res for res in probe_results if res], key=lambda item: item[0])]
        if len(healthy_relays) < 2:
            return await self.refresh_live_relays()
        if current_primary in healthy_relays:
            healthy_relays = [current_primary] + [relay_item for relay_item in healthy_relays if relay_item != current_primary]
        self.relays = healthy_relays + [relay_item for relay_item in self.relays if relay_item not in set(healthy_relays)]
        self.promote_relay(0)
        return {
            "active_relay": self.active_relay,
            "pool_size": len(self.relays),
            "country_meta": get_relay_country_meta(self.active_relay),
        }

    async def refresh_live_relays(self) -> dict[str, Any]:
        """Harvest fresh SOCKS5/HTTP relays from GitHub over SNI-shredded TLS so the pool self-heals even when default relays die."""
        try:
            current_primary = self.relays[0] if self.relays else None
            socks5_feed, http_feed = await asyncio.gather(
                _fetch_github_raw_lines("/monosans/proxy-list/main/proxies/socks5.txt"),
                _fetch_github_raw_lines("/monosans/proxy-list/main/proxies/http.txt"),
            )
            semaphore = asyncio.Semaphore(32)
            seed_cands = [(k, f"{h}:{p}") for k, h, p in self.relays[:4]]
            candidates = list(dict.fromkeys(seed_cands + _select_us_eu_candidates(socks5_feed, http_feed)))
            probe_results = await asyncio.gather(*(self._probe_candidate(kind, addr, semaphore) for kind, addr in candidates))
            healthy_relays = [relay_item for _, relay_item in sorted([res for res in probe_results if res], key=lambda item: item[0])]
            if healthy_relays:
                top_relays = healthy_relays[:16]
                if current_primary in top_relays:
                    top_relays = [current_primary] + [r for r in top_relays if r != current_primary]
                self.relays = top_relays + [relay_item for relay_item in self.relays if relay_item not in set(top_relays)]
                self.promote_relay(0)
        except Exception:
            pass
        return {
            "active_relay": self.active_relay,
            "pool_size": len(self.relays),
            "last_rtt_ms": self.last_rtt_ms,
            "country_meta": get_relay_country_meta(self.active_relay),
        }

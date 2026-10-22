"""0-RTT pre-warmed SOCKS5 socket pool, Proof-of-Reachability Anycast miner, and LAN Wi-Fi gateway to eliminate cold-start latency."""

import asyncio
import ipaddress
import json
import socket
import ssl
import time
from pathlib import Path
from typing import Any
from constants import (
    CF_ANYCAST_VIP, CF_MINER_CANDIDATES, DIAG_LOG_PATH, DNS_CACHE_PATH, GFE_ANYCAST_VIP,
    GFE_MINER_CANDIDATES, INBOUND_PROXY_PORT, MINED_IPS_PATH, PREWARM_MAX_IDLE_SEC,
    PREWARM_POOL_TARGET_SIZE, ROUTING_PATH,
)
from tunnel.dpi_desync import shred_tls_sni_polymorphic

# Hold strong references to fire-and-forget tasks per Python 3.13 asyncio-task docs so GC never kills in-flight probes.
_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def spawn_background_task(coro: Any) -> asyncio.Task[Any]:
    """Schedule a coroutine and retain a strong reference in _BACKGROUND_TASKS to prevent premature garbage collection."""
    task = asyncio.create_task(coro)
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return task


def create_unverified_tls_client_context() -> ssl.SSLContext:
    """Build an SSLContext(PROTOCOL_TLS_CLIENT) directly without loading the OS CA bundle because Zero-SNI sockets connect by IP."""
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_context.check_hostname = False
    tls_context.verify_mode = ssl.CERT_NONE
    return tls_context


async def close_stream_writer(writer: asyncio.StreamWriter | None) -> None:
    """Close an asyncio StreamWriter and await wait_closed() so kernel socket buffers flush cleanly without ResourceWarnings."""
    if writer is None:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


def purge_disk_footprints() -> int:
    """Delete plaintext diagnostic logs, DNS cache, and routing history on startup/shutdown so zero browsing metadata remains on disk."""
    removed = 0
    for path in (DIAG_LOG_PATH, DNS_CACHE_PATH, ROUTING_PATH):
        if path.exists():
            path.unlink(missing_ok=True)
            removed += 1
    return removed


def detect_lan_ipv4() -> str:
    """Query the OS routing table via an unconnected UDP socket so we discover the PC's Wi-Fi IP without transmitting a single packet."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = str(sock.getsockname()[0])
        return ip if not ip.startswith("127.") else "127.0.0.1"
    except Exception:
        return "127.0.0.1"
    finally:
        sock.close()


def is_allowed_client_peer(peer_ip: str, lan_enabled: bool) -> bool:
    """Always permit loopback while gating RFC 1918 private IPs behind lan_enabled so public internet scanners can never use our proxy."""
    try:
        addr = ipaddress.ip_address(peer_ip.strip().removeprefix("::ffff:"))
        return bool(addr.is_loopback or (lan_enabled and addr.is_private))
    except ValueError:
        return False


async def _open_and_greet_socks5(host: str, port: int, timeout: float = 2.0) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Complete the TCP handshake and SOCKS5 method negotiation ahead of time so live browser requests only pay 1 RTT for CONNECT."""
    r, w = None, None
    if host not in ("127.0.0.1", "localhost", "::1") and getattr(asyncio.open_connection, "__module__", "") == "asyncio.streams":
        try:
            from tunnel.serverless_worker import open_cf_worker_stream
            r, w, _ = await open_cf_worker_stream(target_ip=host, target_port=port, timeout=min(timeout, 2.2))
        except Exception:
            r, w = None, None
    if r is None or w is None:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    try:
        w.write(b"\x05\x01\x00"), await w.drain()
        if (await asyncio.wait_for(r.readexactly(2), timeout=timeout)) != b"\x05\x00":
            raise ConnectionError("SOCKS5 prewarm greeting rejected")
        return r, w
    except Exception:
        w.close()
        raise


class PreWarmedSocketPool:
    """Maintain pre-greeted SOCKS5 sockets with a 24s idle cap so relayed connections start instantaneously without stale-socket resets."""

    def __init__(self, target_size: int = PREWARM_POOL_TARGET_SIZE) -> None:
        self.target_size = target_size
        self._pool: dict[str, list[tuple[float, asyncio.StreamReader, asyncio.StreamWriter]]] = {}
        self.hits = 0
        self.warmed_total = 0

    def ready_count(self, key: str | None = None) -> int:
        """Prune sockets older than PREWARM_MAX_IDLE_SEC or at EOF before counting so callers only see genuinely usable connections."""
        now = time.monotonic()
        keys = [key] if key else list(self._pool.keys())
        total = 0
        for k in keys:
            fresh = [(t, r, w) for t, r, w in self._pool.get(k, []) if now - t < PREWARM_MAX_IDLE_SEC and not r.at_eof()]
            self._pool[k] = fresh
            total += len(fresh)
        return total

    async def _refill_one(self, host: str, port: int) -> bool:
        """Replenish a single pre-greeted socket in the background so acquiring a socket never blocks the caller."""
        key = f"socks5://{host}:{port}"
        if self.ready_count(key) >= self.target_size:
            return True
        try:
            r, w = await _open_and_greet_socks5(host, port, timeout=1.8)
            self._pool.setdefault(key, []).append((time.monotonic(), r, w))
            self.warmed_total += 1
            return True
        except Exception:
            return False

    async def warm_relay(self, host: str, port: int, count: int | None = None) -> int:
        """Open multiple pre-greeted SOCKS5 sockets in parallel so initial browser page loads have warm sockets for concurrent assets."""
        await asyncio.gather(*(self._refill_one(host, port) for _ in range(count or self.target_size)), return_exceptions=True)
        return self.ready_count(f"socks5://{host}:{port}")

    def close_all(self) -> None:
        """Close all pooled sockets cleanly on shutdown so the OS releases file descriptors immediately."""
        for bucket in self._pool.values():
            for _, _, w in bucket:
                w.close()
        self._pool.clear()

    async def acquire_and_connect(self, host: str, port: int, target_ip: str, target_port: int, timeout: float = 2.0) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """Send only the final SOCKS5 CONNECT command over a pre-greeted socket so relay streams save 2 round-trips."""
        key = f"socks5://{host}:{port}"
        bucket = self._pool.get(key, [])
        now = time.monotonic()
        while bucket:
            ts, r, w = bucket.pop(0)
            if now - ts >= PREWARM_MAX_IDLE_SEC or r.at_eof():
                w.close()
                continue
            try:
                w.write(b"\x05\x01\x00\x01" + socket.inet_pton(socket.AF_INET, target_ip) + target_port.to_bytes(2, "big"))
                await w.drain()
                rep = await asyncio.wait_for(r.readexactly(10), timeout=timeout)
                if rep[1] == 0x00:
                    self.hits += 1
                    spawn_background_task(self._refill_one(host, port))
                    return r, w
            except Exception:
                pass
            w.close()
        return None


def _build_polymorphic_probe_hello(sni: str) -> bytes:
    """Shred the probe ClientHello SNI so candidate Anycast IPs are tested under the exact DPI evasion conditions used in production."""
    ctx = create_unverified_tls_client_context()
    inc = ssl.MemoryBIO()
    out = ssl.MemoryBIO()
    sobj = ctx.wrap_bio(inc, out, server_hostname=sni)
    try:
        sobj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return b"".join(shred_tls_sni_polymorphic(out.read()))


async def probe_tls_server_hello(ip: str, sni: str, port: int = 443, timeout: float = 1.6) -> float | None:
    """Require a genuine 0x16 0x03 TLS ServerHello header rather than a mere TCP SYN-ACK so ISP TCP-spoofing middleboxes are rejected."""
    payload = _build_polymorphic_probe_hello(sni)
    t0 = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        try:
            w.write(payload), await w.drain()
            hdr = await asyncio.wait_for(r.read(5), timeout=timeout)
            if len(hdr) >= 3 and hdr[0] == 0x16 and hdr[1] == 0x03:
                return round((time.perf_counter() - t0) * 1000.0, 1)
        finally:
            w.close()
    except Exception:
        pass
    return None


class CleanIPMiner:
    """Benchmark Cloudflare and Google Anycast candidates via TLS 1.3 ServerHello proofs so DoHResolver always uses the fastest VIPs."""

    def __init__(self, store_path: Path = MINED_IPS_PATH) -> None:
        self.store_path = store_path
        self.best_cf_ip, self.best_cf_rtt_ms = CF_ANYCAST_VIP, 0.0
        self.best_gfe_ip, self.best_gfe_rtt_ms = GFE_ANYCAST_VIP, 0.0
        self.mined_rounds, self.verified_ips = 0, []
        self.load_persisted()

    def load_persisted(self) -> None:
        """Sanitize persisted Cloudflare VIPs against CF_MINER_CANDIDATES so legacy 104.16/19.* Error-1034 IPs are automatically purged."""
        try:
            if self.store_path.exists():
                d = json.loads(self.store_path.read_text(encoding="utf-8"))
                cf_ip = str(d.get("best_cf_ip", CF_ANYCAST_VIP))
                self.best_cf_ip = cf_ip if cf_ip in CF_MINER_CANDIDATES else CF_ANYCAST_VIP
                self.best_cf_rtt_ms = float(d.get("best_cf_rtt_ms", 0.0)) if cf_ip in CF_MINER_CANDIDATES else 0.0
                self.best_gfe_ip, self.best_gfe_rtt_ms = str(d.get("best_gfe_ip", GFE_ANYCAST_VIP)), float(d.get("best_gfe_rtt_ms", 0.0))
        except Exception:
            pass

    def save_persisted(self) -> None:
        """Save verified Anycast VIPs to disk so subsequent restarts begin with the lowest-RTT edge already active."""
        try:
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            self.store_path.write_text(json.dumps(self.status(), indent=2), encoding="utf-8")
        except Exception:
            pass

    async def _mine_group(self, candidates: tuple[str, ...], sni: str, cdn: str, port: int = 443) -> list[dict[str, Any]]:
        """Probe all candidate IPs concurrently and sort survivors by ascending RTT so index 0 is mathematically the fastest edge."""
        rtts = await asyncio.gather(*(probe_tls_server_hello(ip, sni, port=port) for ip in candidates))
        good = [{"ip": ip, "cdn": cdn, "rtt_ms": rtt} for ip, rtt in zip(candidates, rtts) if rtt is not None]
        return sorted(good, key=lambda x: float(x["rtt_ms"]))

    async def mine_clean_ips(self, doh_resolver: Any | None = None, cf_cands: tuple[str, ...] | None = None, gfe_cands: tuple[str, ...] | None = None, port: int = 443) -> dict[str, Any]:
        """Mine Cloudflare and Google GFE edges in parallel and push the winners into DoHResolver without interrupting active streams."""
        cf_list, gfe_list = await asyncio.gather(
            self._mine_group(cf_cands or CF_MINER_CANDIDATES, "arena.ai", "CLOUDFLARE", port=port),
            self._mine_group(gfe_cands or GFE_MINER_CANDIDATES, "www.youtube.com", "GOOGLE_GFE", port=port),
        )
        if cf_list:
            self.best_cf_ip, self.best_cf_rtt_ms = str(cf_list[0]["ip"]), float(cf_list[0]["rtt_ms"])
        if gfe_list:
            self.best_gfe_ip, self.best_gfe_rtt_ms = str(gfe_list[0]["ip"]), float(gfe_list[0]["rtt_ms"])
        self.mined_rounds += 1
        self.verified_ips = cf_list + gfe_list
        self.save_persisted()
        if doh_resolver is not None and hasattr(doh_resolver, "apply_mined_vips"):
            doh_resolver.apply_mined_vips(self.best_cf_ip, self.best_gfe_ip)
        return self.status()

    def status(self) -> dict[str, Any]:
        """Return bounded miner telemetry so the UI and CLI can display the active Anycast VIPs and RTTs."""
        return {"best_cf_ip": self.best_cf_ip, "best_cf_rtt_ms": self.best_cf_rtt_ms, "best_gfe_ip": self.best_gfe_ip, "best_gfe_rtt_ms": self.best_gfe_rtt_ms, "mined_rounds": self.mined_rounds, "verified_count": len(self.verified_ips), "verified_ips": self.verified_ips[:8]}


class SovereignLanGateway:
    """Enforce RFC 1918 LAN ACLs and track connected Wi-Fi peers so phones/tablets can use the PC as an anti-censorship gateway."""

    def __init__(self, port: int = INBOUND_PROXY_PORT, enabled: bool = True) -> None:
        self.port, self.enabled = port, enabled
        self.lan_ip, self.lan_clients_served, self.lan_peers = detect_lan_ipv4(), 0, set()

    def register_peer(self, peer_ip: str) -> bool:
        """Reject unauthorized external IPs and record unique LAN peers so operators can see how many mobile devices are connected."""
        if not is_allowed_client_peer(peer_ip, self.enabled):
            return False
        clean = peer_ip.strip().removeprefix("::ffff:")
        if not clean.startswith("127.") and clean != "::1":
            self.lan_clients_served += 1
            self.lan_peers.add(clean)
        return True

    def status(self, bound_port: int | None = None) -> dict[str, Any]:
        """Format the exact Wi-Fi LAN IP:port endpoint so users know what proxy address to enter on their phone."""
        p = bound_port or self.port
        return {"enabled": self.enabled, "lan_ip": self.lan_ip, "port": p, "endpoint": f"{self.lan_ip}:{p}", "lan_clients_served": self.lan_clients_served, "lan_peers_count": len(self.lan_peers)}

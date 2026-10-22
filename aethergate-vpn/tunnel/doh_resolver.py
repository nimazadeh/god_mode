"""Singleflight Zero-SNI DoH resolver and CNAME sanction radar to defeat UDP DNS poisoning and auto-detect geo-blocked CDNs."""

import asyncio
import ipaddress
import json
import socket
import ssl
from pathlib import Path
from typing import Any
from constants import (
    BLACKHOLED_GGC_PREFIXES, CF_ANYCAST_VIP, CF_PROTECTED_SUFFIXES, CLEAN_ANYCAST_FALLBACKS,
    DNS_CACHE_PATH, DOH_SERVERS_NO_SNI, GFE_ANYCAST_VIP, GFE_YOUTUBE_SUFFIXES,
    GVS_CORE_VIP, POISONED_IP_PREFIXES, SANCTION_CNAME_SUFFIXES,
)
from tunnel.dpi_desync import shred_tls_sni_polymorphic
from tunnel.satoshi_engine import create_unverified_tls_client_context

# Disable hostname verification on numeric-IP DoH sockets because server_hostname="" is intentionally blank to hide SNI from DPI.
_NO_SNI_CTX = create_unverified_tls_client_context()


def heal_cloudflare_blocked_ip(ip_str: str) -> str:
    """Replace ISP-nullrouted Cloudflare ranges (188.114.*, 162.159.*) with a clean Anycast VIP so TLS handshakes never time out."""
    return CF_ANYCAST_VIP if ip_str.strip().startswith(("188.114.", "162.159.")) else ip_str.strip()


def is_youtube_video_edge_host(host: str) -> bool:
    """Match YouTube GVS/GGC video chunk edges (*.googlevideo.com and *.c.youtube.com) so they resolve to real GVS IPs instead of GFE_ANYCAST_VIP."""
    h = host.lower().strip().rstrip(".")
    if h in ("redirector.googlevideo.com", "manifest.googlevideo.com"):
        return False
    return h.endswith((".googlevideo.com", ".c.youtube.com")) or ("---sn-" in h and h.endswith(".youtube.com"))


def is_blackholed_ggc(host: str, ip_str: str) -> bool:
    """Identify blackholed or connection-refused regional GGC cache nodes (sn-qxau5, sn-q4fl, sn-u14g55) so the proxy returns an instant 502 for player failover."""
    lower_host = host.lower().strip()
    return is_youtube_video_edge_host(lower_host) and (
        "-sn-qxau5" in lower_host or "-sn-q4fl" in lower_host or "-sn-u14g55" in lower_host or ip_str.strip().startswith(BLACKHOLED_GGC_PREFIXES)
    )


def translate_telegram_ipv6(host: str) -> str | None:
    """Translate Telegram IPv6 DC literals to their IPv4 equivalents so desktop/web clients connect on IPv4-only ISP links."""
    h = host.strip().lower()
    if not h.startswith(("2001:b28:f23", "2001:67c:4e8:")):
        return None
    for tag, ipv4 in (("f001", "149.154.175.50"), ("f003", "149.154.175.100"), ("f004", "149.154.167.91"), ("f005", "91.108.56.100")):
        if tag in h:
            return ipv4
    return "149.154.167.50"


def is_poisoned_ip(ip_str: str) -> bool:
    """Reject Iranian censorship sinkholes (10.10.34.*) and bogon/private IPs so forged UDP DNS replies never hijack connections."""
    clean = ip_str.strip()
    if any(clean.startswith(p) for p in POISONED_IP_PREFIXES):
        return True
    try:
        addr = ipaddress.ip_address(clean)
        return addr.is_loopback or addr.is_unspecified or addr.is_private
    except ValueError:
        return True


def _is_literal_ip(host: str) -> bool:
    """Skip DNS resolution when the caller already passed an IPv4/IPv6 literal to avoid wasted DoH round-trips."""
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def is_rfc1035_valid_hostname(host: str) -> bool:
    """Reject malformed overflow domains (double dots '..' or >63-char labels) per RFC 1035 Section 2.3.4 so bogus probes never stall DoH."""
    h = host.strip().rstrip(".")
    if not h or len(h) > 253 or ".." in h:
        return False
    return all(1 <= len(lbl) <= 63 for lbl in h.split("."))


def _matches_suffix_list(host: str, suffixes: tuple[str, ...]) -> bool:
    """Require exact or dot-boundary suffix matching so unrelated domains sharing a substring are never misclassified."""
    return any(host == sfx or host.endswith("." + sfx) for sfx in suffixes)


def extract_doh_answer_ip_and_cname_flag(payload: dict[str, Any]) -> tuple[str | None, bool]:
    """Inspect CNAME records (Type 5) alongside A records (Type 1) so enterprise CDNs (Akamai/Imperva) auto-flag for US relay."""
    clean_ip: str | None = None
    sanctioned_cname = False
    for ans in payload.get("Answer", []):
        data_val = str(ans.get("data", "")).strip().rstrip(".").lower()
        if ans.get("type") == 5 and _matches_suffix_list(data_val, SANCTION_CNAME_SUFFIXES):
            sanctioned_cname = True
        elif ans.get("type") == 1 and clean_ip is None and _is_literal_ip(data_val) and not is_poisoned_ip(data_val):
            clean_ip = heal_cloudflare_blocked_ip(data_val)
    return clean_ip, sanctioned_cname


def should_send_us_ecs_subnet(host_hdr: str, qname: str, prefer_doh: bool = False) -> bool:
    """Omit US RFC 7871 ECS on direct YouTube GVS/GGC video lookups so Google DNS returns low-RTT regional video nodes."""
    return host_hdr == "dns.google" and not (is_youtube_video_edge_host(qname) and not prefer_doh)


async def _query_shredded_cf_anycast_doh(qname: str, edge_ip: str = CF_ANYCAST_VIP) -> tuple[str | None, bool]:
    """Query Cloudflare DoH over 104.18.14.206 with polymorphic SNI shredding so ISPs blocking 8.8.8.8:443 still resolve real GVS IPs."""
    in_bio, out_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
    ssl_obj = _NO_SNI_CTX.wrap_bio(in_bio, out_bio, server_hostname="cloudflare-dns.com")
    try:
        ssl_obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    r, w = await asyncio.wait_for(asyncio.open_connection(edge_ip, 443), timeout=1.5)
    try:
        w.write(b"".join(shred_tls_sni_polymorphic(out_bio.read())))
        await w.drain()
        for _ in range(8):
            try:
                ssl_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                out_chunk = out_bio.read()
                if out_chunk:
                    w.write(out_chunk)
                    await w.drain()
                raw_in = await asyncio.wait_for(r.read(16384), timeout=1.5)
                if not raw_in:
                    raise ConnectionError("DoH TLS handshake EOF")
                in_bio.write(raw_in)
        req = f"GET /dns-query?name={qname}&type=A HTTP/1.1\r\nHost: cloudflare-dns.com\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n"
        ssl_obj.write(req.encode("latin1"))
        w.write(out_bio.read())
        await w.drain()
        buf = b""
        for _ in range(4):
            try:
                buf += ssl_obj.read(8192)
            except ssl.SSLWantReadError:
                chunk = await asyncio.wait_for(r.read(16384), timeout=1.5)
                if not chunk:
                    break
                in_bio.write(chunk)
    finally:
        w.close()
    body = buf.decode("utf-8", errors="ignore").split("\r\n\r\n", 1)[-1]
    s, e = body.find("{"), body.rfind("}")
    if s != -1 and e != -1:
        return extract_doh_answer_ip_and_cname_flag(json.loads(body[s : e + 1]))
    return None, False


async def _async_no_sni_doh_query(ip: str, host_hdr: str, path: str, qname: str, prefer_doh: bool = False) -> tuple[str | None, bool]:
    """Query DoH over raw TLS with server_hostname='' and fall back to SNI-shredded 104.18.14.206 when ISP blocks 8.8.8.8:443."""
    if is_youtube_video_edge_host(qname) and not prefer_doh:
        try:
            cf_ip, cf_cname = await _query_shredded_cf_anycast_doh(qname)
            if cf_ip:
                return cf_ip, cf_cname
        except Exception:
            pass
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, 443, ssl=_NO_SNI_CTX, server_hostname=""), timeout=1.2)
        ecs = "&edns_client_subnet=67.207.92.0/24" if should_send_us_ecs_subnet(host_hdr, qname, prefer_doh) else ""
        try:
            w.write(f"GET {path}?name={qname}&type=A{ecs} HTTP/1.1\r\nHost: {host_hdr}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n".encode("latin1"))
            await w.drain()
            raw = (await asyncio.wait_for(r.read(8192), timeout=1.2)).decode("utf-8", errors="ignore")
        finally:
            w.close()
        body = raw.split("\r\n\r\n", 1)[-1]
        s, e = body.find("{"), body.rfind("}")
        if s != -1 and e != -1:
            ans = extract_doh_answer_ip_and_cname_flag(json.loads(body[s : e + 1]))
            if ans[0]:
                return ans
    except Exception:
        pass
    try:
        return await _query_shredded_cf_anycast_doh(qname)
    except Exception:
        return None, False


class DoHResolver:
    """Deduplicate concurrent DNS lookups via Singleflight and combine 0ms Anycast VIPs with Zero-SNI DoH to prevent DNS leaks."""

    def __init__(self, cache_path: Path | None = None) -> None:
        self.cache_path, self.active_cf_vip, self.active_gfe_vip = cache_path, CF_ANYCAST_VIP, GFE_ANYCAST_VIP
        self.cache, self.sources, self.geoip_flagged_hosts = {}, {}, set()
        self._inflight, self.doh_queries, self.poison_blocked = {}, 0, 0
        self._sem: asyncio.Semaphore | None = None
        self._sem_loop: asyncio.AbstractEventLoop | None = None
        self.load_disk_cache()

    def apply_mined_vips(self, cf_vip: str, gfe_vip: str) -> None:
        """Hot-swap cached Cloudflare and Google Anycast VIPs in-place so newly mined lowest-RTT edges take effect immediately."""
        self.active_cf_vip, self.active_gfe_vip = cf_vip.strip(), gfe_vip.strip()
        for k, src in list(self.sources.items()):
            if src == "CF_ANYCAST_VIP":
                self.cache[k] = self.active_cf_vip
            elif src == "GFE_ANYCAST_VIP":
                self.cache[k] = self.active_gfe_vip

    def flag_geoip_host(self, host: str) -> None:
        """Flag both the host and its registrable root domain for GeoIP relay so sibling API/CDN subdomains do not hit 403 errors."""
        h = host.strip().lower().rstrip(".")
        if h in ("google.com", "www.google.com", "translate.google.com") or _matches_suffix_list(h, ("bing.com", "msn.com", "akamaized.net", "s-msn.com", "live.com", "microsoft.com", "pinterest.com", "pinimg.com", "qq.com", "gameloop.com")):
            return
        self.geoip_flagged_hosts.add(h)
        parts = h.split(".")
        root = ".".join(parts[-2:]) if len(parts) >= 2 else h
        if root not in ("google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "github.io", "vercel.app", "pages.dev"):
            self.geoip_flagged_hosts.add(root)

    def is_geoip_flagged(self, host: str) -> bool:
        """Check whether CNAME or 403 radar flagged this domain or its parent root so subsequent requests route via a US/EU exit IP."""
        h = host.strip().lower().rstrip(".")
        return any(h == f or h.endswith("." + f) for f in self.geoip_flagged_hosts)

    def load_disk_cache(self) -> None:
        """Skip ephemeral googlevideo and www.google.com entries when loading disk cache so stale regional GGC IPs are never reused."""
        try:
            if self.cache_path is not None and self.cache_path.exists():
                data = json.loads(self.cache_path.read_text(encoding="utf-8"))
                for k, v in data.items():
                    if k != "www.google.com" and not is_youtube_video_edge_host(k) and isinstance(v, str):
                        self.cache[k], self.sources[k] = heal_cloudflare_blocked_ip(v), "MEMORY_CACHE"
        except Exception:
            pass

    def save_disk_cache(self) -> None:
        """Persist verified DNS mappings only when an explicit path is configured so default Ghost Mode leaves zero files on disk."""
        try:
            if self.cache_path is not None:
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                out = {k: v for k, v in self.cache.items() if k != "www.google.com"}
                self.cache_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
        except Exception:
            pass

    def seed_custom_record(self, host: str, ip: str) -> None:
        """Allow deterministic IP injection so unit tests and custom overrides can pin hostnames without network queries."""
        h = host.strip().lower()
        self.cache[h], self.sources[h] = ip.strip(), "CUSTOM_SEED"

    def lookup_cached(self, host: str) -> str | None:
        """Provide synchronous O(1) cache inspection so hot-path callers can check resolved IPs without awaiting coroutines."""
        return self.cache.get(host.strip().lower())

    async def _try_os_dns(self, host: str) -> str | None:
        """Filter OS getaddrinfo answers through is_poisoned_ip so ISP DNS sinkholes never hijack regional CDN resolution."""
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM), timeout=1.2
            )
            for info in infos:
                cand = str(info[4][0])
                if is_poisoned_ip(cand):
                    self.poison_blocked += 1
                else:
                    return heal_cloudflare_blocked_ip(cand)
        except Exception:
            pass
        return None

    async def _query_doh_or_os(self, h: str, prefer_doh: bool = False) -> tuple[str, str]:
        """Pace US/Canada Google DoH queries through a polyphase semaphore and block OS DNS fallback on prefer_doh to prevent Tehran ISP leaks."""
        if h in CLEAN_ANYCAST_FALLBACKS:
            fb = CLEAN_ANYCAST_FALLBACKS[h]
            self.cache[h], self.sources[h] = fb, "CLEAN_FALLBACK"
            return fb, "CLEAN_FALLBACK"
        loop = asyncio.get_running_loop()
        if self._sem is None or self._sem_loop is not loop:
            self._sem, self._sem_loop = asyncio.Semaphore(6), loop
        async with self._sem:
            tasks = [asyncio.create_task(_async_no_sni_doh_query(ip, hdr, pth, h)) for ip, hdr, pth in DOH_SERVERS_NO_SNI]
            try:
                for fut in asyncio.as_completed(tasks):
                    try:
                        doh_ip, cname_flag = await fut
                        if doh_ip:
                            self.doh_queries += 1
                            if cname_flag:
                                self.flag_geoip_host(h)
                            src = "DOH_CNAME_GEOIP" if cname_flag else "DOH_ZERO_SNI"
                            self.cache[h], self.sources[h] = doh_ip, src
                            return doh_ip, src
                    except Exception:
                        continue
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()
        if not prefer_doh:
            os_ip = await self._try_os_dns(h)
            if os_ip:
                self.cache[h], self.sources[h] = os_ip, "OS_DNS"
                return os_ip, "OS_DNS"
        # Never cache GVS_CORE_VIP on googlevideo.com or *.c.youtube.com edge nodes because each edge node requires its own real GVS IP.
        if is_youtube_video_edge_host(h):
            return GVS_CORE_VIP, "GVS_CORE_FALLBACK"
        if _matches_suffix_list(h, GFE_YOUTUBE_SUFFIXES):
            self.cache[h], self.sources[h] = self.active_gfe_vip, "GFE_ANYCAST_VIP"
            return self.active_gfe_vip, "GFE_ANYCAST_VIP"
        return h, "UNRESOLVED"

    async def _resolve_uncached(self, h: str, prefer_doh: bool = False) -> tuple[str, str]:
        """Bypass OS DNS on googlevideo.com when prefer_doh=True so US-relayed YouTube Music streams get US-reachable edge IPs."""
        if _matches_suffix_list(h, CF_PROTECTED_SUFFIXES):
            self.cache[h], self.sources[h] = self.active_cf_vip, "CF_ANYCAST_VIP"
            return self.active_cf_vip, "CF_ANYCAST_VIP"
        if h != "www.google.com" and not is_youtube_video_edge_host(h) and _matches_suffix_list(h, GFE_YOUTUBE_SUFFIXES) and not (prefer_doh and h.endswith(".googlevideo.com")):
            self.cache[h], self.sources[h] = self.active_gfe_vip, "GFE_ANYCAST_VIP"
            return self.active_gfe_vip, "GFE_ANYCAST_VIP"
        if (h == "www.google.com" or is_youtube_video_edge_host(h)) and not prefer_doh:
            os_ip = await self._try_os_dns(h)
            if os_ip:
                self.cache[h], self.sources[h] = os_ip, "OS_DNS"
                return os_ip, "OS_DNS"
        return await self._query_doh_or_os(h, prefer_doh=prefer_doh)

    async def resolve_with_meta(self, host: str, prefer_doh: bool = False) -> tuple[str, str]:
        """Coalesce simultaneous lookups for the same hostname into one in-flight Future to prevent DoH socket exhaustion."""
        h = host.strip().lower()
        tg_v4 = translate_telegram_ipv6(h)
        if tg_v4:
            return tg_v4, "TG_IPV6_TO_V4"
        if h in ("localhost", "127.0.0.1") or h.endswith(".aether.internal") or _is_literal_ip(h):
            return h, "LITERAL"
        if not is_rfc1035_valid_hostname(h):
            return "0.0.0.0", "RFC1035_INVALID"
        if h in self.cache and not (prefer_doh and (is_youtube_video_edge_host(h) or h.endswith(".googlevideo.com")) and self.sources.get(h) in ("OS_DNS", "GFE_ANYCAST_VIP")):
            return self.cache[h], self.sources.get(h, "CACHE")
        if h in self._inflight:
            return await self._inflight[h]
        fut: asyncio.Future[tuple[str, str]] = asyncio.get_running_loop().create_future()
        self._inflight[h] = fut
        try:
            res = await self._resolve_uncached(h, prefer_doh=prefer_doh)
            fut.set_result(res)
            return res
        finally:
            self._inflight.pop(h, None)

    async def resolve(self, host: str) -> str:
        """Provide a simple IP-only wrapper around resolve_with_meta so callers that do not need DNS source telemetry stay concise."""
        ip, _ = await self.resolve_with_meta(host)
        return ip

"""Zero-Redis in-memory HTTP cache (RFC 9110/9111/9211/9875) and LAN dashboard shield to keep control-plane responses fast and private."""

from collections import OrderedDict
from collections.abc import Callable
import hashlib
import time
from typing import Any
from fastapi import FastAPI, Request, Response
from constants import RFC_CACHE_DEFAULT_TTL_SEC, RFC_CACHE_MAX_ENTRIES


class ZeroRedisRfcCache:
    """Bound memory usage with an OrderedDict LRU + TTL store so RFC 9111 caching works on Windows without external Redis daemons."""

    def __init__(self, max_entries: int = RFC_CACHE_MAX_ENTRIES, default_ttl: int = RFC_CACHE_DEFAULT_TTL_SEC) -> None:
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self.store: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.invalidations = 0

    def make_key(self, method: str, path: str, accept_enc: str = "") -> str:
        """Include Accept-Encoding in the RFC 9111 composite key so compressed and uncompressed representations never collide."""
        return f"{method.upper()}:{path}:{accept_enc}"

    def get_entry(self, key: str) -> dict[str, Any] | None:
        """Evict expired entries lazily on read and promote hits to the end of the OrderedDict to maintain strict O(1) LRU ordering."""
        entry = self.store.get(key)
        if not entry:
            self.misses += 1
            return None
        age = int(time.time() - entry["created_at"])
        if age > entry["ttl"]:
            self.store.pop(key, None)
            self.misses += 1
            return None
        self.store.move_to_end(key)
        self.hits += 1
        return {**entry, "age": age}

    def put_entry(
        self, key: str, body: bytes, status: int, media_type: str, group: str, ttl: int | None = None
    ) -> dict[str, Any]:
        """Compute a SHA-256 ETag (RFC 9110) and attach a Cache-Groups label (RFC 9875) so mutations can invalidate related routes."""
        etag = f'"{hashlib.sha256(body).hexdigest()[:24]}"'
        entry = {
            "body": body, "status": status, "media_type": media_type or "application/json",
            "etag": etag, "group": group, "created_at": time.time(), "ttl": ttl or self.default_ttl,
        }
        self.store[key] = entry
        self.store.move_to_end(key)
        while len(self.store) > self.max_entries:
            self.store.popitem(last=False)
        return entry

    def invalidate_group(self, group: str = "*") -> int:
        """Purge matching Cache-Groups on unsafe HTTP mutations (POST/PUT/DELETE) per RFC 9111 Section 4.4 so stale state is never served."""
        keys = [k for k, v in self.store.items() if group == "*" or v.get("group") == group]
        for k in keys:
            self.store.pop(k, None)
        self.invalidations += len(keys)
        return len(keys)


def _build_cached_http_response(entry: dict[str, Any], if_none_match: str, hit: bool) -> Response:
    """Return a zero-body 304 Not Modified when If-None-Match matches the ETag to save bandwidth and prove RFC 9110 compliance."""
    age = int(entry.get("age", 0))
    rem_ttl = max(0, int(entry["ttl"]) - age)
    status_hdr = f'"AetherRAM"; hit; ttl={rem_ttl}' if hit else f'"AetherRAM"; fwd=uri-miss; ttl={rem_ttl}'
    headers = {
        "ETag": entry["etag"],
        "Age": str(age),
        "Cache-Control": f"public, max-age={entry['ttl']}, stale-while-revalidate=30",
        "Cache-Status": status_hdr,
        "Cache-Groups": f'"{entry["group"]}"',
        "Vary": "Accept-Encoding",
    }
    if if_none_match and if_none_match == entry["etag"]:
        return Response(content=b"", status_code=304, headers=headers)
    return Response(content=entry["body"], status_code=entry["status"], headers=headers, media_type=entry["media_type"])


async def _dispatch_rfc_cache(request: Request, call_next: Callable[[Request], Any]) -> Response:
    """Block RFC 1918 LAN peers from reading the port-9090 dashboard and bypass caching on live telemetry/tunnel streams."""
    client_ip = str(request.client.host).removeprefix("::ffff:") if request.client else "127.0.0.1"
    if client_ip.startswith(("192.168.", "10.0.", "172.16.", "172.20.")):
        return Response(content=b"403 Forbidden: Satoshi Ghost Mode (Loopback Only)", status_code=403)
    cache: ZeroRedisRfcCache = request.app.state.rfc_cache
    path = request.url.path
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and not path.startswith("/_aether/"):
        cache.invalidate_group("*")
    if request.method != "GET" or path.startswith(("/_aether/", "/api/live", "/api/diagnostics")):
        return await call_next(request)
    key = cache.make_key(request.method, path, request.headers.get("accept-encoding", ""))
    inm = request.headers.get("if-none-match", "")
    cached = cache.get_entry(key)
    if cached is not None:
        return _build_cached_http_response(cached, inm, hit=True)
    res = await call_next(request)
    if res.status_code == 200:
        body = b"".join([chunk async for chunk in res.body_iterator])
        ctype = res.headers.get("content-type") or res.media_type or "text/html; charset=utf-8"
        entry = cache.put_entry(key, body, res.status_code, ctype, path.strip("/") or "root")
        return _build_cached_http_response({**entry, "age": 0}, inm, hit=False)
    return res


def attach_zero_redis_rfc_cache(app: FastAPI, cache: ZeroRedisRfcCache) -> None:
    """Bind the ZeroRedisRfcCache instance to app.state so both middleware and telemetry routes share hit/miss counters."""
    app.state.rfc_cache = cache
    app.middleware("http")(_dispatch_rfc_cache)

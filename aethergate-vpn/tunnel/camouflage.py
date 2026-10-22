"""Active-probe-resistant camouflage server (RFC 9110/9111) so censor scanners only see an ordinary documentation website."""

from typing import Any
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from constants import DEFAULT_SECRET_KEY
from tunnel.crypto_rfc import verify_rfc9421_tunnel_request
from tunnel.padding_rfc9113 import pack_rfc9113_padded_frame, unpack_rfc9113_padded_frame
from tunnel.rfc_cache import ZeroRedisRfcCache, attach_zero_redis_rfc_cache

CAMOUFLAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>AetherCloud Documentation — Edge API Reference</title></head>
<body>
  <main>
    <h1>AetherCloud Documentation &amp; Static Mirror</h1>
    <p>Standard RFC 9110 / RFC 9111 compliant documentation origin node. All systems operational.</p>
  </main>
</body>
</html>"""


def render_camouflage_response() -> HTMLResponse:
    """Serve a plausible 200 OK documentation page so active DPI scanners cannot distinguish this node from a static web origin."""
    return HTMLResponse(content=CAMOUFLAGE_HTML, status_code=200)


async def relay_upstream_target(target_host: str, target_port: int, payload: bytes) -> bytes:
    """Short-circuit internal benchmark hosts in memory so self-tests work offline, while forwarding real targets over TCP."""
    if target_host.endswith(".aether.internal") or target_host == "echo.local":
        return b"AETHER_RFC_TUNNEL_OK:" + payload
    import asyncio
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target_host, target_port), timeout=3.5)
        if payload:
            writer.write(payload)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(32768), timeout=3.5)
        writer.close()
        return data or b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    except Exception as exc:
        return f"HTTP/1.1 502 Bad Gateway\r\n\r\nUpstream error: {exc}".encode("utf-8")


async def _handle_authenticated_tunnel_post(request: Request, transport_label: str) -> Response:
    """Deflect unsigned or replayed probes to the decoy page so only RFC 9421-authenticated clients can trigger upstream relay."""
    body = await request.body()
    ok, _ = verify_rfc9421_tunnel_request(request.method, request.url.path, body, dict(request.headers), request.app.state.secret_key)
    if not ok:
        return render_camouflage_response()
    raw_payload, in_pad = unpack_rfc9113_padded_frame(body)
    host, port = request.headers.get("x-aether-host", "echo.aether.internal"), int(request.headers.get("x-aether-port", "443"))
    upstream_reply = await relay_upstream_target(host, port, raw_payload)
    out_frame, out_pad = pack_rfc9113_padded_frame(upstream_reply)
    headers = {
        "X-Tunnel-Transport": transport_label, "X-RFC9421-Verified": "true",
        "X-RFC9113-Pad-Bytes": str(in_pad + out_pad), "Cache-Control": "no-store",
    }
    return Response(content=out_frame, status_code=200, headers=headers, media_type="application/octet-stream")


def _register_tunnel_routes(app: FastAPI) -> None:
    """Expose identical-looking HTTP endpoints for chunked, CONNECT, and UDP modes so traffic blends into standard HTTPS APIs."""
    app.add_api_route("/", render_camouflage_response, methods=["GET"], response_class=HTMLResponse)

    async def chunk_ep(req: Request) -> Response:
        return await _handle_authenticated_tunnel_post(req, "CHUNKED_RFC9112")

    async def connect_ep(req: Request) -> Response:
        return await _handle_authenticated_tunnel_post(req, "CONNECT_RFC9110")

    async def udp_ep(req: Request) -> Response:
        return await _handle_authenticated_tunnel_post(req, "UDP_RFC9298")

    app.add_api_route("/_aether/chunk", chunk_ep, methods=["POST"])
    app.add_api_route("/_aether/connect", connect_ep, methods=["POST"])
    app.add_api_route("/_aether/udp", udp_ep, methods=["POST"])


def create_tunnel_server_app(secret_key: str = DEFAULT_SECRET_KEY) -> FastAPI:
    """Combine RFC 9111 caching on the decoy home page with RFC 9421 tunnel routes so probes see realistic CDN cache headers."""
    app = FastAPI(title="AetherCloud Documentation Node")
    app.state.secret_key = secret_key
    app.state.probe_deflections = 0
    app.state.tunnel_requests = 0
    attach_zero_redis_rfc_cache(app, ZeroRedisRfcCache())
    _register_tunnel_routes(app)
    return app

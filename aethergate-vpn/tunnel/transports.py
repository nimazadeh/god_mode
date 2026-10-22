"""Multi-RFC client dispatcher (RFC 8441/9110/9112/9298) to encapsulate, pad, and sign outbound frames against active DPI."""

import asyncio
import contextlib
import time
from typing import Any
import httpx
from httpx import ASGITransport
from constants import DEFAULT_MAX_PAD_BYTES, DEFAULT_MIN_PAD_BYTES, DEFAULT_SECRET_KEY
from tunnel.crypto_rfc import sign_rfc9421_tunnel_request
from tunnel.padding_rfc9113 import pack_rfc9113_padded_frame, unpack_rfc9113_padded_frame


def _endpoint_for_mode(transport_mode: str) -> str:
    """Route CONNECT_RFC9110 and CHUNKED/WS modes to distinct URI paths so the server can apply transport-specific framing."""
    if transport_mode == "CONNECT_RFC9110":
        return "/_aether/connect"
    return "/_aether/chunk"


class TunnelClientDispatcher:
    """Wrap outbound payloads in RFC 9113 random padding and RFC 9421 HMAC signatures to defeat active DPI and traffic analysis."""

    def __init__(
        self,
        server_url: str = "http://127.0.0.1:8443",
        secret_key: str = DEFAULT_SECRET_KEY,
        asgi_app: Any | None = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.secret_key = secret_key
        self.asgi_app = asgi_app
        self.bytes_tx = 0
        self.bytes_rx = 0
        self.pad_bytes_total = 0
        self.packets_relayed = 0
        self.last_rtt_ms = 0.0
        self._client: httpx.AsyncClient | None = None
        self._client_base_url: str = ""
        self._client_loop: asyncio.AbstractEventLoop | None = None

    def _make_transport(self) -> ASGITransport | None:
        """Use in-process ASGITransport when targeting the local loopback node so self-tests need zero external sockets."""
        if self.asgi_app is not None and ("127.0.0.1:8443" in self.server_url or "localhost:8443" in self.server_url):
            return ASGITransport(app=self.asgi_app)
        return None

    async def _get_or_create_client(self) -> httpx.AsyncClient:
        """Reuse one persistent AsyncClient per event loop with trust_env=False per official HTTPX docs to pool sockets and prevent OS proxy loopback."""
        current_loop = asyncio.get_running_loop()
        target_base = self.server_url.rstrip("/")
        if (
            self._client is None
            or self._client.is_closed
            or self._client_base_url != target_base
            or self._client_loop is not current_loop
        ):
            if self._client is not None and not self._client.is_closed and self._client_loop is current_loop:
                with contextlib.suppress(Exception):
                    await self._client.aclose()
            self._client = httpx.AsyncClient(
                transport=self._make_transport(),
                base_url=target_base,
                timeout=6.0,
                trust_env=False,
                limits=httpx.Limits(max_keepalive_connections=16, max_connections=64, keepalive_expiry=30.0),
            )
            self._client_base_url = target_base
            self._client_loop = current_loop
        return self._client

    async def aclose(self) -> None:
        """Close the persistent HTTPX connection pool cleanly during shutdown so underlying sockets release immediately."""
        if self._client is not None and not self._client.is_closed:
            with contextlib.suppress(Exception):
                await self._client.aclose()
        self._client = None

    async def _send_signed_frame(
        self, path: str, target_host: str, target_port: int, payload: bytes, min_pad: int, max_pad: int
    ) -> tuple[httpx.Response, int, float]:
        """Pad the payload before signing so the RFC 9530 Repr-Digest protects both the ciphertext and the random padding bytes."""
        frame, in_pad = pack_rfc9113_padded_frame(payload, min_pad=min_pad, max_pad=max_pad)
        headers = sign_rfc9421_tunnel_request("POST", path, frame, self.secret_key)
        headers["X-Aether-Host"] = target_host
        headers["X-Aether-Port"] = str(target_port)
        t0 = time.perf_counter()
        client = await self._get_or_create_client()
        res = await client.post(path, content=frame, headers=headers)
        rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return res, in_pad, rtt_ms

    async def relay_payload(
        self, transport_mode: str, target_host: str, target_port: int, payload: bytes, padding_enabled: bool = True
    ) -> dict[str, Any]:
        """Verify X-RFC9421-Verified on the response before unpacking so decoy camouflage pages are never mistaken for tunnel data."""
        lo, hi = (DEFAULT_MIN_PAD_BYTES, DEFAULT_MAX_PAD_BYTES) if padding_enabled else (0, 0)
        res, in_pad, rtt_ms = await self._send_signed_frame(_endpoint_for_mode(transport_mode), target_host, target_port, payload, lo, hi)
        if res.headers.get("x-rfc9421-verified") != "true":
            return {"ok": False, "transport": transport_mode, "rfc9421_verified": False, "pad_bytes": 0, "response_bytes": b""}
        reply_payload, out_pad = unpack_rfc9113_padded_frame(res.content)
        total_pad = in_pad + out_pad
        self.bytes_tx += len(payload) + in_pad
        self.bytes_rx += len(reply_payload) + out_pad
        self.pad_bytes_total += total_pad
        self.packets_relayed += 1
        self.last_rtt_ms = rtt_ms
        return {"ok": True, "transport": transport_mode, "rfc9421_verified": True, "pad_bytes": total_pad, "rtt_ms": rtt_ms, "response_bytes": reply_payload}

    async def relay_udp_datagram(
        self, target_host: str, target_port: int, datagram: bytes
    ) -> dict[str, Any]:
        """Encapsulate UDP datagrams over HTTP per RFC 9298 (MASQUE) so DNS/QUIC datagrams traverse TCP-only firewalls."""
        res, in_pad, rtt_ms = await self._send_signed_frame(
            "/_aether/udp", target_host, target_port, datagram, DEFAULT_MIN_PAD_BYTES, DEFAULT_MAX_PAD_BYTES
        )
        if res.headers.get("x-rfc9421-verified") != "true":
            return {"ok": False, "rfc": "RFC 9298", "datagram_reply": b""}
        reply_dg, out_pad = unpack_rfc9113_padded_frame(res.content)
        self.pad_bytes_total += in_pad + out_pad
        self.packets_relayed += 1
        return {"ok": True, "rfc": "RFC 9298", "rtt_ms": rtt_ms, "datagram_reply": reply_dg}

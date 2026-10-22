"""Tests for Ticket 26: Mobile LAN Wi-Fi Coalescing & Telegram Parallel Multi-Relay Turbo (v8.2)."""

import asyncio
import pytest
from tunnel.dpi_desync import _configure_client_socket, _send_and_verify_server_hello
from tunnel.geoip_relay import GeoIPRelayPool


class _DummyWriter:
    """Mock StreamWriter for verifying loopback vs LAN Wi-Fi socket configuration."""

    def __init__(self, peer_ip: str) -> None:
        self.peer_ip = peer_ip
        self.written = b""
        self.closed = False

    def get_extra_info(self, name: str) -> object:
        if name == "peername":
            return (self.peer_ip, 54321)
        return None

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def test_configure_client_socket_distinguishes_pc_loopback_from_mobile_lan() -> None:
    """Verify PC loopback returns False (is_lan=False) while 192.168.1.x returns True (is_lan=True)."""
    pc_w = _DummyWriter("127.0.0.1")
    mobile_w = _DummyWriter("192.168.1.45")
    assert _configure_client_socket(pc_w) is False  # type: ignore[arg-type]
    assert _configure_client_socket(mobile_w) is True  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_telegram_mtproto_bypasses_server_hello_wait_immediately() -> None:
    """Verify binary Telegram MTProto packets to 149.154.* bypass the 2.5s ServerHello read wait."""
    rem_r = asyncio.StreamReader()
    rem_w = _DummyWriter("172.171.169.205")
    pool = GeoIPRelayPool()
    mtproto_packet = b"\xef" + (b"\xaa" * 104)  # Non-TLS MTProto Obfuscated2 frame (first byte != 0x16)
    _, _, peek, mode = await _send_and_verify_server_hello(
        rem_r, rem_w, mtproto_packet, True, "149.154.167.223", 443, "socks5://172.171.169.205:3000", pool, True  # type: ignore[arg-type]
    )
    assert mode == "DIRECT_PASSTHROUGH"
    assert peek == b""
    assert rem_w.written == mtproto_packet

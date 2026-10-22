"""Tests for Ticket 25: Auto-Connect on Boot, Telegram IPv6-to-IPv4 DC Translator & Bing/Pinterest Offload."""

from pathlib import Path
import pytest
from main import _build_aether_state
from tunnel.doh_resolver import DoHResolver, translate_telegram_ipv6
from tunnel.smart_router import SmartRouter


def test_auto_connect_on_boot_starts_connected() -> None:
    """Verify AetherGate state boots in connected=True state by default."""
    state = _build_aether_state(bind_inbound_port=0)
    assert state["connected"] is True


@pytest.mark.asyncio
async def test_telegram_ipv6_dc_translates_to_ipv4_and_routes_to_geoip_relay(tmp_path: Path) -> None:
    """Verify Telegram mobile IPv6 DC literals map to IPv4 DCs and route via GEOIP_RELAY."""
    router = SmartRouter(rules_path=tmp_path / "rules.json")
    resolver = DoHResolver(cache_path=tmp_path / "dns.json")
    cases = [
        ("2001:b28:f23d:f001::a", "149.154.175.50"),
        ("2001:67c:4e8:f002::a", "149.154.167.50"),
        ("2001:67c:4e8:f004::b", "149.154.167.91"),
        ("2001:b28:f23f:f005::a", "91.108.56.100"),
    ]
    for ipv6_host, expected_v4 in cases:
        assert router.decide(ipv6_host) == "GEOIP_RELAY"
        assert translate_telegram_ipv6(ipv6_host) == expected_v4
        ip, src = await resolver.resolve_with_meta(ipv6_host)
        assert ip == expected_v4
        assert src == "TG_IPV6_TO_V4"


def test_bing_and_pinterest_stay_on_direct_tunnel_not_geoip_relay(tmp_path: Path) -> None:
    """Verify bing.com, pinterest.com, and gameloop.com are never flagged into GEOIP_RELAY."""
    resolver = DoHResolver(cache_path=tmp_path / "dns.json")
    for host in ("www.bing.com", "www.pinterest.com", "i.pinimg.com", "unifiedaccess.gameloop.com"):
        resolver.flag_geoip_host(host)
        assert resolver.is_geoip_flagged(host) is False

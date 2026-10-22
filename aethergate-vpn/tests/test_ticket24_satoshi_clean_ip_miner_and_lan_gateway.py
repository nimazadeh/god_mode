"""Tests for Ticket 24: Satoshi Clean-IP Proof-of-Reachability Miner & Sovereign LAN Gateway."""

import asyncio
from pathlib import Path
from playwright.async_api import async_playwright
import pytest
from tunnel.doh_resolver import DoHResolver
from tunnel.satoshi_engine import CleanIPMiner, SovereignLanGateway, is_allowed_client_peer, probe_tls_server_hello


async def _mock_tls_server_hello(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    """Respond with a valid 0x16 0x03 0x03 TLS ServerHello record header if client sends 0x16."""
    try:
        data = await asyncio.wait_for(r.read(4096), timeout=1.5)
        if data and data[0] == 0x16:
            w.write(b"\x16\x03\x03\x00\x04DONE"), await w.drain()
    except Exception:
        pass
    finally:
        w.close()


async def _mock_http_block_page(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    """Respond with plain HTTP 403 block page instead of TLS ServerHello."""
    try:
        await asyncio.wait_for(r.read(1024), timeout=1.0)
        w.write(b"HTTP/1.1 403 Forbidden\r\n\r\n"), await w.drain()
    except Exception:
        pass
    finally:
        w.close()


@pytest.mark.asyncio
async def test_clean_ip_miner_verifies_tls_server_hello_and_hot_swaps_doh_vips(tmp_path: Path) -> None:
    """Verify CleanIPMiner requires genuine 0x16 0x03 ServerHello proof and hot-swaps DoHResolver VIPs."""
    tls_srv = await asyncio.start_server(_mock_tls_server_hello, "127.0.0.1", 0)
    bad_srv = await asyncio.start_server(_mock_http_block_page, "127.0.0.1", 0)
    tls_port = int(tls_srv.sockets[0].getsockname()[1])
    bad_port = int(bad_srv.sockets[0].getsockname()[1])
    try:
        ok_rtt = await probe_tls_server_hello("127.0.0.1", "arena.ai", port=tls_port)
        bad_rtt = await probe_tls_server_hello("127.0.0.1", "arena.ai", port=bad_port)
        assert ok_rtt is not None and ok_rtt >= 0.0
        assert bad_rtt is None

        store = tmp_path / "mined_clean_ips.json"
        miner = CleanIPMiner(store_path=store)
        resolver = DoHResolver(cache_path=tmp_path / "dns.json")
        res = await miner.mine_clean_ips(
            doh_resolver=resolver, cf_cands=("127.0.0.1",), gfe_cands=("127.0.0.1",), port=tls_port
        )
        assert res["best_cf_ip"] == "127.0.0.1"
        assert res["best_gfe_ip"] == "127.0.0.1"
        assert store.exists()
        assert await resolver.resolve("arena.ai") == "127.0.0.1"
        assert await resolver.resolve("www.youtube.com") == "127.0.0.1"
    finally:
        tls_srv.close(), bad_srv.close()
        await tls_srv.wait_closed(), await bad_srv.wait_closed()


def test_sovereign_lan_gateway_rfc1918_acl() -> None:
    """Verify SovereignLanGateway allows loopback always, RFC 1918 LAN when enabled, and blocks public IPs."""
    assert is_allowed_client_peer("127.0.0.1", False) is True
    assert is_allowed_client_peer("::1", False) is True
    assert is_allowed_client_peer("192.168.1.50", True) is True
    assert is_allowed_client_peer("10.0.0.15", True) is True
    assert is_allowed_client_peer("172.20.0.8", True) is True
    assert is_allowed_client_peer("192.168.1.50", False) is False
    assert is_allowed_client_peer("8.8.8.8", True) is False
    assert is_allowed_client_peer("1.1.1.1", True) is False

    gw = SovereignLanGateway(port=10808, enabled=True)
    assert gw.register_peer("192.168.1.77") is True
    assert gw.lan_clients_served == 1
    gw.enabled = False
    assert gw.register_peer("192.168.1.77") is False
    assert gw.register_peer("127.0.0.1") is True


@pytest.mark.asyncio
async def test_satoshi_dashboard_ui_badges_and_controls_e2e_browser() -> None:
    """Verify Satoshi v8.0 badges and controls in Chromium and capture screenshot."""
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1440, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        await page.click(".advanced-drawer summary")
        lan_txt = await page.locator("#lan-gateway-badge").inner_text()
        pool_txt = await page.locator("#prewarm-pool-badge").inner_text()
        assert "LAN NODE:" in lan_txt
        assert "0-RTT POOL:" in pool_txt
        await page.click("#btn-toggle-lan")
        await page.wait_for_timeout(300)
        lan_off = await page.locator("#lan-gateway-badge").inner_text()
        assert "OFF" in lan_off
        await page.click("#btn-toggle-lan")
        await page.click(".advanced-drawer summary")
        await page.wait_for_timeout(300)
        Path("/home/user/screenshots").mkdir(parents=True, exist_ok=True)
        await page.screenshot(path="/home/user/screenshots/aethergate_v8_satoshi_edition.png")
        await browser.close()
        assert errors == []

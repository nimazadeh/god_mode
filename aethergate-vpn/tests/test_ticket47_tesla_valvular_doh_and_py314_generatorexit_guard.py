"""Tests for Ticket 53 (v11.4): Nikola Tesla Valvular DoH (Zero Astara/Tehran DNS Leak), .bat Title Fix & Python 3.14 GeneratorExit Guard."""

import asyncio
from pathlib import Path
import pytest
from constants import AETHERGATE_VERSION, DOH_SERVERS_NO_SNI
import tunnel.doh_resolver as doh_mod
from tunnel.inbound_proxy import UnifiedInboundProxy
from tunnel.smart_router import SmartRouter

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_version_v11_4_and_bat_files_have_no_unescaped_ampersand_live_bug() -> None:
    """Verify v11.4+ .bat launchers do not contain unescaped '& Live' in title commands that trigger cmd.exe 'Live is not recognized'."""
    assert AETHERGATE_VERSION.startswith("v11.")
    for bat_name in ("run-windows.bat", "start_aethergate.bat"):
        text = (ROOT_DIR / bat_name).read_text(encoding="utf-8")
        assert "v11." in text
        assert "& Live" not in text, f"{bat_name} must not have unescaped '& Live' in title command"


@pytest.mark.asyncio
async def test_tesla_valvular_doh_eliminates_astara_and_irancell_os_dns_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify DOH_SERVERS_NO_SNI excludes 1.1.1.1 (Astara) and DoHResolver never falls back to OS DNS (Irancell Tehran) when prefer_doh=True."""
    doh_ips = [entry[0] for entry in DOH_SERVERS_NO_SNI]
    assert "1.1.1.1" not in doh_ips, "1.1.1.1 routes to Cloudflare Astara/Baku from Iran and must not be in DOH_SERVERS_NO_SNI"
    assert "1.0.0.1" not in doh_ips
    assert doh_ips == ["8.8.8.8", "8.8.4.4"]

    os_dns_called = False

    async def _forbidden_os_dns(self: doh_mod.DoHResolver, host: str) -> str | None:
        nonlocal os_dns_called
        os_dns_called = True
        return "2a01:5ec0:dfff:5::2"

    async def _failing_doh(ip: str, host_hdr: str, path: str, qname: str, *_args: object, **_kwargs: object) -> tuple[str | None, bool]:
        return None, False

    monkeypatch.setattr(doh_mod.DoHResolver, "_try_os_dns", _forbidden_os_dns)
    monkeypatch.setattr(doh_mod, "_async_no_sni_doh_query", _failing_doh)

    resolver = doh_mod.DoHResolver()
    ip, src = await resolver.resolve_with_meta("sub123.browserleaks.org", prefer_doh=True)
    assert os_dns_called is False, "OS DNS (Irancell Tehran) must NEVER be queried when prefer_doh=True"
    assert src == "UNRESOLVED"


@pytest.mark.asyncio
async def test_python314_generatorexit_and_pending_client_task_guard() -> None:
    """Verify UnifiedInboundProxy tracks active client tasks and handles GeneratorExit without raising RuntimeError."""
    router = SmartRouter()

    class _DummyDispatcher:
        bytes_tx = 0
        bytes_rx = 0
        packets_relayed = 0

    proxy = UnifiedInboundProxy(dispatcher=_DummyDispatcher(), router=router)
    assert hasattr(proxy, "_active_client_tasks")

    closed_sync = False

    class _FakeWriter:
        def get_extra_info(self, name: str) -> tuple[str, int]:
            return ("127.0.0.1", 54321)

        def close(self) -> None:
            nonlocal closed_sync
            closed_sync = True

        async def wait_closed(self) -> None:
            await asyncio.sleep(0.01)

    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    coro = proxy._handle_client(reader, writer)  # type: ignore[arg-type]
    # Advance coroutine to its first await point (awaiting first_byte from reader), then close() it to inject GeneratorExit like Python 3.14 GC.
    try:
        coro.send(None)
    except StopIteration:
        pass
    # Closing the suspended coroutine throws GeneratorExit into _handle_client; it must NOT raise RuntimeError: coroutine ignored GeneratorExit.
    coro.close()
    assert closed_sync is True

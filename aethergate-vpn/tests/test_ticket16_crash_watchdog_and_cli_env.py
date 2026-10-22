"""Tests for Ticket 16: Crash-Proof Windows Proxy Watchdog and CLI Developer Environment Injector."""

from tunnel.os_proxy import SystemProxyAdapter


def test_cli_developer_env_injector_sets_and_clears_proxy_vars() -> None:
    """Verify enabling the tunnel injects HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY for CLI tools."""
    adapter = SystemProxyAdapter("127.0.0.1:10808")
    st_on = adapter.set_enabled(True)
    assert st_on["enabled"] is True
    assert st_on["cli_env_active"] is True
    assert adapter.cli_env["HTTP_PROXY"] == "http://127.0.0.1:10808"
    assert adapter.cli_env["HTTPS_PROXY"] == "http://127.0.0.1:10808"
    assert adapter.cli_env["ALL_PROXY"] == "socks5h://127.0.0.1:10808"

    st_off = adapter.set_enabled(False)
    assert st_off["enabled"] is False
    assert st_off["cli_env_active"] is False
    assert adapter.cli_env == {}


def test_crash_watchdog_emergency_disable_resets_proxy_on_close_event() -> None:
    """Verify Windows Console CTRL_CLOSE_EVENT (event=2) triggers emergency_disable() and turns off proxy."""
    adapter = SystemProxyAdapter("127.0.0.1:10808")
    adapter.set_enabled(True)
    assert adapter.enabled is True
    assert adapter.watchdog_registered is True

    # Simulate Windows kernel32 SetConsoleCtrlHandler firing CTRL_CLOSE_EVENT (2)
    handled = adapter._on_console_ctrl_event(2)
    assert handled is True
    assert adapter.enabled is False
    assert adapter.cli_env == {}

"""Windows WinINet system proxy adapter, CLI environment injector, and crash watchdog so closing the terminal never breaks internet access."""

import atexit
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
from constants import INBOUND_PROXY_PORT

# Exclude loopback, RFC 1918 LAN, and .ir domains at the OS proxy level so domestic traffic bypasses the proxy socket entirely.
WIN_PROXY_OVERRIDE = "localhost;127.*;192.168.*;10.*;*.ir;<local>"


def sanitize_chromium_preferences_json(raw_json: str) -> str:
    """Rewrite Chromium intl.accept_languages to en-US,en and lock webrtc.ip_handling_policy to disable_non_proxied_udp."""
    try:
        data = json.loads(raw_json)
        intl = data.setdefault("intl", {})
        if isinstance(intl, dict):
            intl["accept_languages"] = "en-US,en"
            intl["selected_languages"] = "en-US,en"
        webrtc = data.setdefault("webrtc", {})
        if isinstance(webrtc, dict):
            webrtc["ip_handling_policy"] = "disable_non_proxied_udp"
            webrtc["multiple_routes_enabled"] = False
            webrtc["nonproxied_udp_enabled"] = False
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return raw_json


def build_windows_webrtc_policy_commands() -> tuple[str, ...]:
    """Build Windows Registry policy and firewall commands that block non-proxied WebRTC STUN UDP so real ISP IPs never leak."""
    return (
        'reg add "HKCU\\Software\\Policies\\Google\\Chrome" /v WebRtcIPHandling /t REG_SZ /d disable_non_proxied_udp /f',
        'reg add "HKLM\\Software\\Policies\\Google\\Chrome" /v WebRtcIPHandling /t REG_SZ /d disable_non_proxied_udp /f',
        'reg add "HKLM\\Software\\Policies\\Google\\Chrome\\ForcedLanguages" /v 1 /t REG_SZ /d en-US /f',
        'reg add "HKCU\\Software\\Policies\\BraveSoftware\\Brave" /v WebRtcIPHandling /t REG_SZ /d disable_non_proxied_udp /f',
        'reg add "HKCU\\Software\\Policies\\Microsoft\\Edge" /v WebRtcLocalhostIpHandling /t REG_SZ /d disable_non_proxied_udp /f',
        'netsh advfirewall firewall add rule name="AetherGate Block WebRTC STUN UDP" dir=out action=block protocol=UDP remoteport=3478,5349,19302-19309',
    )


def _notify_wininet_refresh() -> None:
    """Broadcast WinINet options 39/37 and flush OS DNS so Chrome/Edge apply proxy changes immediately without restarting."""
    try:
        wininet = getattr(ctypes, "windll", None) and ctypes.windll.wininet
        if wininet:
            wininet.InternetSetOptionW(0, 39, 0, 0)
            wininet.InternetSetOptionW(0, 37, 0, 0)
        if sys.platform == "win32":
            subprocess.run(["ipconfig", "/flushdns"], creationflags=0x08000000, timeout=2.0, check=False)
    except Exception:
        pass


class SystemProxyAdapter:
    """Synchronize Windows Registry proxy settings, developer CLI env vars, and console close handlers to prevent orphaned proxy states."""

    def __init__(self, proxy_endpoint: str = f"127.0.0.1:{INBOUND_PROXY_PORT}") -> None:
        self.proxy_endpoint = proxy_endpoint
        self.enabled = False
        self.platform = sys.platform
        self.cli_env: dict[str, str] = {}
        self.watchdog_registered = False
        self._win_ctrl_cb: Any = None
        self.register_crash_watchdog()

    def register_crash_watchdog(self) -> None:
        """Hook both Python atexit and Windows SetConsoleCtrlHandler so clicking 'X' on cmd.exe still cleans up HKCU ProxyEnable."""
        if self.watchdog_registered:
            return
        atexit.register(self.emergency_disable)
        if self.platform == "win32":
            try:
                handler_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)
                # Keep a strong reference to _win_ctrl_cb on self so Python's garbage collector never frees the C callback pointer.
                self._win_ctrl_cb = handler_type(self._on_console_ctrl_event)
                ctypes.windll.kernel32.SetConsoleCtrlHandler(self._win_ctrl_cb, 1)
            except Exception:
                pass
        self.watchdog_registered = True

    def _on_console_ctrl_event(self, event: int) -> bool:
        """Intercept CTRL_C, CTRL_CLOSE, LOGOFF, and SHUTDOWN kernel signals to disable the OS proxy before Windows kills the process."""
        if event in (0, 1, 2, 5, 6):
            self.emergency_disable()
        return True

    def emergency_disable(self) -> None:
        """Force ProxyEnable=0 during abnormal teardown so the user's browser never gets stuck pointing at a closed localhost port."""
        if self.enabled or self.cli_env:
            self.set_enabled(False)

    def _sync_cli_env(self, enable: bool) -> None:
        """Use socks5h:// for ALL_PROXY so CLI tools (git, curl, pip) resolve DNS through our anti-poisoning DoH engine."""
        http_url, socks_url = f"http://{self.proxy_endpoint}", f"socks5h://{self.proxy_endpoint}"
        self.cli_env = (
            {"HTTP_PROXY": http_url, "HTTPS_PROXY": http_url, "ALL_PROXY": socks_url, "NO_PROXY": "localhost,127.0.0.1,.ir"}
            if enable else {}
        )
        if self.platform == "win32":
            self._apply_windows_cli_env(enable)

    def _apply_windows_cli_env(self, enable: bool) -> None:
        """Persist proxy env vars in HKCU\\Environment on connect and delete them on disconnect so new terminals inherit tunnel access."""
        try:
            import winreg  # type: ignore
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
                for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
                    if enable and k in self.cli_env:
                        winreg.SetValueEx(key, k, 0, winreg.REG_SZ, self.cli_env[k])
                    else:
                        try:
                            winreg.DeleteValue(key, k)
                        except OSError:
                            pass
        except Exception:
            pass

    def set_enabled(self, enable: bool) -> dict[str, Any]:
        """Update both browser WinINet settings and CLI environment variables atomically so all apps share the same tunnel state."""
        self.enabled = bool(enable)
        self._sync_cli_env(self.enabled)
        if self.platform == "win32":
            self._apply_windows_registry(self.enabled)
        return self.status()

    def _apply_windows_registry(self, enable: bool) -> None:
        """Write to HKCU instead of HKLM so AetherGate runs with standard user privileges without requiring Administrator UAC prompts."""
        try:
            import winreg  # type: ignore
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
                if enable:
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.proxy_endpoint)
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, WIN_PROXY_OVERRIDE)
            self._apply_windows_browser_locale_cloak(enable)
            _notify_wininet_refresh()
        except Exception:
            pass

    def _apply_windows_browser_locale_cloak(self, enable: bool) -> None:
        """Enforce HKCU ForcedLanguages=en-US and patch Chromium Preferences so browsers never leak fa-IR when a Persian keyboard is active."""
        try:
            import winreg  # type: ignore
            for pol_root, sub_name in (
                (r"Software\Policies\Google\Chrome", "ForcedLanguages"),
                (r"Software\Policies\BraveSoftware\Brave", "ForcedLanguages"),
                (r"Software\Policies\Microsoft\Edge", "DefinePreferredLanguages"),
            ):
                if enable:
                    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, pol_root) as pk:
                        winreg.SetValueEx(pk, "ApplicationLocaleValue", 0, winreg.REG_SZ, "en-US")
                        winreg.SetValueEx(pk, "DnsOverHttpsMode", 0, winreg.REG_SZ, "off")
                        winreg.SetValueEx(pk, "WebRtcIPHandling", 0, winreg.REG_SZ, "disable_non_proxied_udp")
                        winreg.SetValueEx(pk, "WebRtcLocalhostIpHandling", 0, winreg.REG_SZ, "disable_non_proxied_udp")
                        winreg.SetValueEx(pk, "WebRtcUdpPortRange", 0, winreg.REG_SZ, "10000-10000")
                    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{pol_root}\\{sub_name}") as fk:
                        winreg.SetValueEx(fk, "1", 0, winreg.REG_SZ, "en-US")
            local_app = Path(os.environ.get("LOCALAPPDATA", ""))
            for browser_rel in ("Google/Chrome/User Data", "Microsoft/Edge/User Data", "BraveSoftware/Brave-Browser/User Data"):
                ud = local_app / browser_rel
                for pref_file in (ud.glob("*/Preferences") if ud.is_dir() else ()):
                    raw = pref_file.read_text(encoding="utf-8", errors="ignore")
                    if "fa" in raw or "disable_non_proxied_udp" not in raw:
                        pref_file.write_text(sanitize_chromium_preferences_json(raw), encoding="utf-8")
        except Exception:
            pass

    def status(self) -> dict[str, Any]:
        """Expose watchdog and CLI env telemetry so the dashboard can verify OS-level protection is active."""
        return {
            "enabled": self.enabled,
            "cli_env_active": bool(self.cli_env),
            "watchdog_active": self.watchdog_registered,
            "endpoint": self.proxy_endpoint,
            "proxy_endpoint": self.proxy_endpoint,
            "platform": self.platform,
        }

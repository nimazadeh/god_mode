@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
title AetherGate VPN v11.14 - Google AI Studio 403 Immunity & CF-Worker Bypass Guard
cd /d "%~dp0"

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python 3.11+ was not found in your Windows PATH.
    pause
    exit /b 1
)

netsh advfirewall firewall add rule name="AetherGate LAN Node" dir=in action=allow protocol=TCP localport=10808 >nul 2>nul
netsh advfirewall firewall add rule name="AetherGate Block WebRTC STUN UDP" dir=out action=block protocol=UDP remoteport=3478,5349,19302-19309 >nul 2>nul
reg add "HKCU\Software\Policies\Google\Chrome" /v WebRtcIPHandling /t REG_SZ /d disable_non_proxied_udp /f >nul 2>nul
reg add "HKLM\Software\Policies\Google\Chrome" /v WebRtcIPHandling /t REG_SZ /d disable_non_proxied_udp /f >nul 2>nul
reg add "HKCU\Software\Policies\BraveSoftware\Brave" /v WebRtcIPHandling /t REG_SZ /d disable_non_proxied_udp /f >nul 2>nul
reg add "HKCU\Software\Policies\Microsoft\Edge" /v WebRtcLocalhostIpHandling /t REG_SZ /d disable_non_proxied_udp /f >nul 2>nul

if not exist "venv\Scripts\python.exe" (
    echo [1/2] Creating isolated Python virtual environment...
    python -m venv venv
)

start "" "http://127.0.0.1:9090/"
if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" main.py
) else (
    python main.py
)
pause

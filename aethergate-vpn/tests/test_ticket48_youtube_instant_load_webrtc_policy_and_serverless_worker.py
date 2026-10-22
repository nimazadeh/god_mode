"""Ticket 54 (v11.5) TDD verification for YouTube Instant Load (Zero Companion Split-Brain & Non-ECS GVS DoH), Windows Registry/Firewall WebRTC Leak Guard, and Personal Serverless Cloudflare Worker Relay."""

import json
from pathlib import Path
import pytest

from constants import AETHERGATE_VERSION, CF_ANYCAST_VIP, DEFAULT_PERSONAL_CF_WORKER, GFE_ANYCAST_VIP, GVS_CORE_VIP
from main import _build_aether_state
from tunnel.doh_resolver import should_send_us_ecs_subnet
from tunnel.geoip_relay import GeoIPRelayPool, get_relay_country_meta
from tunnel.os_proxy import build_windows_webrtc_policy_commands, sanitize_chromium_preferences_json
from tunnel.serverless_worker import (
    build_cloudflare_worker_script,
    build_worker_upgrade_headers,
    decode_rfc6455_server_frames,
    encode_rfc6455_client_frame,
)
from tunnel.smart_router import SmartRouter, is_youtube_zero_captcha_host


def test_version_v11_5_and_youtube_companion_hosts_stay_on_direct_tunnel_in_strict_mode() -> None:
    """Verify v11.5 keeps all YouTube player/BotGuard/signaler companion hosts on direct TUNNEL even when strict_privacy_partitioning=True."""
    assert AETHERGATE_VERSION in ("v11.5", "v11.6", "v11.7", "v11.8", "v11.9", "v11.10", "v11.11", "v11.12", "v11.13")
    st = _build_aether_state()
    rtr: SmartRouter = st["router"]
    assert rtr.strict_privacy_partitioning is True

    # All YouTube player, attestation (BotGuard), signaler, and media hosts must route via direct TUNNEL so tokens never split-brain across IPs.
    for yt_host in (
        "www.youtube.com",
        "m.youtube.com",
        "youtu.be",
        "youtube-nocookie.com",
        "youtubei.googleapis.com",
        "jnn-pa.googleapis.com",
        "waa-pa.clients6.google.com",
        "signaler-pa.clients6.google.com",
        "ogads-pa.clients6.google.com",
        "ogs.google.com",
        "apis.google.com",
        "consent.youtube.com",
        "consent.google.com",
        "i.ytimg.com",
        "s.ytimg.com",
        "yt3.ggpht.com",
        "yt3.googleusercontent.com",
        "rr1---sn-4g5ednsd.googlevideo.com",
    ):
        assert is_youtube_zero_captcha_host(yt_host) is True, f"{yt_host} must be recognized as a zero-captcha direct YouTube host"
        assert rtr.decide(yt_host) == "TUNNEL", f"{yt_host} must stay on direct TUNNEL in strict mode so YouTube never hangs"

    # Search engines and AI Studio must still route via GEOIP_RELAY in strict mode.
    for relay_host in ("google.com", "www.google.com", "aistudio.google.com", "alkalimakersuite-pa.clients6.google.com"):
        assert rtr.decide(relay_host) == "GEOIP_RELAY"

    # Direct googlevideo.com lookups (prefer_doh=False) must NOT send a US ECS subnet so Google DNS returns regional low-RTT GGC nodes.
    assert should_send_us_ecs_subnet("dns.google", "rr1---sn-4g5ednsd.googlevideo.com", prefer_doh=False) is False
    assert should_send_us_ecs_subnet("dns.google", "rr1---sn-4g5ednsd.googlevideo.com", prefer_doh=True) is True
    assert should_send_us_ecs_subnet("dns.google", "test.bash.ws", prefer_doh=True) is True


def test_windows_webrtc_registry_policy_and_preferences_udp_killswitch() -> None:
    """Verify Chromium Preferences JSON, Windows Registry policies, and .bat launchers block non-proxied WebRTC STUN UDP leaks."""
    raw_prefs = json.dumps({"intl": {"accept_languages": "en-US,en"}})
    patched_raw = sanitize_chromium_preferences_json(raw_prefs)
    patched = json.loads(patched_raw)
    assert patched["intl"]["accept_languages"] == "en-US,en"
    assert patched["webrtc"]["ip_handling_policy"] == "disable_non_proxied_udp"
    assert patched["webrtc"]["multiple_routes_enabled"] is False
    assert patched["webrtc"]["nonproxied_udp_enabled"] is False

    cmds = build_windows_webrtc_policy_commands()
    assert any("WebRtcIPHandling" in c and "disable_non_proxied_udp" in c for c in cmds)
    assert any("WebRtcLocalhostIpHandling" in c and "disable_non_proxied_udp" in c for c in cmds)
    assert any("19302-19309" in c and "action=block" in c for c in cmds)

    for bat_name in ("run-windows.bat", "start_aethergate.bat"):
        bat_text = (Path(__file__).resolve().parent.parent / bat_name).read_text(encoding="utf-8")
        assert any(v in bat_text for v in ("v11.5", "v11.6", "v11.7", "v11.8", "v11.9", "v11.10", "v11.11", "v11.12", "v11.13"))
        assert "disable_non_proxied_udp" in bat_text
        assert "19302-19309" in bat_text


def test_personal_serverless_cloudflare_worker_generator_and_headers() -> None:
    """Verify the serverless Cloudflare Worker script uses cloudflare:sockets connect(), binaryType=arraybuffer, and RFC 6455 framing."""
    assert DEFAULT_PERSONAL_CF_WORKER == "frosty-bush-aethergate.nimazadeh963.workers.dev"
    pool = GeoIPRelayPool()
    assert pool.personal_worker_host == "frosty-bush-aethergate.nimazadeh963.workers.dev"
    meta = get_relay_country_meta(f"cfworker://{DEFAULT_PERSONAL_CF_WORKER}:443")
    assert meta["country_code"] == "CF"
    assert "Personal Worker" in meta["location"]

    script = build_cloudflare_worker_script("my-secret-tesla-key")
    assert 'import { connect } from "cloudflare:sockets";' in script
    assert 'serverWs.binaryType = "arraybuffer";' in script
    assert "x-aether-token" in script.lower()
    assert "x-aether-target" in script.lower()
    assert "my-secret-tesla-key" in script

    worker_file = Path(__file__).resolve().parent.parent / "serverless" / "cloudflare_worker.js"
    assert worker_file.exists()
    assert 'serverWs.binaryType = "arraybuffer";' in worker_file.read_text(encoding="utf-8")

    hdrs = build_worker_upgrade_headers(DEFAULT_PERSONAL_CF_WORKER, "104.236.69.55", 443, "my-secret-tesla-key")
    assert b"Host: frosty-bush-aethergate.nimazadeh963.workers.dev\r\n" in hdrs
    assert b"X-Aether-Token: my-secret-tesla-key\r\n" in hdrs
    assert b"X-Aether-Target: 104.236.69.55:443\r\n" in hdrs
    assert b"Upgrade: websocket\r\n" in hdrs

    # Verify RFC 6455 client masking and server unmasked binary frame decoding
    client_frame = encode_rfc6455_client_frame(b"hello-tesla")
    assert client_frame[0] == 0x82 and (client_frame[1] & 0x80) == 0x80
    server_frame = b"\x82\x05world\x88\x00"
    chunks, rem, closed = decode_rfc6455_server_frames(server_frame)
    assert chunks == [b"world"] and rem == b"" and closed is True

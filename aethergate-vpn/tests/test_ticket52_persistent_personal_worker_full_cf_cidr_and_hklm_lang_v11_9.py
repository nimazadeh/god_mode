"""Ticket 58 (v11.9) TDD verification for Permanent Personal Cloudflare Worker Lock, Full Cloudflare CIDR NAT64 Coverage, Zero-Error Worker Promise Guards, and HKLM ForcedLanguages."""

from pathlib import Path
import pytest

from constants import AETHERGATE_VERSION, DEFAULT_PERSONAL_CF_WORKER
from main import _build_aether_state
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.os_proxy import build_windows_webrtc_policy_commands
from tunnel.serverless_worker import (
    build_cloudflare_worker_script,
    build_worker_upgrade_headers,
    is_cloudflare_anycast_ip,
)


def test_version_v11_9_mtalk_block_and_full_cloudflare_cidr_nat64() -> None:
    """Verify v11.9 blocks mtalk.google.com:5228 at edge and translates all Cloudflare IPv4 CIDRs via RFC 6052 NAT64."""
    assert AETHERGATE_VERSION in ("v11.9", "v11.10", "v11.11", "v11.12", "v11.13")
    state = _build_aether_state()
    assert state["router"].decide("mtalk.google.com") == "BLOCK"

    for cf_ip in (
        "104.18.14.206",
        "104.22.10.5",
        "104.23.240.72",
        "162.158.93.34",
        "172.64.66.1",
        "172.65.1.1",
        "172.66.1.1",
        "172.68.20.76",
        "172.69.113.91",
        "172.70.245.4",
        "172.71.140.76",
        "198.41.128.10",
        "141.101.64.10",
        "108.162.192.10",
        "173.245.48.10",
    ):
        assert is_cloudflare_anycast_ip(cf_ip) is True, f"{cf_ip} must be recognized as Cloudflare Anycast IP"
        hdr = build_worker_upgrade_headers(DEFAULT_PERSONAL_CF_WORKER, cf_ip, 443).decode("latin1")
        assert "X-Aether-Nat64: 1\r\n" in hdr
        assert "X-Aether-Target: [2602:fc59:b0:64::" in hdr


def test_demote_relay_preserves_personal_worker_and_worker_js_guards_promises() -> None:
    """Verify demote_relay never permanently kills personal_worker_verified and cloudflare_worker.js catches socket promises."""
    pool = GeoIPRelayPool()
    assert pool.personal_worker_verified is True
    pool.demote_relay(f"cfworker://{DEFAULT_PERSONAL_CF_WORKER}:443")
    assert pool.personal_worker_verified is True, "demote_relay must not permanently disable personal_worker_verified"

    script = build_cloudflare_worker_script()
    js_disk = (Path(__file__).resolve().parent.parent / "serverless" / "cloudflare_worker.js").read_text(encoding="utf-8")
    for content in (script, js_disk):
        assert ".closed.catch(" in content
        assert ".opened.catch(" in content

    cmds = "\n".join(build_windows_webrtc_policy_commands())
    assert "HKLM\\Software\\Policies\\Google\\Chrome\\ForcedLanguages" in cmds

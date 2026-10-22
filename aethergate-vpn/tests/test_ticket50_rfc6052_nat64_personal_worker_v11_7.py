"""Ticket 56 (v11.7) TDD verification for IETF RFC 6052 NAT64 IPv6 Synthesis, 100% Personal Cloudflare Worker Priority (Google + Cloudflare + Telegram), and Live Binary TLS Passthrough."""

import ssl
import pytest

from constants import AETHERGATE_VERSION, CF_ANYCAST_VIP, DEFAULT_PERSONAL_CF_WORKER, GFE_ANYCAST_VIP
from tunnel.geoip_relay import GeoIPRelayPool
from tunnel.satoshi_engine import create_unverified_tls_client_context
from tunnel.serverless_worker import (
    NAT64_US_FREMONT_PREFIX,
    build_cloudflare_worker_script,
    build_worker_upgrade_headers,
    ipv4_to_rfc6052_nat64,
)


def test_version_v11_7_and_rfc6052_nat64_ipv6_synthesis() -> None:
    """Verify IETF RFC 6052 Section 2.2 embeds IPv4 octets into [2602:fc59:b0:64::xxxx:yyyy] for Cloudflare Anycast targets."""
    assert AETHERGATE_VERSION in ("v11.7", "v11.8", "v11.9", "v11.10", "v11.11", "v11.12", "v11.13")
    assert NAT64_US_FREMONT_PREFIX == "2602:fc59:b0:64::"
    assert ipv4_to_rfc6052_nat64("104.18.14.206") == "[2602:fc59:b0:64::6812:0ece]"
    assert ipv4_to_rfc6052_nat64("172.64.155.209") == "[2602:fc59:b0:64::ac40:9bd1]"
    assert ipv4_to_rfc6052_nat64("[2602:fc59:b0:64::6812:0ece]") == "[2602:fc59:b0:64::6812:0ece]"

    cf_hdrs = build_worker_upgrade_headers(DEFAULT_PERSONAL_CF_WORKER, CF_ANYCAST_VIP, 443)
    assert b"X-Aether-Target: [2602:fc59:b0:64::6812:0ece]:443\r\n" in cf_hdrs
    assert b"X-Aether-Nat64: 1\r\n" in cf_hdrs

    gfe_hdrs = build_worker_upgrade_headers(DEFAULT_PERSONAL_CF_WORKER, GFE_ANYCAST_VIP, 443)
    assert b"X-Aether-Target: 216.239.38.120:443\r\n" in gfe_hdrs

    script = build_cloudflare_worker_script()
    assert "ipv4ToNat64" in script
    assert "2602:fc59:b0:64::" in script


@pytest.mark.asyncio
async def test_live_personal_worker_opens_both_google_and_cloudflare_targets() -> None:
    """Verify GeoIPRelayPool routes both Google (216.239.38.120) and Cloudflare (104.18.14.206 via RFC 6052 NAT64) through cfworker://."""
    pool = GeoIPRelayPool()
    assert pool.personal_worker_verified is True

    # 1. Google AI Studio (216.239.38.120:443) via personal Cloudflare Worker
    r_gfe, w_gfe, via_gfe = await pool.open_relayed_connection(GFE_ANYCAST_VIP, 443)
    try:
        assert via_gfe == f"cfworker://{DEFAULT_PERSONAL_CF_WORKER}:443"
        ctx = create_unverified_tls_client_context()
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        sobj = ctx.wrap_bio(inc, out, server_hostname="aistudio.google.com")
        try:
            sobj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        w_gfe.write(out.read())
        await w_gfe.drain()
        sh_gfe = await r_gfe.read(4096)
        assert len(sh_gfe) > 100 and sh_gfe[:3] == b"\x16\x03\x03"
    finally:
        w_gfe.close()

    # 2. Cloudflare Anycast (104.18.14.206:443 -> [2602:fc59:b0:64::6812:0ece]:443) via personal Cloudflare Worker
    r_cf, w_cf, via_cf = await pool.open_relayed_connection(CF_ANYCAST_VIP, 443)
    try:
        assert via_cf == f"cfworker://{DEFAULT_PERSONAL_CF_WORKER}:443"
    finally:
        w_cf.close()

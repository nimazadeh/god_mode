"""Tests for Ticket 34: Universal Zero-Hardcode 403/451 Immune System & Exact-Host Media Exemption."""

import pytest
from constants import GEOIP_RELAY_SUFFIXES
from main import _build_aether_state
from tunnel.doh_resolver import DoHResolver
from tunnel.inbound_proxy import UnifiedInboundProxy, detect_access_denied_signature
from tunnel.smart_router import SmartRouter, is_direct_jet_media_host


def test_exact_host_media_exemption_unlocks_notebook_google_com_and_unknown_subdomains() -> None:
    """Verify notebook.google.com is NOT hardcoded, yet routes to GEOIP_RELAY while www.google.com stays TUNNEL."""
    assert "notebook.google.com" not in GEOIP_RELAY_SUFFIXES
    assert is_direct_jet_media_host("notebook.google.com") is False
    assert is_direct_jet_media_host("labs.google.com") is False
    assert is_direct_jet_media_host("future-ai-2028.googleapis.com") is False
    assert is_direct_jet_media_host("www.google.com") is True
    assert is_direct_jet_media_host("translate.google.com") is True
    assert is_direct_jet_media_host("clients4.google.com") is True

    st = _build_aether_state()
    rtr: SmartRouter = st["router"]
    assert rtr.strict_privacy_partitioning is True
    assert rtr.decide("www.google.com") == "GEOIP_RELAY"
    rtr.strict_privacy_partitioning = False
    assert rtr.decide("www.google.com") == "TUNNEL"
    assert rtr.decide("notebook.google.com") == "GEOIP_RELAY"
    rtr.strict_privacy_partitioning = False
    for any_host in ("notebook.google.com", "notebook.google", "labs.google.com", "unknown-saas-2027.io"):
        assert rtr.decide(any_host) == "GEOIP_RELAY", f"{any_host} must route via GEOIP_RELAY without hardcoding"
    assert rtr.decide("www.google.com") == "TUNNEL"
    assert rtr.decide("translate.google.com") == "TUNNEL"


def test_universal_403_451_and_geo_redirect_signature_detector() -> None:
    """Verify Google 403 permission error, HTTP 451, and 302 Geo-Block redirects are detected universally."""
    google_403 = (
        b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
        b"<b>403.</b> <ins>That\xe2\x80\x99s an error.</ins>"
        b"<p>Your client does not have permission to get URL <code>/</code> from this server.</p>"
    )
    geo_redirect = b"HTTP/1.1 302 Found\r\nLocation: https://example.com/region-unavailable\r\n\r\n"
    legal_451 = b"HTTP/1.1 451 Unavailable For Legal Reasons\r\n\r\n"
    normal_200 = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>"

    assert detect_access_denied_signature(google_403) is True
    assert detect_access_denied_signature(geo_redirect) is True
    assert detect_access_denied_signature(legal_451) is True
    assert detect_access_denied_signature(normal_200) is False


@pytest.mark.asyncio
async def test_selective_mode_zero_hardcode_auto_promotion_on_notebook_google_com(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify even with location_cloak_all=False, unknown 403 hosts (notebook.google.com & third-party) auto-promote."""
    st = _build_aether_state()
    proxy: UnifiedInboundProxy = st["inbound_proxy"]
    proxy.router.location_cloak_all = False
    proxy.router.strict_privacy_partitioning = False

    assert proxy._should_probe_unknown_https("notebook.google.com", "216.239.38.120", 443) is True
    assert proxy._should_probe_unknown_https("portal.unknown-chip-vendor-2027.com", "151.101.1.69", 443) is True
    assert proxy._should_probe_unknown_https("www.google.com", "216.239.38.120", 443) is False

    async def _fake_probe(host: str, ip: str, port: int = 443) -> bool:
        return host in ("notebook.google.com", "portal.unknown-chip-vendor-2027.com")

    monkeypatch.setattr("tunnel.inbound_proxy.probe_https_access_denied", _fake_probe)

    d1 = await proxy._evaluate_auto_geoip(1, "notebook.google.com", "216.239.38.120", 443, "TUNNEL")
    d2 = await proxy._evaluate_auto_geoip(2, "portal.unknown-chip-vendor-2027.com", "151.101.1.69", 443, "TUNNEL")
    assert d1 == "GEOIP_RELAY"
    assert d2 == "GEOIP_RELAY"
    assert proxy.router.decide("notebook.google.com") == "GEOIP_RELAY"
    assert proxy.router.decide("api.unknown-chip-vendor-2027.com") == "GEOIP_RELAY"
    assert proxy.router.decide("www.google.com") == "TUNNEL"


def test_multi_tenant_umbrella_isolation_in_flag_geoip_host() -> None:
    """Verify flagging notebook.google.com does not flag www.google.com, while corporate domains flag their root."""
    doh = DoHResolver()
    doh.flag_geoip_host("notebook.google.com")
    assert doh.is_geoip_flagged("notebook.google.com") is True
    assert doh.is_geoip_flagged("www.google.com") is False
    assert doh.is_geoip_flagged("translate.google.com") is False

    doh.flag_geoip_host("portal.sanctioned-enterprise-2027.org")
    assert doh.is_geoip_flagged("portal.sanctioned-enterprise-2027.org") is True
    assert doh.is_geoip_flagged("api.sanctioned-enterprise-2027.org") is True

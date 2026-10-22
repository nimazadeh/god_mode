"""Tests for Ticket 31: YouTube Music Split-Unlock, mylocation.org + Wi-Fi BSSID Shield & Live RFC 9460/9849 Telemetry."""

import pytest
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import DoHResolver
from tunnel.smart_router import SmartRouter


def test_youtube_music_split_unlock_and_jet_speed_googlevideo() -> None:
    """Verify music.youtube.com routes via US GEOIP_RELAY while youtube.com and googlevideo.com stay on TUNNEL."""
    rtr = SmartRouter()
    assert rtr.decide("music.youtube.com") == "GEOIP_RELAY"
    assert rtr.decide("www.youtube.com") == "TUNNEL"
    assert rtr.decide("m.youtube.com") == "TUNNEL"
    assert rtr.decide("rr2---sn-4g5lznly.googlevideo.com") == "TUNNEL"


def test_mylocation_org_and_wifi_bssid_triangulation_blocker() -> None:
    """Verify mylocation.org and 30+ GeoIP sites use US GEOIP_RELAY while browser Wi-Fi BSSID services are BLOCKED."""
    rtr = SmartRouter()
    for loc_host in (
        "mylocation.org", "www.mylocation.org", "iplocation.net", "whatismyip.com",
        "ip2location.com", "ipgeolocation.io", "dnsleaktest.com", "check-host.net",
    ):
        assert rtr.decide(loc_host) == "GEOIP_RELAY", f"{loc_host} must route via US GEOIP_RELAY"

    for bssid_host in ("location.services.mozilla.com", "inference.location.live.net"):
        assert rtr.decide(bssid_host) == "BLOCK", f"{bssid_host} must be BLOCKED to prevent Wi-Fi BSSID location leaks"


@pytest.mark.asyncio
async def test_live_rfc9460_ech_0xfe0d_visible_in_diagnostic_report() -> None:
    """Verify DiagnosticLogger._probe_rfc9460_ech surfaces live RFC 9460/9849 ECH proof in report_text."""
    diag = DiagnosticLogger()
    chk = await diag._probe_rfc9460_ech("arena.ai")
    assert chk["name"] == "RFC9460_ECH_0XFE0D"
    assert chk["ok"] is True
    assert "ECH 0xfe0d" in chk["tls_http"]
    assert "X25519" in chk["tls_http"]
    assert "cloudflare-ech.com" in chk["tls_http"]
    diag.last_checks = [chk]
    report = diag.build_text_report()
    assert "RFC9460_ECH_0XFE0D" in report
    assert "RFC9849_ECH" in report

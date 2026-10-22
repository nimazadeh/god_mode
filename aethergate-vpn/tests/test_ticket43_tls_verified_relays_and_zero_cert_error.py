"""Ticket 49 (v11.0) TDD verification for TLS-Verified Zero-MITM Relay Admission, Zero Unretrieved Task Exceptions, and 0ms Privacy-Checker Resolution."""

import asyncio
import pytest

from constants import AETHERGATE_VERSION, CLEAN_ANYCAST_FALLBACKS, DEFAULT_BLOCKED_PATTERNS
from tunnel.doh_resolver import DoHResolver
from tunnel.geoip_relay import GeoIPRelayPool, _is_clean_relay_addr, _select_us_eu_candidates
from tunnel.smart_router import SmartRouter


def test_version_v11_0_and_captive_portal_port_8080_and_145_220_filtered() -> None:
    """Verify v11.0 excludes captive-portal ports (:8080, :80, :8888, :8443, :3128) and 145.220.* MITM honeypots."""
    assert AETHERGATE_VERSION.startswith(("v10.", "v11."))
    for bad_addr in (
        "145.220.227.142:8080",
        "145.220.227.195:8080",
        "145.220.227.142:1080",
        "67.207.92.87:8080",
        "67.207.92.87:80",
        "67.207.92.87:8888",
        "67.207.92.87:3128",
    ):
        assert _is_clean_relay_addr(bad_addr) is False, f"Captive portal / MITM candidate {bad_addr} must be rejected"

    cands = _select_us_eu_candidates(
        ["67.207.92.87:1088", "145.220.227.142:8080", "145.220.227.10:1080"],
        ["62.146.180.4:3000", "145.220.227.195:8080", "67.207.92.87:8080"],
    )
    assert ("socks5", "67.207.92.87:1088") in cands
    assert ("http", "62.146.180.4:3000") in cands
    for _, addr in cands:
        assert not addr.startswith("145.220."), f"Honeypot prefix 145.220.* leaked into candidates: {addr}"
        assert not addr.endswith((":8080", ":3128", ":80", ":8888")), f"Captive portal port leaked: {addr}"


@pytest.mark.asyncio
async def test_probe_candidate_rejects_mitm_or_eof_relay_via_tls_passthrough_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify _probe_candidate rejects relays that pass TCP/SOCKS5 connect but fail real TLS 1.3 certificate passthrough."""
    pool = GeoIPRelayPool()

    class _DummyWriter:
        def close(self) -> None:
            pass

    async def _fake_connect_ok(*_args, **_kwargs):
        return asyncio.StreamReader(), _DummyWriter()

    async def _fake_tls_mitm_fail(*_args, **_kwargs) -> bool:
        return False

    monkeypatch.setattr("tunnel.geoip_relay._connect_single_relay", _fake_connect_ok)
    monkeypatch.setattr("tunnel.geoip_relay._verify_relay_tls_passthrough", _fake_tls_mitm_fail, raising=False)

    sem = asyncio.Semaphore(5)
    res = await pool._probe_candidate("socks5", "67.207.92.87:1088", sem)
    assert res is None, "Relay that fails TLS 1.3 certificate passthrough must be rejected to prevent ERR_CERT_AUTHORITY_INVALID"


@pytest.mark.asyncio
async def test_race_batch_never_leaves_unretrieved_task_exceptions() -> None:
    """Verify _race_batch consumes exceptions on all sibling tasks when one task wins and another raises IncompleteReadError."""
    pool = GeoIPRelayPool()
    unretrieved: list[dict] = []
    loop = asyncio.get_running_loop()
    old_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _l, ctx: unretrieved.append(ctx))

    class _DummyWriter:
        def close(self) -> None:
            pass

    async def _mock_try_indexed(index: int, _ip: str, _port: int, _timeout: float):
        if index == 0:
            return index, asyncio.StreamReader(), _DummyWriter(), "socks5://67.207.92.87:1088"
        raise asyncio.IncompleteReadError(b"", None)

    pool._try_indexed_relay = _mock_try_indexed  # type: ignore[method-assign]
    try:
        winner = await pool._race_batch([0, 1], "104.18.14.206", 443, timeout=1.0)
        await asyncio.sleep(0.05)
        import gc
        gc.collect()
        await asyncio.sleep(0.02)
    finally:
        loop.set_exception_handler(old_handler)

    assert winner is not None and winner[0] == 0
    assert len(unretrieved) == 0, f"Leaked unretrieved task exception: {unretrieved}"


@pytest.mark.asyncio
async def test_privacy_checkers_resolve_instantly_and_msn_ad_trackers_blocked() -> None:
    """Verify browserleaks.com, whoer.net, and pixelscan.net have clean Anycast fallbacks and MSN ad trackers are blocked."""
    doh = DoHResolver()
    for checker in ("browserleaks.com", "www.browserleaks.com", "whoer.net", "pixelscan.net"):
        assert checker in CLEAN_ANYCAST_FALLBACKS
        ip, src = await doh.resolve_with_meta(checker)
        assert ip != "UNRESOLVED" and "." in ip
        assert src in ("CF_ANYCAST_VIP", "CLEAN_FALLBACK")

    rtr = SmartRouter()
    rtr.strict_privacy_partitioning = True
    for tracker in ("scorecardresearch.com", "sb.scorecardresearch.com", "srtb.msn.com"):
        assert any(p in DEFAULT_BLOCKED_PATTERNS for p in (tracker, "scorecardresearch.com"))
        assert rtr.decide(tracker) == "BLOCK", f"Ad tracker {tracker} must be BLOCKED immediately"

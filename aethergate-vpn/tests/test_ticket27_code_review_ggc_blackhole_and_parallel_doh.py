"""Tests for Ticket 27/28: Anti-Error-1034 Cloudflare 104.18.* Lock & RFC 9110 §9.3.6 GGC 0ms Fast-Fail."""

import json
from pathlib import Path
import pytest
from constants import CF_ANYCAST_VIP, CF_MINER_CANDIDATES
from tunnel.diag_logger import DiagnosticLogger
from tunnel.doh_resolver import is_blackholed_ggc
from tunnel.dpi_desync import _failover_and_replay
from tunnel.satoshi_engine import CleanIPMiner


def test_cloudflare_miner_candidates_prevent_error_1034_and_purge_stale_104_19(tmp_path: Path) -> None:
    """Verify CF_MINER_CANDIDATES only includes 104.18.* IPs and load_persisted purges 104.19.192.29."""
    for ip in CF_MINER_CANDIDATES:
        assert ip.startswith("104.18."), f"Non-104.18 IP {ip} causes Cloudflare Error 1034 on arena.ai"

    store = tmp_path / "mined_clean_ips.json"
    store.write_text(json.dumps({"best_cf_ip": "104.19.192.29", "best_cf_rtt_ms": 420.0}), encoding="utf-8")
    miner = CleanIPMiner(store_path=store)
    assert miner.best_cf_ip == CF_ANYCAST_VIP == "104.18.14.206"


def test_is_blackholed_ggc_identifies_caucasus_sn_qxau5_nodes() -> None:
    """Verify blackholed Caucasus GGC nodes (sn-qxau5, 62.212.*, 94.20.*) are flagged for 0ms 502 Fast-Fail."""
    assert is_blackholed_ggc("rr1---sn-qxau5-btqy.googlevideo.com", "62.212.242.13") is True
    assert is_blackholed_ggc("rr3---sn-qxau5-btqr.googlevideo.com", "94.20.252.174") is True
    assert is_blackholed_ggc("r1---sn-4g5lznly.googlevideo.com", "173.194.16.198") is False


def test_diag_logger_promote_route_encapsulation() -> None:
    """Verify DiagnosticLogger.promote_route updates route cleanly without private attribute access."""
    diag = DiagnosticLogger()
    cid = diag.start_conn("HTTP_CONNECT", "example.com", 443, "TUNNEL")
    diag.promote_route(cid, "GEOIP_RELAY")
    assert diag._routes[cid] == "GEOIP_RELAY"


@pytest.mark.asyncio
async def test_failover_and_replay_fast_fails_blackholed_ggc() -> None:
    """Verify _failover_and_replay immediately raises TimeoutError on 62.212.* so ExoPlayer switches to fallback."""
    with pytest.raises(TimeoutError, match="GGC_BLACKHOLE_FASTFAIL"):
        await _failover_and_replay(
            "62.212.242.13", b"HELLO", False, "62.212.242.13", 443, "62.212.242.13", None, False
        )

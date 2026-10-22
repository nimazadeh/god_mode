"""Tests for Ticket 44 (v10.5): 2026 Frontier Cryptography (RFC 10024 X25519MLKEM768), PETS 2026 DAITA v2 Ephemeral Defense, NDSS 2025/2026 Anti-RTTdiff Scheduler, and FOCI 2026 Iran Border DPI Radar."""

import struct
from fastapi.testclient import TestClient
from constants import (
    AETHERGATE_VERSION,
    IRAN_DPI_NTE1_TTL_RANGE,
    IRAN_DPI_NTL1_TTL_RANGE,
    RFC10024_CLIENT_SHARE_LEN,
    RFC10024_GROUP_X25519MLKEM768,
    RFC10024_SERVER_SHARE_LEN,
    RFC10024_SHARED_SECRET_LEN,
)
from main import create_control_app
from tunnel.dpi_desync import shred_tls_sni_daita_ephemeral
from tunnel.frontier_2026 import (
    audit_frontier_2026_capabilities,
    classify_iran_border_dpi_anomaly,
    combine_rfc10024_hybrid_shared_secret,
    compute_rayleigh_front_schedule,
    evaluate_cross_layer_rtt_diff,
    generate_rfc10024_x25519mlkem768_client_share,
    inspect_post_quantum_key_share,
    sample_daita_v2_ephemeral_machine,
    verify_fips203_encapsulation_key,
)
from tunnel.ja4_shield import compute_ja4_fingerprint, reassemble_tls_handshake_body


def _build_pq_client_hello(sni: str = "arena.ai", group_id: int = RFC10024_GROUP_X25519MLKEM768) -> bytes:
    """Construct a valid TLS 1.3 ClientHello carrying SNI, supported_groups, and an RFC 10024 X25519MLKEM768 key_share."""
    sni_bytes = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_ext = struct.pack("!HH", 0x0000, len(sni_entry) + 2) + struct.pack("!H", len(sni_entry)) + sni_entry

    sup_groups_payload = struct.pack("!HHH", 4, group_id, 0x001D)
    sup_groups_ext = struct.pack("!HH", 0x000A, len(sup_groups_payload)) + sup_groups_payload

    sup_ver_ext = struct.pack("!HHBHH", 0x002B, 5, 4, 0x0304, 0x0303)

    pq_share = generate_rfc10024_x25519mlkem768_client_share(seed=b"ticket44-deterministic-seed-2026")
    key_share_ext = pq_share["tls_extension_bytes"]

    exts = sni_ext + sup_groups_ext + sup_ver_ext + key_share_ext
    body_core = (
        b"\x03\x03"
        + (b"\x11" * 32)
        + b"\x00"
        + struct.pack("!HHH", 4, 0x1301, 0x1302)
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    hs_msg = b"\x01" + len(body_core).to_bytes(3, "big") + body_core
    return b"\x16\x03\x01" + struct.pack("!H", len(hs_msg)) + hs_msg


def test_rfc10024_x25519mlkem768_hybrid_key_share_and_fips203_modulus_check() -> None:
    """Verify RFC 10024 (August 2026) X25519MLKEM768 (0x11EC) client share layout (1184B ML-KEM-768 || 32B X25519 = 1216B) and FIPS 203 check."""
    assert AETHERGATE_VERSION.startswith(("v10.", "v11."))
    assert RFC10024_GROUP_X25519MLKEM768 == 0x11EC
    assert RFC10024_CLIENT_SHARE_LEN == 1216
    assert RFC10024_SERVER_SHARE_LEN == 1120
    assert RFC10024_SHARED_SECRET_LEN == 64

    share = generate_rfc10024_x25519mlkem768_client_share(seed=b"rfc10024-seed-vector")
    assert share["group_id"] == 0x11EC
    assert share["group_name"] == "X25519MLKEM768"
    assert share["mlkem768_ek_len"] == 1184
    assert share["x25519_pk_len"] == 32
    assert share["client_share_len"] == 1216
    assert len(share["client_share_bytes"]) == 1216
    assert share["fips203_valid"] is True
    assert verify_fips203_encapsulation_key(share["client_share_bytes"][:1184]) is True
    assert verify_fips203_encapsulation_key(b"\xff" * 1184) is False

    # Verify RFC 10024 Section 4.3 shared secret concatenation order (ML-KEM first, X25519 second for FIPS SP 800-56Cr2 compliance).
    mlkem_secret = b"\xaa" * 32
    x25519_secret = b"\xbb" * 32
    combined = combine_rfc10024_hybrid_shared_secret(mlkem_secret, x25519_secret)
    assert combined["valid"] is True
    assert combined["shared_secret_len"] == 64
    assert combined["raw_shared_secret"][:32] == mlkem_secret
    assert combined["raw_shared_secret"][32:] == x25519_secret
    assert len(combined["hkdf_handshake_secret_hex"]) == 64

    # All-zero X25519 shared secret must be rejected per RFC 10024 Section 4.3 & RFC 9846 Section 7.4.2.
    bad_combined = combine_rfc10024_hybrid_shared_secret(mlkem_secret, b"\x00" * 32)
    assert bad_combined["valid"] is False


def test_ja4_shield_and_pq_inspector_detect_rfc10024_x25519mlkem768() -> None:
    """Verify JA4 fingerprinter and PQ inspector identify RFC 10024 X25519MLKEM768 (0x11EC) and natural multi-packet size."""
    hello = _build_pq_client_hello("arena.ai", RFC10024_GROUP_X25519MLKEM768)
    assert len(hello) > 1250
    pq_info = inspect_post_quantum_key_share(hello)
    assert pq_info["pq_resistant"] is True
    assert pq_info["pq_hybrid_group"] == "X25519MLKEM768"
    assert pq_info["group_code"] == "0x11ec"
    assert pq_info["key_share_len"] == 1216

    ja4_meta = compute_ja4_fingerprint(hello)
    assert ja4_meta["pq_resistant"] is True
    assert ja4_meta["pq_hybrid_group"] == "X25519MLKEM768"


def test_pets2026_daita_v2_ephemeral_state_machine_and_rayleigh_front_shredder() -> None:
    """Verify PETS 2026 DAITA v2 ephemeral state machine generates distinct record boundaries per connection while preserving JA4."""
    m1 = sample_daita_v2_ephemeral_machine(b"conn-seed-alpha")
    m2 = sample_daita_v2_ephemeral_machine(b"conn-seed-beta")
    assert m1["machine_id"] != m2["machine_id"]
    assert 1.4 <= m1["rayleigh_sigma"] <= 3.8
    assert 32 <= m1["padding_budget_bytes"] <= 192

    schedule = compute_rayleigh_front_schedule(m1, step_count=6)
    assert len(schedule) == 6
    timestamps = [t for t, _ in schedule]
    assert timestamps == sorted(timestamps)

    hello = _build_pq_client_hello("www.youtube.com")
    orig_ja4 = compute_ja4_fingerprint(hello)["ja4"]
    recs_a, meta_a = shred_tls_sni_daita_ephemeral(hello, connection_seed=b"session-1")
    recs_b, meta_b = shred_tls_sni_daita_ephemeral(hello, connection_seed=b"session-2")
    assert len(recs_a) >= 3 and len(recs_b) >= 3
    assert meta_a["machine_id"] != meta_b["machine_id"]
    reassembled = reassemble_tls_handshake_body(b"".join(recs_a))
    assert reassembled == hello[5:]
    assert compute_ja4_fingerprint(b"".join(recs_a))["ja4"] == orig_ja4


def test_ndss2025_cross_layer_rtt_diff_and_foci2026_iran_dpi_radar() -> None:
    """Verify NDSS 2025/2026 Anti-RTTdiff scheduler math and FOCI 2026 Iran NTL1/NTE1 TTL injector & pre-shutdown detector."""
    # High RTT discrepancy on unmultiplexed local-DNS flow should flag elevated risk and compute pacing interval.
    exposed = evaluate_cross_layer_rtt_diff(transport_rtt_ms=25.0, app_rtt_ms=195.0, multiplexed_streams=1, dns_via_tunnel=False)
    defended = evaluate_cross_layer_rtt_diff(transport_rtt_ms=25.0, app_rtt_ms=195.0, multiplexed_streams=8, dns_via_tunnel=True)
    assert exposed["rtt_diff_ms"] == 170.0
    assert exposed["susceptibility_score"] > defended["susceptibility_score"]
    assert defended["effective_detection_recall"] <= 0.08
    assert defended["pacing_interval_ms"] > 0.0

    # FOCI 2026 Figure 2: NTL1 (TTL 53-55) and NTE1 (TTL 186-188) and Scan-2 Pre-Shutdown anomaly.
    assert IRAN_DPI_NTL1_TTL_RANGE == (53, 55)
    assert IRAN_DPI_NTE1_TTL_RANGE == (186, 188)
    ntl1 = classify_iran_border_dpi_anomaly(
        payload=b"<html><title>NTL1</title><iframe src='http://10.10.34.36/?type=InvalidKeyword&policy=MainPolicy'>",
        observed_ttl=54,
    )
    assert ntl1["injector_id"] == "NTL1"
    assert ntl1["is_iran_border_dpi"] is True

    nte1 = classify_iran_border_dpi_anomaly(payload=b"<title>NTE1</title>", observed_ttl=187)
    assert nte1["injector_id"] == "NTE1"
    assert nte1["is_iran_border_dpi"] is True

    shutdown_drill = classify_iran_border_dpi_anomaly(quic_drop_rate=1.0, dns_tcp_drop_rate=0.9668)
    assert shutdown_drill["pre_shutdown_drill_detected"] is True
    assert shutdown_drill["recommended_action"] == "LOCK_ZERO_SNI_DOH_AND_2HOP_RELAY"


def test_live_state_exposes_frontier_2026_posture() -> None:
    """Verify /api/live/state includes frontier_2026 telemetry for RFC 10024, DAITA v2, Anti-RTTdiff, and FOCI 2026 radar."""
    audit = audit_frontier_2026_capabilities()
    assert audit["rfc10024_x25519mlkem768"] is True
    assert audit["pets2026_daita_v2_ephemeral"] is True
    assert audit["ndss2025_anti_rttdiff_scheduler"] is True
    assert audit["foci2026_iran_dpi_radar"] is True

    app = create_control_app(start_proxy=False)
    with TestClient(app) as client:
        res = client.get("/api/live/state")
        assert res.status_code == 200
        data = res.json()
        assert data["satoshi"]["frontier_2026"]["rfc10024_x25519mlkem768"] is True

"""Unit tests for the deterministic 10-control posture grading engine."""

from __future__ import annotations

from observatory.analyzer import assess_security_posture
from observatory.models import CollectedObservation


def test_hardened_target_scores_a_plus_and_redacts_cookie_secret() -> None:
    observation = CollectedObservation(
        requested_url="https://secure.example.com/",
        final_url="https://secure.example.com/",
        hostname="secure.example.com",
        registered_domain="example.com",
        status_code=200,
        response_time_ms=142,
        tls_established=True,
        tls_version="TLSv1.3",
        tls_cipher="TLS_AES_256_GCM_SHA384",
        cert_days_remaining=88,
        headers={
            "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=(), geolocation=()",
            "server": "cloudflare",
        },
        set_cookie_headers=[
            "session_id=SUPER_SECRET_TOKEN_9988; Path=/; Secure; HttpOnly; SameSite=Strict"
        ],
        html_body='<!doctype html><html><body><a href="/.well-known/security.txt">Security</a></body></html>',
        spf_record="v=spf1 include:_spf.example.com -all",
        dmarc_record="v=DMARC1; p=reject; rua=mailto:sec@example.com",
    )

    report = assess_security_posture(observation)
    assert report.score == 100
    assert report.grade == "A+"
    assert "SUPER_SECRET_TOKEN_9988" not in report.model_dump_json()
    assert len(report.findings) == 10
    assert all(item.status == "pass" for item in report.findings)


def test_unhardened_http_target_scores_f_and_flags_surface_risks() -> None:
    observation = CollectedObservation(
        requested_url="http://legacy-shop.example/",
        final_url="http://legacy-shop.example/",
        hostname="legacy-shop.example",
        registered_domain="legacy-shop.example",
        status_code=200,
        response_time_ms=610,
        tls_established=False,
        tls_version="",
        tls_cipher="",
        cert_days_remaining=None,
        headers={
            "server": "Apache/2.4.41 (Ubuntu)",
            "x-powered-by": "PHP/7.4.3",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
        set_cookie_headers=["PHPSESSID=raw_token_abc123; Path=/"],
        html_body=(
            "<html><body>"
            '<script src="http://cdn.legacy-shop.example/app.js"></script>'
            '<form action="http://legacy-shop.example/login" method="post">'
            '<input type="password" name="pwd">'
            "</form>"
            '<a href="https://partner.example" target="_blank">Partner</a>'
            "</body></html>"
        ),
        spf_record="",
        dmarc_record="",
    )

    report = assess_security_posture(observation)
    assert report.score < 20
    assert report.grade == "F"
    assert "raw_token_abc123" not in report.model_dump_json()
    assert report.surface.insecure_password_forms == 1
    assert report.surface.unsafe_blank_links == 1
    assert sum(1 for item in report.findings if item.status == "fail") >= 7

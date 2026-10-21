"""Unit tests for Anti-SSRF target URL validation and normalization."""

from __future__ import annotations

import pytest

from observatory.target_guard import SsrfBlockedError, normalize_and_validate_target


def fake_public_resolver(hostname: str) -> list[str]:
    mapping = {
        "github.com": ["140.82.121.4"],
        "docs.github.com": ["185.199.108.153"],
        "example.com": ["93.184.215.14"],
        "internal.corp.test": ["10.0.4.25"],
        "metadata.cloud.test": ["169.254.169.254"],
        "loopback.alias.test": ["127.0.0.1"],
        "ipv6-loopback.test": ["::1"],
    }
    if hostname not in mapping:
        raise OSError("Name resolution failed")
    return mapping[hostname]


def test_bare_domain_defaults_to_https_scheme() -> None:
    validated = normalize_and_validate_target(
        "github.com",
        resolver=fake_public_resolver,
    )
    assert validated.normalized_url == "https://github.com/"
    assert validated.hostname == "github.com"
    assert validated.registered_domain == "github.com"
    assert validated.resolved_ips == ["140.82.121.4"]


def test_subdomain_extracts_root_domain_for_dns_policies() -> None:
    validated = normalize_and_validate_target(
        "https://docs.github.com/en",
        resolver=fake_public_resolver,
    )
    assert validated.hostname == "docs.github.com"
    assert validated.registered_domain == "github.com"


@pytest.mark.parametrize(
    "forbidden_input",
    [
        "http://127.0.0.1:8000",
        "http://localhost/admin",
        "https://internal.corp.test",
        "http://metadata.cloud.test/latest/meta-data/",
        "https://loopback.alias.test",
        "http://[::1]:8080/",
        "file:///etc/passwd",
        "ftp://example.com/resource",
        "https://example.com:22/",
    ],
)
def test_blocks_private_loopback_metadata_schemes_and_unsafe_ports(
    forbidden_input: str,
) -> None:
    with pytest.raises((SsrfBlockedError, ValueError)):
        normalize_and_validate_target(
            forbidden_input,
            resolver=fake_public_resolver,
        )

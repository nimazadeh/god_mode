"""Anti-SSRF URL normalization and public IP address verification."""

from __future__ import annotations

from collections.abc import Callable
import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

from observatory.constants import (
    ALLOWED_PORTS,
    ALLOWED_SCHEMES,
    TWO_LABEL_PUBLIC_SUFFIXES,
)
from observatory.models import ValidatedTarget


class SsrfBlockedError(ValueError):
    """Raised when a target resolves to a private, loopback, or unsafe endpoint."""


def default_system_resolver(hostname: str) -> list[str]:
    """Resolve A/AAAA records via the operating system resolver."""
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    seen: list[str] = []
    for entry in infos:
        ip_text = entry[4][0]
        if ip_text not in seen:
            seen.append(ip_text)
    return seen


def extract_registered_domain(hostname: str) -> str:
    """Derive the registrable root domain so DNS SPF/DMARC queries target the apex."""
    labels = [part for part in hostname.lower().strip(".").split(".") if part]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in TWO_LABEL_PUBLIC_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def assert_public_ip_address(raw_ip: str) -> None:
    """Reject non-global IPv4/IPv6 ranges to prevent Server-Side Request Forgery."""
    parsed_ip = ipaddress.ip_address(raw_ip)
    if (
        parsed_ip.is_private
        or parsed_ip.is_loopback
        or parsed_ip.is_link_local
        or parsed_ip.is_multicast
        or parsed_ip.is_unspecified
        or parsed_ip.is_reserved
    ):
        raise SsrfBlockedError(
            "دسترسی به آدرس‌های شبکه داخلی، محلی یا رزروشده (SSRF) مسدود است."
        )


def normalize_and_validate_target(
    raw_url: str,
    resolver: Callable[[str], list[str]] | None = None,
) -> ValidatedTarget:
    """Normalize a user-provided domain/URL and verify every resolved IP is global."""
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("لطفاً آدرس وب‌سایت معتبر وارد کنید.")

    # Default bare domain names to HTTPS because modern posture checks expect TLS first.
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SsrfBlockedError(
            "فقط پروتکل‌های استاندارد وب (HTTP و HTTPS) مجاز هستند."
        )

    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname or hostname == "localhost":
        raise SsrfBlockedError(
            "لطفاً یک دامنه عمومی معتبر (مانند example.com) وارد کنید."
        )

    try:
        explicit_port = parsed.port
    except ValueError as error:
        raise ValueError("شماره پورت واردشده در آدرس معتبر نیست.") from error

    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SsrfBlockedError(
            "پورت انتخاب‌شده خارج از پورت‌های مجاز وب (80, 443, 8080, 8443) است."
        )

    # Check literal IPv4/IPv6 inputs directly before invoking DNS resolution.
    try:
        ipaddress.ip_address(hostname)
        assert_public_ip_address(hostname)
        resolved_ips = [hostname]
    except SsrfBlockedError:
        raise
    except ValueError:
        if "." not in hostname:
            raise SsrfBlockedError(
                "لطفاً یک دامنه عمومی معتبر (مانند example.com) وارد کنید."
            )
        active_resolver = resolver or default_system_resolver
        try:
            resolved_ips = active_resolver(hostname)
        except OSError as error:
            raise ValueError(
                f"دامنه «{hostname}» در سیستم DNS جهانی یافت نشد."
            ) from error
        if not resolved_ips:
            raise ValueError(f"هیچ رکورد IP معتبری برای «{hostname}» یافت نشد.")
        for candidate_ip in resolved_ips:
            assert_public_ip_address(candidate_ip)

    normalized_path = parsed.path if parsed.path else "/"
    netloc = hostname if explicit_port is None else f"{hostname}:{port}"
    normalized_url = urlunparse((scheme, netloc, normalized_path, "", parsed.query, ""))

    return ValidatedTarget(
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        registered_domain=extract_registered_domain(hostname),
        port=port,
        resolved_ips=resolved_ips,
    )

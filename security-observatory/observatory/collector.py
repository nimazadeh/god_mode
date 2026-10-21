"""Read-only HTTP, TLS certificate, and public DoH DNS collector."""

from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
import time
import httpx

from observatory.constants import (
    CONNECT_TIMEOUT_SECONDS,
    DOH_ENDPOINT,
    MAX_HTML_BYTES,
    READ_TIMEOUT_SECONDS,
    USER_AGENT_HEADER,
)
from observatory.models import CollectedObservation, ValidatedTarget
from observatory.target_guard import normalize_and_validate_target


def inspect_tls_endpoint(
    hostname: str,
    port: int = 443,
) -> tuple[bool, str, str, int | None]:
    """Read negotiated TLS version, cipher suite, and certificate remaining days."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection(
            (hostname, port),
            timeout=CONNECT_TIMEOUT_SECONDS,
        ) as raw_sock:
            with context.wrap_socket(
                raw_sock,
                server_hostname=hostname,
            ) as tls_sock:
                version = tls_sock.version() or ""
                cipher_tuple = tls_sock.cipher()
                cipher_name = cipher_tuple[0] if cipher_tuple else ""
                cert = tls_sock.getpeercert()
                days_remaining: int | None = None
                not_after_raw = cert.get("notAfter") if cert else None
                if isinstance(not_after_raw, str):
                    expires_at = datetime.strptime(
                        not_after_raw,
                        "%b %d %H:%M:%S %Y %Z",
                    ).replace(tzinfo=timezone.utc)
                    delta = expires_at - datetime.now(timezone.utc)
                    days_remaining = max(0, delta.days)
                return True, version, cipher_name, days_remaining
    except Exception:
        return False, "", "", None


def query_doh_txt_records(
    http_client: httpx.Client,
    domain_name: str,
) -> list[str]:
    """Fetch public TXT records over RFC 8484 DNS-over-HTTPS without UDP port 53."""
    try:
        response = http_client.get(
            DOH_ENDPOINT,
            params={"name": domain_name, "type": "TXT"},
            headers={"Accept": "application/dns-json"},
        )
        if response.status_code != 200:
            return []
        payload = response.json()
        records: list[str] = []
        for item in payload.get("Answer", []):
            raw_data = str(item.get("data", "")).strip().strip('"')
            if raw_data:
                records.append(raw_data)
        return records
    except Exception:
        return []


def collect_passive_observation(target: ValidatedTarget) -> CollectedObservation:
    """Perform a single passive GET request plus TLS and public SPF/DMARC checks."""
    timeout_cfg = httpx.Timeout(
        connect=CONNECT_TIMEOUT_SECONDS,
        read=READ_TIMEOUT_SECONDS,
        write=5.0,
        pool=5.0,
    )
    started_at = time.perf_counter()

    # trust_env=False isolates outbound HTTP calls from sandbox proxy variables.
    with httpx.Client(
        trust_env=False,
        timeout=timeout_cfg,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT_HEADER},
    ) as client:
        spf_candidates = query_doh_txt_records(client, target.registered_domain)
        dmarc_candidates = query_doh_txt_records(
            client,
            f"_dmarc.{target.registered_domain}",
        )
        spf_record = next(
            (txt for txt in spf_candidates if "v=spf1" in txt.lower()),
            "",
        )
        dmarc_record = next(
            (txt for txt in dmarc_candidates if "v=dmarc1" in txt.lower()),
            "",
        )

        current_url = target.normalized_url
        current_target = target
        response: httpx.Response | None = None

        try:
            for _hop in range(6):
                with client.stream("GET", current_url) as streamed:
                    if streamed.is_redirect and streamed.has_redirect_location:
                        next_raw = str(
                            streamed.url.join(streamed.headers["location"])
                        )
                        # Re-run Anti-SSRF guard on every redirect hop to prevent redirect SSRF.
                        current_target = normalize_and_validate_target(next_raw)
                        current_url = current_target.normalized_url
                        continue

                    status_code = streamed.status_code
                    final_url = str(streamed.url)
                    lower_headers = {
                        key.lower(): value for key, value in streamed.headers.items()
                    }
                    set_cookie_list = list(streamed.headers.get_list("set-cookie"))
                    body_chunks: list[bytes] = []
                    downloaded = 0
                    for chunk in streamed.iter_bytes(chunk_size=16_384):
                        body_chunks.append(chunk)
                        downloaded += len(chunk)
                        if downloaded >= MAX_HTML_BYTES:
                            break
                    html_body = b"".join(body_chunks).decode(
                        "utf-8",
                        errors="replace",
                    )
                    response = streamed
                    break
            else:
                raise ValueError("تعداد تغییر مسیرهای (Redirect) دامنه بیش از حد مجاز است.")
        except httpx.TimeoutException as error:
            dns_hint = (
                "رکوردهای DNS دامنه قابل مشاهده بود"
                if (spf_record or dmarc_record)
                else "پاسخی در مهلت زمانی دریافت نشد"
            )
            raise ValueError(
                f"اتصال از سرور ابری به «{target.hostname}» با محدودیت زمانی روبه‌رو شد ({dns_hint}). "
                "اگر این وب‌سایت فایروال جغرافیایی (مخصوص IP ایران) دارد، نسخه ویندوز برنامه را روی سیستم خودتان اجرا کنید."
            ) from error
        except httpx.RequestError as error:
            raise ValueError(
                f"امکان برقراری اتصال وب با «{target.hostname}» وجود نداشت: {type(error).__name__}"
            ) from error

    elapsed_ms = max(1, int((time.perf_counter() - started_at) * 1000))
    if response is None:
        raise ValueError("پاسخ معتبری از وب‌سرور دریافت نشد.")

    tls_established = False
    tls_version = ""
    tls_cipher = ""
    cert_days_remaining: int | None = None
    if current_target.scheme == "https":
        (
            tls_established,
            tls_version,
            tls_cipher,
            cert_days_remaining,
        ) = inspect_tls_endpoint(
            current_target.hostname,
            current_target.port,
        )

    return CollectedObservation(
        requested_url=target.normalized_url,
        final_url=final_url,
        hostname=current_target.hostname,
        registered_domain=current_target.registered_domain,
        status_code=status_code,
        response_time_ms=elapsed_ms,
        tls_established=tls_established,
        tls_version=tls_version,
        tls_cipher=tls_cipher,
        cert_days_remaining=cert_days_remaining,
        headers=lower_headers,
        set_cookie_headers=set_cookie_list,
        html_body=html_body,
        spf_record=spf_record,
        dmarc_record=dmarc_record,
    )

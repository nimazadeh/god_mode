"""Deterministic 10-control security posture analyzer and HTML hygiene engine."""

from __future__ import annotations

from datetime import datetime, timezone
import re

from observatory.constants import (
    CSP_UNSAFE_DYNAMIC_DIRECTIVE,
    CSP_UNSAFE_INLINE_DIRECTIVE,
)
from observatory.models import (
    AuditReport,
    CollectedObservation,
    ControlFinding,
    PostureGrade,
    SurfaceHygieneSummary,
)

MAX_AGE_PATTERN = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
VERSION_NUMBER_PATTERN = re.compile(r"/\d+\.\d+")
META_GENERATOR_PATTERN = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
HTTP_SUBRESOURCE_PATTERN = re.compile(
    r'<(?:script|iframe|img|link)[^>]+(?:src|href)=["\']http://',
    re.IGNORECASE,
)
INSECURE_PASSWORD_FORM_PATTERN = re.compile(
    r"<form\b[^>]*>.*?type=[\"']password[\"'].*?</form>",
    re.IGNORECASE | re.DOTALL,
)
EXTERNAL_BLANK_LINK_PATTERN = re.compile(
    r'<a\b([^>]*target=["\']_blank["\'][^>]*)>',
    re.IGNORECASE,
)


def map_score_to_grade(score: int) -> tuple[PostureGrade, str]:
    """Translate a 0..100 integer score into a standard grade and Persian label."""
    if score >= 95:
        return "A+", "مقاوم‌سازی ممتاز (سطح سازمانی)"
    if score >= 85:
        return "A", "سلامت امنیتی قوی و استاندارد"
    if score >= 70:
        return "B", "قابل‌قبول (دارای چند شکاف پیکربندی)"
    if score >= 55:
        return "C", "ریسک متوسط (نیازمند اصلاح هدرها)"
    if score >= 40:
        return "D", "پیکربندی ضعیف (نیازمند مقاوم‌سازی)"
    return "F", "آسیب‌پذیر در پیکربندی پایه (اقدام فوری)"


def redact_cookie_header(raw_cookie: str) -> str:
    """Strip secret session values so audit logs store attribute flags only."""
    parts = [segment.strip() for segment in raw_cookie.split(";") if segment.strip()]
    if not parts:
        return ""
    first = parts[0]
    cookie_name = first.split("=", 1)[0].strip() if "=" in first else first
    safe_head = f"{cookie_name}=<redacted>"
    if len(parts) == 1:
        return safe_head
    return "; ".join([safe_head] + parts[1:])


def inspect_html_surface(
    html: str,
    is_https_page: bool,
    headers: dict[str, str],
) -> SurfaceHygieneSummary:
    """Count passive HTML exposure patterns without modifying or replaying forms."""
    mixed_count = (
        len(HTTP_SUBRESOURCE_PATTERN.findall(html)) if is_https_page else 0
    )

    insecure_forms = 0
    for form_match in INSECURE_PASSWORD_FORM_PATTERN.finditer(html):
        snippet = form_match.group(0)
        explicit_http_action = 'action="http://' in snippet.lower() or "action='http://" in snippet.lower()
        if explicit_http_action or not is_https_page:
            insecure_forms += 1

    unsafe_blank = 0
    for anchor_attrs in EXTERNAL_BLANK_LINK_PATTERN.findall(html):
        lower_attrs = anchor_attrs.lower()
        if "noopener" not in lower_attrs and "noreferrer" not in lower_attrs:
            unsafe_blank += 1

    has_sec_txt = "security.txt" in html.lower()

    stack_parts: list[str] = []
    if headers.get("server"):
        stack_parts.append(headers["server"])
    if headers.get("x-powered-by"):
        stack_parts.append(headers["x-powered-by"])
    gen_match = META_GENERATOR_PATTERN.search(html)
    if gen_match:
        stack_parts.append(gen_match.group(1).strip())

    detected_stack = " | ".join(stack_parts) if stack_parts else "مخفی‌شده (استاندارد)"
    return SurfaceHygieneSummary(
        mixed_content_urls=mixed_count,
        insecure_password_forms=insecure_forms,
        unsafe_blank_links=unsafe_blank,
        has_security_txt_link=has_sec_txt,
        detected_stack=detected_stack[:120],
    )


def _assess_tls_control(obs: CollectedObservation) -> ControlFinding:
    is_https_final = obs.final_url.lower().startswith("https://")
    if is_https_final and obs.tls_established:
        cert_ok = obs.cert_days_remaining is None or obs.cert_days_remaining >= 14
        if obs.tls_version == "TLSv1.3" and cert_ok:
            return ControlFinding(
                control_id="tls-transport",
                category_fa="رمزنگاری نشست",
                title_fa="پروتکل رمزنگاری TLS و گواهی SSL",
                status="pass",
                earned_points=15,
                max_points=15,
                observed_value=f"{obs.tls_version} ({obs.tls_cipher})",
                impact_fa="ارتباط کاربر و سرور با جدیدترین استاندارد TLS 1.3 رمزنگاری شده است.",
                remediation_title_fa="پیکربندی استاندارد فعلی",
                remediation_snippet="ssl_protocols TLSv1.2 TLSv1.3;",
            )
        if obs.tls_version in ("TLSv1.2", "TLSv1.3"):
            return ControlFinding(
                control_id="tls-transport",
                category_fa="رمزنگاری نشست",
                title_fa="پروتکل رمزنگاری TLS و گواهی SSL",
                status="warn",
                earned_points=11,
                max_points=15,
                observed_value=f"{obs.tls_version} | انقضا: {obs.cert_days_remaining} روز",
                impact_fa="پروتکل TLS فعال است اما ارتقا به TLS 1.3 یا تمدید زودهنگام گواهی توصیه می‌شود.",
                remediation_title_fa="فعال‌سازی TLS 1.3 در Nginx",
                remediation_snippet="ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;",
            )

    return ControlFinding(
        control_id="tls-transport",
        category_fa="رمزنگاری نشست",
        title_fa="پروتکل رمزنگاری TLS و گواهی SSL",
        status="fail",
        earned_points=0,
        max_points=15,
        observed_value="HTTP بدون رمزنگاری (فاقد TLS معتبر)",
        impact_fa="تمام رمزهای عبور، کوکی‌ها و اطلاعات فرم‌ها در شبکه به صورت متن باز قابل شنود هستند.",
        remediation_title_fa="انتقال اجباری HTTP به HTTPS در Nginx",
        remediation_snippet="server {\n    listen 80;\n    return 301 https://$host$request_uri;\n}",
    )


def _assess_hsts_control(headers: dict[str, str]) -> ControlFinding:
    raw_hsts = headers.get("strict-transport-security", "").strip()
    if raw_hsts:
        match = MAX_AGE_PATTERN.search(raw_hsts)
        max_age = int(match.group(1)) if match else 0
        if max_age >= 15_552_000:
            return ControlFinding(
                control_id="hsts-policy",
                category_fa="امنیت انتقال",
                title_fa="سیاست امنیت انتقال سخت‌گیرانه — HSTS",
                status="pass",
                earned_points=15,
                max_points=15,
                observed_value=raw_hsts[:110],
                impact_fa="مرورگرها اجازه اتصال ناامن HTTP و حملات SSL Stripping را نمی‌دهند.",
                remediation_title_fa="هدر HSTS استاندارد",
                remediation_snippet='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            )
        return ControlFinding(
            control_id="hsts-policy",
            category_fa="امنیت انتقال",
            title_fa="سیاست امنیت انتقال سخت‌گیرانه — HSTS",
            status="warn",
            earned_points=8,
            max_points=15,
            observed_value=raw_hsts[:110],
            impact_fa="هدر HSTS فعال است اما مدت زمان max-age کمتر از ۶ ماه (۱۵,۵۵۲,۰۰۰ ثانیه) است.",
            remediation_title_fa="افزایش مدت HSTS به یک سال",
            remediation_snippet='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        )

    return ControlFinding(
        control_id="hsts-policy",
        category_fa="امنیت انتقال",
        title_fa="سیاست امنیت انتقال سخت‌گیرانه — HSTS",
        status="fail",
        earned_points=0,
        max_points=15,
        observed_value="Missing Header: Strict-Transport-Security",
        impact_fa="در شبکه‌های وای‌فای عمومی امکان تنزل اتصال کاربر از HTTPS به HTTP (حمله مرد میانی) وجود دارد.",
        remediation_title_fa="افزودن هدر HSTS در وب‌سرور",
        remediation_snippet='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    )


def _assess_csp_control(headers: dict[str, str]) -> ControlFinding:
    raw_csp = headers.get("content-security-policy", "").strip()
    if raw_csp:
        lowered = raw_csp.lower()
        has_weakness = (
            CSP_UNSAFE_DYNAMIC_DIRECTIVE in lowered
            or CSP_UNSAFE_INLINE_DIRECTIVE in lowered
        )
        if not has_weakness:
            return ControlFinding(
                control_id="csp-policy",
                category_fa="مهار تزریق اسکریپت",
                title_fa="سیاست امنیت محتوا — Content-Security-Policy",
                status="pass",
                earned_points=20,
                max_points=20,
                observed_value=raw_csp[:110],
                impact_fa="سیاست CSP قوی جلوی اجرای اسکریپت‌های تزریقی (XSS) و بارگذاری منابع غیرمجاز را می‌گیرد.",
                remediation_title_fa="سیاست CSP سخت‌گیرانه",
                remediation_snippet="add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none';\" always;",
            )
        return ControlFinding(
            control_id="csp-policy",
            category_fa="مهار تزریق اسکریپت",
            title_fa="سیاست امنیت محتوا — Content-Security-Policy",
            status="warn",
            earned_points=12,
            max_points=20,
            observed_value=raw_csp[:110],
            impact_fa="هدر CSP تعریف شده اما حاوی مجوز اسکریپت خطی/پویا است که سپر ضد XSS را تضعیف می‌کند.",
            remediation_title_fa="جایگزینی اسکریپت خطی با Nonce یا فایل مجزا",
            remediation_snippet="add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;",
        )

    return ControlFinding(
        control_id="csp-policy",
        category_fa="مهار تزریق اسکریپت",
        title_fa="سیاست امنیت محتوا — Content-Security-Policy",
        status="fail",
        earned_points=0,
        max_points=20,
        observed_value="Missing Header: Content-Security-Policy",
        impact_fa="در صورت بروز کوچک‌ترین باگ XSS یا آلودگی اسکریپت تبلیغاتی، سرقت نشست کاربران ممکن می‌شود.",
        remediation_title_fa="تعریف هدر CSP پایه در Nginx / Cloudflare",
        remediation_snippet="add_header Content-Security-Policy \"default-src 'self'; img-src 'self' data: https:; object-src 'none'; frame-ancestors 'self';\" always;",
    )


def _assess_frame_control(headers: dict[str, str]) -> ControlFinding:
    xfo = headers.get("x-frame-options", "").strip()
    csp = headers.get("content-security-policy", "").lower()
    if xfo.upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp:
        shown = xfo if xfo else "CSP frame-ancestors"
        return ControlFinding(
            control_id="anti-clickjacking",
            category_fa="محافظت رابط کاربری",
            title_fa="محافظت در برابر فریم مخفی — Anti-Clickjacking",
            status="pass",
            earned_points=10,
            max_points=10,
            observed_value=shown[:90],
            impact_fa="سایت‌های مهاجم نمی‌توانند صفحات حساس این وب‌سایت را داخل iframe نامرئی بارگذاری کنند.",
            remediation_title_fa="محافظت فریم فعال است",
            remediation_snippet='add_header X-Frame-Options "SAMEORIGIN" always;',
        )

    return ControlFinding(
        control_id="anti-clickjacking",
        category_fa="محافظت رابط کاربری",
        title_fa="محافظت در برابر فریم مخفی — Anti-Clickjacking",
        status="fail",
        earned_points=0,
        max_points=10,
        observed_value="Missing Header: X-Frame-Options / frame-ancestors",
        impact_fa="مهاجم می‌تواند دکمه‌های پنل کاربری سایت را زیر لایه نامرئی قرار داده و کلیک کاربر را بدزدد.",
        remediation_title_fa="بستن بارگذاری در فریم بیگانه",
        remediation_snippet='add_header X-Frame-Options "SAMEORIGIN" always;',
    )


def _assess_mime_control(headers: dict[str, str]) -> ControlFinding:
    xcto = headers.get("x-content-type-options", "").strip()
    if xcto.lower() == "nosniff":
        return ControlFinding(
            control_id="mime-nosniff",
            category_fa="ایمنی فایل",
            title_fa="جلوگیری از حدس خطرناک نوع فایل — MIME Sniffing",
            status="pass",
            earned_points=10,
            max_points=10,
            observed_value=xcto,
            impact_fa="مرورگر فایل‌های آپلودشده کاربران (مانند تصویر یا متن) را به عنوان اسکریپت اجرا نمی‌کند.",
            remediation_title_fa="هدر nosniff فعال است",
            remediation_snippet='add_header X-Content-Type-Options "nosniff" always;',
        )

    return ControlFinding(
        control_id="mime-nosniff",
        category_fa="ایمنی فایل",
        title_fa="جلوگیری از حدس خطرناک نوع فایل — MIME Sniffing",
        status="fail",
        earned_points=0,
        max_points=10,
        observed_value="Missing Header: X-Content-Type-Options: nosniff",
        impact_fa="فایل‌های آپلودی کاربران ممکن است توسط مرورگر به عنوان کد اجرایی تفسیر شوند.",
        remediation_title_fa="فعال‌سازی فوری nosniff",
        remediation_snippet='add_header X-Content-Type-Options "nosniff" always;',
    )


def _assess_cookies_control(raw_cookies: list[str]) -> ControlFinding:
    if not raw_cookies:
        return ControlFinding(
            control_id="cookie-hygiene",
            category_fa="حفاظت نشست",
            title_fa="امنیت پرچم‌های کوکی نشست — Secure / HttpOnly / SameSite",
            status="pass",
            earned_points=10,
            max_points=10,
            observed_value="No Session Cookie Issued on Public Landing",
            impact_fa="هیچ کوکی ناامنی در پاسخ اولیه صادر نشده است.",
            remediation_title_fa="الگوی استاندارد صدور کوکی",
            remediation_snippet="Set-Cookie: session=<token>; Path=/; Secure; HttpOnly; SameSite=Lax",
        )

    redacted_list = [redact_cookie_header(item) for item in raw_cookies]
    all_secure = all("; secure" in item.lower() for item in raw_cookies)
    all_httponly = all("; httponly" in item.lower() for item in raw_cookies)
    all_samesite = all("samesite=" in item.lower() for item in raw_cookies)

    if all_secure and all_httponly and all_samesite:
        return ControlFinding(
            control_id="cookie-hygiene",
            category_fa="حفاظت نشست",
            title_fa="امنیت پرچم‌های کوکی نشست — Secure / HttpOnly / SameSite",
            status="pass",
            earned_points=10,
            max_points=10,
            observed_value=redacted_list[0][:110],
            impact_fa="تمام کوکی‌ها با پرچم‌های کامل ضد سرقت XSS و ضد CSRF محافظت شده‌اند.",
            remediation_title_fa="پرچم‌های امنیتی کوکی کامل است",
            remediation_snippet="Set-Cookie: session=<token>; Path=/; Secure; HttpOnly; SameSite=Lax",
        )

    if all_secure:
        return ControlFinding(
            control_id="cookie-hygiene",
            category_fa="حفاظت نشست",
            title_fa="امنیت پرچم‌های کوکی نشست — Secure / HttpOnly / SameSite",
            status="warn",
            earned_points=5,
            max_points=10,
            observed_value=redacted_list[0][:110],
            impact_fa="کوکی دارای Secure است اما یکی از پرچم‌های HttpOnly یا SameSite تنظیم نشده است.",
            remediation_title_fa="تکمیل پرچم‌های HttpOnly و SameSite",
            remediation_snippet="proxy_cookie_flags ~ secure httponly samesite=lax;",
        )

    return ControlFinding(
        control_id="cookie-hygiene",
        category_fa="حفاظت نشست",
        title_fa="امنیت پرچم‌های کوکی نشست — Secure / HttpOnly / SameSite",
        status="fail",
        earned_points=0,
        max_points=10,
        observed_value=redacted_list[0][:110],
        impact_fa="کوکی نشست فاقد پرچم‌های حیاتی Secure / HttpOnly است و در معرض سرقت توکن قرار دارد.",
        remediation_title_fa="اجبار پرچم‌های امنیتی کوکی در Nginx",
        remediation_snippet="proxy_cookie_flags ~ secure httponly samesite=lax;",
    )


def _assess_cors_control(headers: dict[str, str]) -> ControlFinding:
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    if acao == "*" and acac == "true":
        return ControlFinding(
            control_id="cors-hygiene",
            category_fa="ایزوله‌سازی دامنه",
            title_fa="سیاست اشتراک منابع بین‌دامنه‌ای — CORS",
            status="fail",
            earned_points=0,
            max_points=5,
            observed_value="Access-Control-Allow-Origin: * + Credentials",
            impact_fa="ترکیب بسیار خطرناک CORS باز با ارسال کوکی که امکان سرقت اطلاعات حساب از سایت‌های دیگر را می‌دهد.",
            remediation_title_fa="محدودسازی CORS به دامنه مورد اعتماد",
            remediation_snippet='add_header Access-Control-Allow-Origin "https://app.example.com" always;',
        )
    if acao == "*":
        return ControlFinding(
            control_id="cors-hygiene",
            category_fa="ایزوله‌سازی دامنه",
            title_fa="سیاست اشتراک منابع بین‌دامنه‌ای — CORS",
            status="warn",
            earned_points=3,
            max_points=5,
            observed_value="Access-Control-Allow-Origin: *",
            impact_fa="پاسخ‌های عمومی برای تمام دامنه‌ها باز است؛ مطمئن شوید روی APIهای خصوصی اعمال نشده باشد.",
            remediation_title_fa="محدودسازی CORS در APIهای احرازهویت‌شده",
            remediation_snippet='add_header Access-Control-Allow-Origin "https://app.example.com" always;',
        )
    return ControlFinding(
        control_id="cors-hygiene",
        category_fa="ایزوله‌سازی دامنه",
        title_fa="سیاست اشتراک منابع بین‌دامنه‌ای — CORS",
        status="pass",
        earned_points=5,
        max_points=5,
        observed_value=acao if acao else "Same-Origin Default Isolation",
        impact_fa="مرورگر اجازه خواندن داده‌های خصوصی سایت توسط دامنه‌های بیگانه را نمی‌دهد.",
        remediation_title_fa="سیاست Same-Origin ایمن است",
        remediation_snippet="# Keep default Same-Origin browser isolation enabled.",
    )


def _assess_privacy_headers_control(headers: dict[str, str]) -> ControlFinding:
    ref = headers.get("referrer-policy", "").strip()
    perm = headers.get("permissions-policy", "").strip()
    if ref and perm:
        return ControlFinding(
            control_id="referrer-permissions",
            category_fa="حریم خصوصی مرورگر",
            title_fa="کنترل نشت ارجاع‌دهنده و سخت‌افزار مرورگر — Referrer & Permissions",
            status="pass",
            earned_points=5,
            max_points=5,
            observed_value=f"Referrer-Policy: {ref[:42]} | Permissions-Policy: Enabled",
            impact_fa="نشت توکن‌های موجود در URL به سایت‌های ثالث و دسترسی غیرمجاز به میکروفون/دوربین بسته شده است.",
            remediation_title_fa="پیکربندی کامل حریم خصوصی",
            remediation_snippet='add_header Referrer-Policy "strict-origin-when-cross-origin" always;\nadd_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        )
    if ref or perm:
        return ControlFinding(
            control_id="referrer-permissions",
            category_fa="حریم خصوصی مرورگر",
            title_fa="کنترل نشت ارجاع‌دهنده و سخت‌افزار مرورگر — Referrer & Permissions",
            status="warn",
            earned_points=3,
            max_points=5,
            observed_value=f"Referrer-Policy: {ref or 'missing'} | Permissions-Policy: {'set' if perm else 'missing'}",
            impact_fa="فقط یکی از دو هدر Referrer-Policy یا Permissions-Policy تنظیم شده است.",
            remediation_title_fa="افزودن هر دو هدر محافظتی",
            remediation_snippet='add_header Referrer-Policy "strict-origin-when-cross-origin" always;\nadd_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        )
    return ControlFinding(
        control_id="referrer-permissions",
        category_fa="حریم خصوصی مرورگر",
        title_fa="کنترل نشت ارجاع‌دهنده و سخت‌افزار مرورگر — Referrer & Permissions",
        status="fail",
        earned_points=0,
        max_points=5,
        observed_value="Missing: Referrer-Policy & Permissions-Policy",
        impact_fa="آدرس کامل صفحات داخلی (حاوی لینک بازیابی رمز یا شناسه سفارش) هنگام کلیک روی لینک خارجی لو می‌رود.",
        remediation_title_fa="افزودن هدرهای حریم خصوصی مرورگر",
        remediation_snippet='add_header Referrer-Policy "strict-origin-when-cross-origin" always;\nadd_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
    )


def _assess_fingerprint_control(
    headers: dict[str, str],
    html_body: str,
) -> ControlFinding:
    server_val = headers.get("server", "").strip()
    powered_val = headers.get("x-powered-by", "").strip()
    gen_match = META_GENERATOR_PATTERN.search(html_body)
    gen_val = gen_match.group(1).strip() if gen_match else ""
    combined = " | ".join(part for part in (server_val, powered_val, gen_val) if part)

    if powered_val or VERSION_NUMBER_PATTERN.search(combined) or gen_val:
        return ControlFinding(
            control_id="stack-fingerprint",
            category_fa="کاهش سطح حمله",
            title_fa="عدم افشای نسخه دقیق وب‌سرور و زبان بک‌اند",
            status="fail",
            earned_points=0,
            max_points=5,
            observed_value=combined[:110],
            impact_fa="افشای نسخه دقیق (مانند PHP یا Apache) به ربات‌ها کمک می‌کند دقیقاً CVE همان نسخه را هدف بگیرند.",
            remediation_title_fa="مخفی‌سازی نسخه وب‌سرور و PHP",
            remediation_snippet="server_tokens off;\nfastcgi_hide_header X-Powered-By;",
        )

    return ControlFinding(
        control_id="stack-fingerprint",
        category_fa="کاهش سطح حمله",
        title_fa="عدم افشای نسخه دقیق وب‌سرور و زبان بک‌اند",
        status="pass",
        earned_points=5,
        max_points=5,
        observed_value=server_val if server_val else "Masked / Hidden",
        impact_fa="هیچ شماره نسخه دقیقی از وب‌سرور یا مفسر بک‌اند افشا نشده است.",
        remediation_title_fa="پنهان‌سازی نسخه فعال است",
        remediation_snippet="server_tokens off;",
    )


def _assess_email_spoofing_control(
    domain: str,
    spf: str,
    dmarc: str,
) -> ControlFinding:
    if spf and dmarc:
        return ControlFinding(
            control_id="dns-email-auth",
            category_fa="امنیت دامنه و ایمیل",
            title_fa="محافظت دامنه در برابر جعل ایمیل — SPF & DMARC",
            status="pass",
            earned_points=5,
            max_points=5,
            observed_value=f"SPF: OK | {dmarc[:72]}",
            impact_fa="کلاهبرداران نمی‌توانند با جعل آدرس ایمیل رسمی شرکت، برای مشتریان فیشینگ بفرستند.",
            remediation_title_fa="رکوردهای ضدجعل ایمیل فعال هستند",
            remediation_snippet=f'_dmarc.{domain}. IN TXT "v=DMARC1; p=quarantine;"',
        )
    if spf or dmarc:
        return ControlFinding(
            control_id="dns-email-auth",
            category_fa="امنیت دامنه و ایمیل",
            title_fa="محافظت دامنه در برابر جعل ایمیل — SPF & DMARC",
            status="warn",
            earned_points=2,
            max_points=5,
            observed_value=f"SPF: {'present' if spf else 'missing'} | DMARC: {'present' if dmarc else 'missing'}",
            impact_fa="فقط یکی از رکوردهای SPF یا DMARC روی DNS تنظیم شده و حفاظت ضد فیشینگ ناقص است.",
            remediation_title_fa="تکمیل رکورد TXT در پنل DNS دامنه",
            remediation_snippet=f'{domain}. IN TXT "v=spf1 a mx ~all"\n_dmarc.{domain}. IN TXT "v=DMARC1; p=quarantine;"',
        )

    return ControlFinding(
        control_id="dns-email-auth",
        category_fa="امنیت دامنه و ایمیل",
        title_fa="محافظت دامنه در برابر جعل ایمیل — SPF & DMARC",
        status="fail",
        earned_points=0,
        max_points=5,
        observed_value="Missing DNS TXT: SPF & DMARC",
        impact_fa="هر فردی در اینترنت می‌تواند از نام دامنه رسمی این کسب‌وکار ایمیل جعلی (Spoofing) ارسال کند!",
        remediation_title_fa="ثبت رکوردهای TXT در کلودفلر / پنل دامنه",
        remediation_snippet=f'{domain}. IN TXT "v=spf1 a mx -all"\n_dmarc.{domain}. IN TXT "v=DMARC1; p=reject;"',
    )


def assess_security_posture(
    observation: CollectedObservation,
    scanned_at_iso: str | None = None,
) -> AuditReport:
    """Compute the full 0..100 posture report from a passive observation."""
    headers = {k.lower(): v for k, v in observation.headers.items()}
    is_https = observation.final_url.lower().startswith("https://")

    findings = [
        _assess_tls_control(observation),
        _assess_hsts_control(headers),
        _assess_csp_control(headers),
        _assess_frame_control(headers),
        _assess_mime_control(headers),
        _assess_cookies_control(observation.set_cookie_headers),
        _assess_cors_control(headers),
        _assess_privacy_headers_control(headers),
        _assess_fingerprint_control(headers, observation.html_body),
        _assess_email_spoofing_control(
            observation.registered_domain,
            observation.spf_record,
            observation.dmarc_record,
        ),
    ]

    total_score = max(0, min(100, sum(item.earned_points for item in findings)))
    grade, risk_label = map_score_to_grade(total_score)

    passed_count = sum(1 for item in findings if item.status == "pass")
    warning_count = sum(1 for item in findings if item.status == "warn")
    failed_count = sum(1 for item in findings if item.status == "fail")

    surface = inspect_html_surface(observation.html_body, is_https, headers)

    if observation.tls_established:
        days_part = (
            f" ({observation.cert_days_remaining} روز اعتبار)"
            if observation.cert_days_remaining is not None
            else ""
        )
        tls_summary = f"{observation.tls_version}{days_part}"
    else:
        tls_summary = "بدون TLS (HTTP خام)"

    timestamp = scanned_at_iso or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    return AuditReport(
        audit_id=0,
        target_url=observation.requested_url,
        final_url=observation.final_url,
        hostname=observation.hostname,
        registered_domain=observation.registered_domain,
        scanned_at_iso=timestamp,
        status_code=observation.status_code,
        response_time_ms=observation.response_time_ms,
        score=total_score,
        grade=grade,
        risk_label_fa=risk_label,
        tls_summary=tls_summary,
        cert_days_remaining=observation.cert_days_remaining,
        passed_count=passed_count,
        warning_count=warning_count,
        failed_count=failed_count,
        spf_present=bool(observation.spf_record),
        dmarc_present=bool(observation.dmarc_record),
        surface=surface,
        findings=findings,
    )

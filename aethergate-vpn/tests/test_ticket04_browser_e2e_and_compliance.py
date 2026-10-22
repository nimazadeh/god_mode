"""Ticket 04: Code compliance checks and Playwright E2E browser verification for AetherGate VPN."""

import ast
from pathlib import Path
import re
from playwright.async_api import async_playwright
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
SCREENSHOT_PATH = Path("/home/user/screenshots/aethergate_vpn_dashboard.png")


def _count_non_comment_code_lines(text: str) -> int:
    """Count executable source lines excluding blank lines and comments so rich multi-line WHY documentation is never penalized."""
    in_docstring = False
    code_lines = 0
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("/*") or stripped.startswith("*") or stripped.startswith("//"):
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            if stripped.count('"""') == 1 or stripped.count("'''") == 1:
                in_docstring = not in_docstring
            continue
        if in_docstring:
            if '"""' in stripped or "'''" in stripped:
                in_docstring = False
            continue
        code_lines += 1
    return code_lines


def test_python_line_and_function_caps_and_zero_persian() -> None:
    """Enforce clean modular size (excluding WHY comments/docstrings) and zero Persian text in source files."""
    persian_re = re.compile(r"[\u0600-\u06FF]")
    for py_file in ROOT_DIR.rglob("*.py"):
        if any(p in py_file.parts for p in ("venv", ".pytest_cache", "tests")):
            continue
        text = py_file.read_text(encoding="utf-8")
        assert not persian_re.search(text), f"Persian character found in {py_file}"
        code_lines = _count_non_comment_code_lines(text)
        assert code_lines <= 400, f"{py_file.name} has {code_lines} non-comment code lines (>400)"
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_src = ast.get_source_segment(text, node) or ""
                fn_code_lines = _count_non_comment_code_lines(fn_src)
                assert fn_code_lines <= 60, f"{py_file.name}:{node.name} has {fn_code_lines} code lines (>60)"


def test_js_and_css_strict_craft_compliance() -> None:
    """Enforce clean JS size (excluding WHY comments), no innerHTML/eval, no !important, and colors only in variables.css."""
    js_dir = ROOT_DIR / "dashboard" / "js"
    css_dir = ROOT_DIR / "dashboard" / "css"
    assert js_dir.exists() and css_dir.exists()
    for js_file in js_dir.glob("*.js"):
        text = js_file.read_text(encoding="utf-8")
        code_lines = _count_non_comment_code_lines(text)
        assert code_lines <= 250, f"{js_file.name} has {code_lines} non-comment code lines (>250)"
        assert "innerHTML" not in text, f"innerHTML forbidden in {js_file.name}"
        assert "eval(" not in text, f"eval() forbidden in {js_file.name}"

    color_re = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(")
    for css_file in css_dir.glob("*.css"):
        text = css_file.read_text(encoding="utf-8")
        assert "!important" not in text, f"!important forbidden in {css_file.name}"
        if css_file.name != "variables.css":
            assert not color_re.search(text), f"Hardcoded color found in {css_file.name}"


def test_windows_bat_crlf_and_linux_vps_deploy_script() -> None:
    """Verify start_aethergate.bat uses CRLF, deploy_vps_server.sh exists, and FEATURES.md is maintained."""
    bat = ROOT_DIR / "start_aethergate.bat"
    sh = ROOT_DIR / "deploy_vps_server.sh"
    feat = ROOT_DIR / "FEATURES.md"
    feat_docs = ROOT_DIR / "docs" / "FEATURES.md"
    assert bat.exists() and sh.exists() and feat.exists() and feat_docs.exists()
    assert "Layer 7:" in feat.read_text(encoding="utf-8")
    raw = bat.read_bytes()
    assert b"\r\n" in raw, "start_aethergate.bat must have CRLF line endings"


@pytest.mark.asyncio
async def test_aethergate_dashboard_e2e_browser_and_screenshot() -> None:
    """Verify AetherGate VPN Control Center UI, transport switching, E2E benchmark, and camouflage probe."""
    SCREENSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
        page.on("pageerror", lambda err: errors.append(str(err)))

        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        await page.wait_for_selector("#btn-toggle-tunnel")

        # 1. Verify auto-connected or toggle to CONNECTED state
        cur_txt = await page.locator("#tunnel-state-badge").inner_text()
        if "CONNECTED" not in cur_txt:
            await page.click("#btn-toggle-tunnel")
        await page.wait_for_function(
            "document.getElementById('tunnel-state-badge')?.textContent.includes('CONNECTED')"
        )

        # 2. Expand progressive disclosure drawer and verify Smart Anti-DPI Engine
        await page.click(".advanced-drawer summary")
        await page.click("[data-transport='DPI_DESYNC_DOH']")
        await page.click("#btn-run-benchmark")
        await page.wait_for_function(
            "document.getElementById('benchmark-result-box')?.textContent.includes('RFC 9421 VERIFIED')"
        )

        # 3. Test Active Probe Camouflage
        await page.click("#btn-test-camouflage")
        await page.wait_for_function(
            "document.getElementById('camouflage-probe-status')?.textContent.includes('200 OK')"
        )

        # 4. Add a custom Smart Routing rule and collapse drawer for clean view
        await page.fill("#route-pattern-input", "scholar.example.org")
        await page.select_option("#route-action-select", "TUNNEL")
        await page.click("#btn-add-route")
        await page.wait_for_function(
            "document.getElementById('routing-rules-tbody')?.textContent.includes('scholar.example.org')"
        )
        await page.click(".advanced-drawer summary")

        await page.screenshot(path=str(SCREENSHOT_PATH), full_page=False)
        await browser.close()

    assert errors == [], f"Browser errors: {errors}"
    assert SCREENSHOT_PATH.exists() and SCREENSHOT_PATH.stat().st_size > 10000

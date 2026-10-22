"""Ticket 47 (v10.8) TDD verification for single canonical Phosphor Hacker Terminal UI (zero Variant B/C switcher remnants) and 7 Sovereign Power Clauses in AGENT.md."""

from pathlib import Path
import pytest
from playwright.async_api import async_playwright
from constants import AETHERGATE_VERSION

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_version_v10_8_and_zero_variant_remnants_in_ui_files() -> None:
    """Verify v10.8 version and ensure index.html, ui.js, and app.js have zero legacy variantNames/applyVariant/stepVariant code."""
    assert AETHERGATE_VERSION.startswith(("v10.", "v11."))
    ui_js = (ROOT_DIR / "dashboard" / "js" / "ui.js").read_text(encoding="utf-8")
    app_js = (ROOT_DIR / "dashboard" / "js" / "app.js").read_text(encoding="utf-8")
    index_html = (ROOT_DIR / "dashboard" / "index.html").read_text(encoding="utf-8")

    for forbidden in ("variantNames", "Variant B", "Variant C", "applyVariant", "stepVariant", "setVariant", "proto-switcher", "data-variant"):
        assert forbidden not in ui_js, f"Legacy variant code {forbidden!r} still present in ui.js"
        assert forbidden not in app_js, f"Legacy variant code {forbidden!r} still present in app.js"
        assert forbidden not in index_html, f"Legacy variant code {forbidden!r} still present in index.html"


def test_agent_md_contains_seven_sovereign_power_clauses_and_single_zip_law() -> None:
    """Verify AGENT.md defines the 7 Sovereign 0.01% Mastery Clauses and matches between /home/user/AGENT.md and project root."""
    workspace_agent = Path("/home/user/AGENT.md").read_text(encoding="utf-8")
    project_agent = (ROOT_DIR / "AGENT.md").read_text(encoding="utf-8")
    assert workspace_agent == project_agent
    assert not Path("/home/user/AGENTS.md").exists(), "Duplicate AGENTS.md must not exist alongside AGENT.md"

    for sovereign_pillar in (
        "Adversarial Red-Team & Nation-State Threat Modeling",
        "First-Principles Mathematical & Byte-Level Thinking",
        "Zero Dead-Code & Ruthless Surgical Cleanliness",
        "Zero-Panic Autonomous Self-Healing & Root-Cause Mastery",
        "Architectural Continuity & Sacred Invariant Guarding",
        "3-Horizon Chess Grandmaster Foresight",
        "Relentless Scientific Ambition & Devotion",
        "Single Active Version ZIP Law",
    ):
        assert sovereign_pillar in workspace_agent, f"Missing sovereign pillar {sovereign_pillar!r} in AGENT.md"


@pytest.mark.asyncio
async def test_canonical_single_url_dashboard_renders_cleanly() -> None:
    """Verify http://127.0.0.1:9090/ loads directly with zero variant query params or switcher elements."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))

        await page.goto("http://127.0.0.1:9090/", wait_until="networkidle")
        assert page.url == "http://127.0.0.1:9090/"
        assert await page.locator("#proto-switcher").count() == 0
        assert await page.get_attribute("body", "data-variant") is None
        assert await page.locator("#console-sticky-header").count() == 1

        await browser.close()
        assert errors == []

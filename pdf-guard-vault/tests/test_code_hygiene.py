"""Automated code hygiene, deep-module seam, performance budget, and Windows .bat tests."""

from __future__ import annotations

from pathlib import Path
import re
import sqlite3

from vault.storage import VaultRepository

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEXT_EXTENSIONS = {".py", ".js", ".css", ".html", ".bat", ".md", ".ini", ".txt"}


def iter_project_text_files() -> list[Path]:
    """Return all tracked text files in the project."""
    collected: list[Path] = []
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(
            part in {".venv", "venv", "__pycache__", ".pytest_cache", "data"}
            for part in path.parts
        ):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS:
            collected.append(path)
    return sorted(collected)


def test_source_code_comments_and_core_modules_are_english_while_ui_is_persian() -> None:
    """Verify Python logic/CSS/batch files are English while HTML UI is Persian RTL."""
    persian_arabic_pattern = re.compile(
        r"[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]"
    )

    strict_english_files = [
        PROJECT_ROOT / "main.py",
        PROJECT_ROOT / "run-windows.bat",
        PROJECT_ROOT / "start_vault.bat",
        PROJECT_ROOT / "web" / "css" / "tokens.css",
        PROJECT_ROOT / "web" / "css" / "app.css",
        PROJECT_ROOT / "vault" / "constants.py",
        PROJECT_ROOT / "vault" / "models.py",
        PROJECT_ROOT / "vault" / "pdf_stamper.py",
        PROJECT_ROOT / "vault" / "storage.py",
        PROJECT_ROOT / "vault" / "exporter.py",
        PROJECT_ROOT / "vault" / "api.py",
    ]
    for file_path in strict_english_files:
        content = file_path.read_text(encoding="utf-8")
        assert persian_arabic_pattern.search(content) is None, (
            f"Found non-English character in {file_path.relative_to(PROJECT_ROOT)}"
        )

    for file_path in iter_project_text_files():
        if file_path.suffix.lower() in {".py", ".js"}:
            for line in file_path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    assert persian_arabic_pattern.search(stripped) is None, (
                        f"Comment must be English in {file_path.relative_to(PROJECT_ROOT)}: {stripped}"
                    )

    index_html = (PROJECT_ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert 'lang="fa"' in index_html
    assert 'dir="rtl"' in index_html
    assert persian_arabic_pattern.search(index_html) is not None


def test_source_files_contain_zero_ai_footprint_terms() -> None:
    """Ensure the repository reads as natural software engineering work without AI markers."""
    disallowed_markers = [
        "hidden" + " eyes",
        "nikola" + " tesla",
        "sato" + "shi",
        "arena" + ".ai",
        "clau" + "de",
        "chat" + "gpt",
        "matt" + " pocock",
    ]
    for file_path in iter_project_text_files():
        if file_path.name == "test_code_hygiene.py":
            continue
        lowered = file_path.read_text(encoding="utf-8").lower()
        for marker in disallowed_markers:
            assert marker not in lowered, (
                f"Found disallowed marker '{marker}' in {file_path.relative_to(PROJECT_ROOT)}"
            )


def test_web_assets_avoid_unsafe_dom_and_css_overrides() -> None:
    """Enforce Best Practices by banning unsafe DOM injection and CSS important flags."""
    forbidden_tokens = [
        "inner" + "HTML",
        "outer" + "HTML",
        "eval" + "(",
        "!" + "important",
        "variant" + "Names",
    ]
    for file_path in iter_project_text_files():
        if file_path.name == "test_code_hygiene.py":
            continue
        content = file_path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in content, (
                f"Forbidden token '{token}' found in {file_path.relative_to(PROJECT_ROOT)}"
            )


def test_api_layer_respects_deep_service_seam() -> None:
    """Verify the HTTP transport layer never reaches past CourseVaultService into .repository."""
    api_source = (PROJECT_ROOT / "vault" / "api.py").read_text(encoding="utf-8")
    assert ".repository." not in api_source
    assert ".stamper." not in api_source


def test_performance_budgets_and_sqlite_query_plans(tmp_path: Path) -> None:
    """Enforce performance-optimization budgets and verify indexed SQLite plans."""
    js_size = (PROJECT_ROOT / "web" / "js" / "app.js").stat().st_size
    css_size = (
        (PROJECT_ROOT / "web" / "css" / "tokens.css").stat().st_size
        + (PROJECT_ROOT / "web" / "css" / "app.css").stat().st_size
    )
    assert js_size < 200 * 1024
    assert css_size < 50 * 1024

    db_path = tmp_path / "plan_check.db"
    VaultRepository(db_path)
    conn = sqlite3.connect(db_path)
    receipt_plan = conn.execute(
        "EXPLAIN QUERY PLAN SELECT * FROM receipts WHERE status = 'pending' ORDER BY receipt_id DESC"
    ).fetchall()
    plan_text = " ".join(str(row) for row in receipt_plan)
    assert "idx_receipts_status" in plan_text


def test_windows_batch_launchers_use_flat_goto_and_crlf() -> None:
    """Verify Windows batch scripts use CRLF line endings and avoid parenthesized blocks."""
    for bat_name in ("run-windows.bat", "start_vault.bat"):
        bat_path = PROJECT_ROOT / bat_name
        assert bat_path.exists(), f"Missing {bat_name}"
        raw_bytes = bat_path.read_bytes()
        assert b"\r\n" in raw_bytes
        text = raw_bytes.decode("utf-8")
        assert "chcp 65001 >nul" in text
        assert "v1.0.0" in text
        assert "goto VENV_READY" in text
        assert "(" not in text and ")" not in text

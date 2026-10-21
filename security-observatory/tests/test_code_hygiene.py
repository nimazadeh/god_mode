"""Repository-wide Clean Code, Windows batch syntax, and zero-forbidden-token checks."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_SUBSTRINGS = (
    "inner" + "HTML",
    "ev" + "al",
    "!impor" + "tant",
    "variant" + "Names",
)

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".css",
    ".html",
    ".md",
    ".bat",
    ".ini",
    ".txt",
}


def test_zero_forbidden_substrings_across_entire_project() -> None:
    violations: list[str] = []
    for path in sorted(PROJECT_ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        if any(part.startswith(".") or part == "__pycache__" for part in path.parts):
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for token in FORBIDDEN_SUBSTRINGS:
            if token in content:
                violations.append(f"{path.relative_to(PROJECT_ROOT)} -> {token}")
    assert violations == []


def test_windows_batch_files_avoid_parenthesized_if_blocks() -> None:
    bat_files = list(PROJECT_ROOT.glob("*.bat"))
    assert len(bat_files) >= 2
    for bat_path in bat_files:
        text = bat_path.read_text(encoding="utf-8")
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            assert not stripped.endswith("("), f"Parenthesized block in {bat_path.name}"
            assert stripped != ")", f"Closing parenthesis block in {bat_path.name}"


def test_frontend_clipboard_promises_attach_catch_handler() -> None:
    js_text = (PROJECT_ROOT / "web" / "js" / "app.js").read_text(encoding="utf-8")
    assert "writeText(" in js_text
    assert ".catch(function () {})" in js_text

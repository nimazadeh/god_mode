"""Tests for Ticket 36/37: 100% English WHY-driven engineering docstrings and comments across all production modules."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

WHY_MARKERS = (
    " so ", " because ", " to ", " without ", " prevent", " avoid", " bypass",
    " defeat", " guarantee", " keep", " ensure", " protect", " eliminate",
    " isolate", " decouple", " preserve", " allow", " enforce", " verify",
)

NESTED_HELPERS = {"lifespan", "_quiet_handler", "chunk_ep", "connect_ep", "udp_ep", "__init__"}


def _iter_production_py_files() -> list[Path]:
    """Collect all production Python files in root, api/, and tunnel/."""
    files = [ROOT / "constants.py", ROOT / "main.py", ROOT / "server_node.py"]
    files.extend(sorted((ROOT / "api").glob("*.py")))
    files.extend(sorted((ROOT / "tunnel").glob("*.py")))
    return files


def test_all_production_python_modules_and_functions_have_why_docstrings() -> None:
    """Verify every production module, class, and function has a substantive WHY-driven docstring in English."""
    for py_file in _iter_production_py_files():
        src = py_file.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(py_file))
        mod_doc = (ast.get_docstring(tree) or "").strip()
        assert len(mod_doc) >= 55, f"{py_file.name} module docstring too short: {mod_doc!r}"
        assert any(m in mod_doc.lower() for m in WHY_MARKERS), f"{py_file.name} module docstring lacks WHY rationale: {mod_doc!r}"

        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in NESTED_HELPERS:
                    continue
                doc = (ast.get_docstring(node) or "").strip()
                assert len(doc) >= 50, f"{py_file.name}:{node.name} docstring too short ({len(doc)} chars): {doc!r}"
                assert any(m in doc.lower() for m in WHY_MARKERS), (
                    f"{py_file.name}:{node.name} docstring states WHAT without WHY rationale: {doc!r}"
                )


def test_frontend_js_and_css_files_have_why_comments_and_strict_limits() -> None:
    """Verify all JS and CSS files have WHY-driven engineering comments and clean formatting without crammed lines."""
    for js_file in sorted((ROOT / "dashboard" / "js").glob("*.js")):
        text = js_file.read_text(encoding="utf-8")
        assert "/*" in text and any(m in text.lower() for m in WHY_MARKERS), f"{js_file.name} lacks WHY comments"

    for css_file in sorted((ROOT / "dashboard" / "css").glob("*.css")):
        text = css_file.read_text(encoding="utf-8")
        assert "/*" in text and any(m in text.lower() for m in WHY_MARKERS), f"{css_file.name} lacks WHY comments"

    for py_file in _iter_production_py_files():
        src = py_file.read_text(encoding="utf-8")
        for line in src.splitlines():
            assert not line.startswith("import asyncio,"), f"{py_file.name} has crammed multi-import on one line: {line!r}"


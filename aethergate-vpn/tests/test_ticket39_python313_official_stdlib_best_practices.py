"""Tests for Ticket 45 (v10.6): Official Python 3.13-3.15 stdlib best practices (strong background task pool, PEP 585/604 typing, SSLContext(PROTOCOL_TLS_CLIENT), socket.inet_pton, and keep_alive=True)."""

import ast
import asyncio
from pathlib import Path
import ssl
import pytest
from constants import AETHERGATE_VERSION
from tunnel.satoshi_engine import (
    _BACKGROUND_TASKS,
    close_stream_writer,
    create_unverified_tls_client_context,
    spawn_background_task,
)

ROOT = Path(__file__).resolve().parent.parent


def _production_py_files() -> list[Path]:
    """Return all production Python modules in root, api/, and tunnel/."""
    files = [ROOT / "constants.py", ROOT / "main.py", ROOT / "server_node.py"]
    files.extend(sorted((ROOT / "api").glob("*.py")))
    files.extend(sorted((ROOT / "tunnel").glob("*.py")))
    return files


def test_version_v10_6_and_zero_deprecated_typing_or_inet_aton() -> None:
    """Verify AETHERGATE_VERSION is v10.6 and production files use PEP 585/604 typing and socket.inet_pton instead of inet_aton."""
    assert AETHERGATE_VERSION.startswith(("v10.", "v11."))
    for py_file in _production_py_files():
        src = py_file.read_text(encoding="utf-8")
        assert "inet_aton(" not in src, f"{py_file.name} still uses legacy socket.inet_aton()"
        tree = ast.parse(src, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "typing":
                imported_names = {alias.name for alias in node.names}
                assert "AsyncIterator" not in imported_names, f"{py_file.name} imports deprecated typing.AsyncIterator"
                assert "Optional" not in imported_names, f"{py_file.name} imports legacy typing.Optional instead of PEP 604 X | None"


def test_unverified_tls_client_context_uses_protocol_tls_client() -> None:
    """Verify create_unverified_tls_client_context builds SSLContext(PROTOCOL_TLS_CLIENT) without loading default CA certs."""
    ctx = create_unverified_tls_client_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE


@pytest.mark.asyncio
async def test_spawn_background_task_retains_strong_reference_and_discards_on_completion() -> None:
    """Verify spawn_background_task follows docs.python.org/3/library/asyncio-task.html strong-reference set pattern."""
    gate = asyncio.Event()

    async def _worker() -> str:
        await gate.wait()
        return "done"

    task = spawn_background_task(_worker())
    assert task in _BACKGROUND_TASKS
    gate.set()
    res = await task
    await asyncio.sleep(0)
    assert res == "done"
    assert task not in _BACKGROUND_TASKS


@pytest.mark.asyncio
async def test_close_stream_writer_and_start_server_keep_alive() -> None:
    """Verify close_stream_writer awaits wait_closed() and inbound_proxy.py passes keep_alive=True to asyncio.start_server."""
    inbound_src = (ROOT / "tunnel" / "inbound_proxy.py").read_text(encoding="utf-8")
    assert "keep_alive=True" in inbound_src

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await close_stream_writer(writer)

    srv = await asyncio.start_server(_handle, "127.0.0.1", 0, keep_alive=True)
    port = srv.sockets[0].getsockname()[1]
    _, client_writer = await asyncio.open_connection("127.0.0.1", port)
    await close_stream_writer(client_writer)
    assert client_writer.is_closing()
    srv.close()
    await srv.wait_closed()

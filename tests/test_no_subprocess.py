"""The package must never shell out.

This is the reason ``spyglass-lite`` exists: upstream Spyglass calls Sherlock,
Maigret and Holehe as subprocesses, which means a Go binary, a pipx install and
a shell on PATH before the first lookup. A single stray ``subprocess`` import
would quietly reintroduce that dependency, so it is asserted, not documented.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import spyglass_lite

SRC = Path(spyglass_lite.__file__).parent
FORBIDDEN_MODULES = {
    "subprocess",
    "pty",
    "pexpect",
    "shlex",  # only useful for building shell command lines
}
FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "spawnv"),
}
ALLOWED_THIRD_PARTY = {"httpx", "dns", "phonenumbers"}


def _modules() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_there_are_sources():
    assert len(_modules()) > 5


def test_no_forbidden_imports():
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                assert name not in FORBIDDEN_MODULES, f"{path.name} imports {name}"


def test_no_shelling_out_through_os():
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            owner = node.func.value
            if isinstance(owner, ast.Name):
                assert (owner.id, node.func.attr) not in FORBIDDEN_CALLS, (
                    f"{path.name} calls {owner.id}.{node.func.attr}"
                )


def test_no_dynamic_imports():
    """``__import__`` would defeat the import allow-list below."""
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "__import__", f"{path.name} uses __import__"


def test_dependencies_are_exactly_what_the_metadata_promises():
    """Every third-party import must be a declared dependency."""
    allowed = ALLOWED_THIRD_PARTY | set(sys.stdlib_module_names) | {"spyglass_lite"}
    seen: set[str] = set()

    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                seen.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                seen.add(node.module.split(".")[0])

    unexpected = {name for name in seen if name and name not in allowed}
    assert not unexpected, f"undeclared third-party imports: {sorted(unexpected)}"


def test_no_network_at_import_time():
    """Importing the package must not perform I/O.

    Run in a child interpreter: purging ``sys.modules`` in-process would
    hand the rest of the session a second copy of every module.
    """
    probe = """
import socket

def deny(*args, **kwargs):
    raise SystemExit("network access during import")

socket.socket.connect = deny
socket.create_connection = deny
socket.getaddrinfo = deny

import spyglass_lite
print("ok")
"""
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_no_bundled_binaries():
    allowed = {".py", ".json", ".gz", ".typed", ".txt", ".md"}
    for path in SRC.rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts:
            assert path.suffix in allowed, f"unexpected artefact in package: {path}"

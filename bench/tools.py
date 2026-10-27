"""Runners for every engine in the comparison.

Each runner returns the same shape — a stable ``ToolRun`` — so the scorer
never needs to know which tool produced a claim. Containment of the command
lines here is deliberate: this is the only place in the repository that is
allowed to shell out, and it is not part of the shipped package.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent

# A checkout of upstream Spyglass, for the field-parity harness. Never commit
# an absolute path here: it makes the benchmark unusable on every machine but
# the one it was written on, and on every OS but that one.
UPSTREAM = Path(os.environ.get("SPYGLASS_UPSTREAM") or ROOT.parent / ".upstream")

SHERLOCK_LINE = re.compile(r"^\[\+\]\s+(?P<name>.+?):\s+(?P<url>https?://\S+)", re.M)
URL = re.compile(r"https?://[^\s<>\"']+")


def domain_of(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


@dataclass
class ToolRun:
    tool: str
    handle: str
    found: dict[str, str] = field(default_factory=dict)
    unknown: dict[str, str] = field(default_factory=dict)
    checked: int | None = None
    skipped: int | None = None
    seconds: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "handle": self.handle,
            "found": self.found,
            "unknown": self.unknown,
            "checked": self.checked,
            "skipped": self.skipped,
            "seconds": round(self.seconds, 2),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolRun:
        return cls(**data)


# ─── lite ─────────────────────────────────────────────────


def _absorb(result, tool: str, seconds: float) -> ToolRun:
    found = {domain_of(profile.url): profile.url for profile in result.found}
    # Unknown.domain is already a bare domain, not a URL.
    unknown = {
        (item.domain or "").lower().removeprefix("www."): item.reason
        for item in result.unknown
        if item.domain
    }
    return ToolRun(
        tool=tool,
        handle=result.target,
        found=found,
        unknown=unknown,
        checked=result.checked,
        skipped=result.skipped,
        seconds=seconds,
    )


def run_lite(handle: str, *, strict: bool = True, limit: int | None = None) -> ToolRun:
    from spyglass_lite import Spyglass

    tool = "lite" if strict else "lite-raw"
    started = time.perf_counter()
    try:
        # The benchmark's fairness contract gives every engine the same
        # per-request timeout, so it must not inherit the library default:
        # a benchmark measures the engine, not the current default knob.
        result = Spyglass(timeout=15).username(
            handle,
            strict=strict,
            limit=limit,
            # Raw mode means the dataset rule and nothing else, including the
            # catch-all probe, so it is comparable to Sherlock's output.
            verify_catchall=strict,
        )
    except Exception as exc:
        return ToolRun(tool=tool, handle=handle, error=f"{type(exc).__name__}: {exc}")
    return _absorb(result, tool, time.perf_counter() - started)


# ─── sherlock ─────────────────────────────────────────────


def run_sherlock(handle: str, *, timeout: int = 15) -> ToolRun:
    started = time.perf_counter()
    binary = shutil.which("sherlock")
    if not binary:
        return ToolRun("sherlock", handle, error="sherlock not on PATH")

    try:
        proc = subprocess.run(
            [
                binary,
                handle,
                "--print-found",
                "--no-color",
                "--timeout",
                str(timeout),
            ],
            capture_output=True,
            text=True,
            timeout=timeout * 6 + 120,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except subprocess.TimeoutExpired:
        return ToolRun("sherlock", handle, error="timeout", seconds=time.perf_counter() - started)

    found: dict[str, str] = {}
    for match in SHERLOCK_LINE.finditer(proc.stdout):
        url = match.group("url").rstrip(".,)")
        found.setdefault(domain_of(url), url)

    return ToolRun(
        "sherlock",
        handle,
        found=found,
        seconds=time.perf_counter() - started,
        error="" if proc.returncode == 0 else f"exit {proc.returncode}",
    )


# ─── maigret ──────────────────────────────────────────────


def run_maigret(handle: str, *, timeout: int = 15, top_sites: int = 1000) -> ToolRun:
    started = time.perf_counter()
    binary = shutil.which("maigret")
    if not binary:
        return ToolRun("maigret", handle, error="maigret not on PATH")

    with tempfile.TemporaryDirectory(prefix="sg-bench-maigret-") as tmp:
        try:
            proc = subprocess.run(
                [
                    binary,
                    handle,
                    "--no-progressbar",
                    "--no-color",
                    "--no-recursion",
                    "--no-extracting",
                    "--no-autoupdate",
                    "--timeout",
                    str(timeout),
                    "--top-sites",
                    str(top_sites),
                    "-J",
                    "simple",
                    "-fo",
                    tmp,
                ],
                capture_output=True,
                text=True,
                timeout=max(600, top_sites // 2),
                env={**os.environ, "NO_COLOR": "1"},
            )
        except subprocess.TimeoutExpired:
            return ToolRun(
                "maigret", handle, error="timeout", seconds=time.perf_counter() - started
            )

        report = Path(tmp) / f"report_{handle}_simple.json"
        found: dict[str, str] = {}
        unknown: dict[str, str] = {}
        if report.exists():
            data = json.loads(report.read_text())
            for _key, entry in data.items():
                status = entry.get("status", {})
                url = status.get("url") or entry.get("url_user") or ""
                if not url:
                    continue
                if status.get("status") == "Claimed":
                    found.setdefault(domain_of(url), url)
                elif status.get("status") == "Unknown":
                    unknown.setdefault(domain_of(url), "maigret unknown")
        else:
            for url in URL.findall(proc.stdout):
                found.setdefault(domain_of(url), url)

    return ToolRun(
        "maigret",
        handle,
        found=found,
        unknown=unknown,
        seconds=time.perf_counter() - started,
        error="" if proc.returncode == 0 else f"exit {proc.returncode}",
    )


# ─── upstream Spyglass ────────────────────────────────────


def run_upstream(handle: str, *, timeout: int = 900) -> ToolRun:
    """Run the real ``spyglass.username.username`` in its own process.

    It shells out to user-scanner, Sherlock, Maigret and Blackbird and then
    re-verifies every candidate, so it needs a long leash. The child prints
    one JSON document; nothing it writes to stdout otherwise is parsed.
    """
    started = time.perf_counter()
    runner = Path(__file__).with_name("_upstream_runner.py")
    try:
        proc = subprocess.run(
            [sys.executable, str(runner), handle],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "PYTHONPATH": str(UPSTREAM), "NO_COLOR": "1"},
        )
    except subprocess.TimeoutExpired:
        return ToolRun("spyglass", handle, error="timeout", seconds=time.perf_counter() - started)

    marker = "---SGJSON---"
    payload = ""
    if marker in proc.stdout:
        payload = proc.stdout.split(marker, 1)[1]
    elif proc.stdout.lstrip().startswith("{"):
        payload = proc.stdout

    if not payload.strip():
        return ToolRun(
            "spyglass",
            handle,
            error=(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "no output")[
                :200
            ],
            seconds=time.perf_counter() - started,
        )

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        return ToolRun(
            "spyglass",
            handle,
            error=f"bad json: {exc}",
            seconds=time.perf_counter() - started,
        )

    found: dict[str, str] = {}
    for key, value in data.items():
        if key in {"breach", "rejected", "details", "candidates", "verdict"}:
            continue
        if not isinstance(value, list):
            continue
        for item in value:
            url = item.get("url", "")
            if url:
                found.setdefault(domain_of(url), url)

    rejected = data.get("rejected", {})
    unknown = {
        domain_of(url): reason for url, reason in rejected.items() if isinstance(reason, str)
    }
    return ToolRun(
        "spyglass",
        handle,
        found=found,
        unknown=unknown,
        checked=data.get("candidates"),
        seconds=time.perf_counter() - started,
    )


# ─── coverage ─────────────────────────────────────────────


def site_domains(tool: str) -> set[str]:
    """Domains each engine's own database claims to cover."""
    if tool.startswith("lite"):
        from spyglass_lite import _registry

        return {domain_of(f"https://{site['domain']}/") for site in _registry.sites()}

    if tool == "sherlock":
        return _domains_from_data(_data_file("sherlock", "sherlock_project"))

    if tool == "maigret":
        return _domains_from_data(_data_file("maigret", "maigret"))

    if tool == "spyglass":
        return site_domains("sherlock") | site_domains("maigret")

    return set()


def _data_file(tool: str, package: str) -> Path | None:
    """Locate a tool's database without importing it.

    The CLIs are usually installed for a different interpreter (pipx, system
    Python), so ``import`` is not reliable from the benchmark's venv.
    """
    try:
        module = __import__(package)
        candidate = Path(module.__file__).parent / "resources" / "data.json"
        if candidate.exists():
            return candidate
    except ImportError:
        pass

    binary = shutil.which(tool)
    if not binary:
        return None
    root = Path(binary).resolve().parent.parent
    for candidate in root.glob(f"lib/python*/site-packages/{package}/resources/data.json"):
        return candidate
    return None


def _domains_from_data(path: Path | None) -> set[str]:
    if path is None:
        return set()
    data = json.loads(path.read_text())
    entries = data.get("sites", data) if isinstance(data, dict) else {}
    domains = set()
    for entry in entries.values():
        if not isinstance(entry, dict):
            continue
        url = entry.get("urlMain") or entry.get("url") or ""
        domain = domain_of(url) if url.startswith("http") else ""
        if domain:
            domains.add(domain)
    return domains


async def run_lite_async(handle: str, *, strict: bool, limit: int | None) -> ToolRun:
    """In-process lite run, kept async so the benchmark can share a loop."""
    return run_lite(handle, strict=strict, limit=limit)


def run_many(runner, handles, **kwargs) -> list[ToolRun]:
    with contextlib.suppress(KeyboardInterrupt):
        return [runner(handle, **kwargs) for handle in handles]
    return []

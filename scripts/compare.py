#!/usr/bin/env python3
"""spyglass-lite vs Sherlock vs user-scanner on two handles.

    .venv/bin/python scripts/compare.py           # run all three engines live
    .venv/bin/python scripts/compare.py --reuse   # re-run lite only, reusing
                                                 # the sherlock/user-scanner
                                                 # results saved in
                                                 # compare_results.txt

Every engine x handle job runs in its own worker thread, so all scans happen
at once and wall time is whatever the single slowest engine takes. lite
itself is async internally (50 requests in flight, per-host capped), so the
two lite scans together never exceed 4 requests per host.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import spyglass_lite as sg

HANDLES = ["teamleader", "teamleaderistrue"]
ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "compare_results.txt"
REUSED_TOOLS = ("sherlock", "user-scanner")
SHERLOCK_TIMEOUT = 600  # seconds per handle
USER_SCANNER_TIMEOUT = 900  # seconds per handle

SHERLOCK_LINE = re.compile(r"^\[\+\]\s+(?P<name>.+?):\s+(?P<url>https?://\S+)", re.M)
USER_SCANNER_HIT = re.compile(r"\[[✔✓]\]\s+(?P<name>.+?)\s+\[(?P<url>https?://[^\]]+)\]")


def domain_of(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def say(msg: str) -> None:
    print(msg, flush=True)


# ── engines ────────────────────────────────────────────────────────────


def run_lite(handle: str) -> dict:
    started = time.perf_counter()
    try:
        result = sg.Spyglass().username(handle)
    except Exception as exc:  # one engine failing must not kill the comparison
        return {"error": f"{type(exc).__name__}: {exc}", "found": {}, "seconds": 0.0}
    return {
        "found": {domain_of(p.url): p.url for p in result.found},
        "unknown": len(result.unknown),
        "checked": result.checked,
        "errors": len(result.errors),
        "seconds": time.perf_counter() - started,
    }


def run_sherlock(handle: str) -> dict:
    if not shutil.which("sherlock"):
        return {"error": "sherlock not on PATH", "found": {}, "seconds": 0.0}
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            ["sherlock", handle, "--print-found", "--no-color", "--timeout", "30"],
            capture_output=True,
            text=True,
            timeout=SHERLOCK_TIMEOUT,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "found": {}, "seconds": time.perf_counter() - started}

    found: dict[str, str] = {}
    for match in SHERLOCK_LINE.finditer(proc.stdout):
        url = match.group("url").rstrip(".,)")
        found.setdefault(domain_of(url), url)
    error = "" if proc.returncode == 0 else f"exit {proc.returncode}"
    return {"found": found, "error": error, "seconds": time.perf_counter() - started}


def run_user_scanner(handle: str) -> dict:
    if not shutil.which("user-scanner"):
        return {"error": "user-scanner not on PATH", "found": {}, "seconds": 0.0}
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="sg-compare-us-") as tmp:
        out = f"{tmp}/{handle}.json"
        try:
            # "d" answers its interactive update prompt with "don't ask again".
            proc = subprocess.run(
                ["user-scanner", "-u", handle, "-f", "json", "-o", out, "--only-found"],
                input="d\n",
                capture_output=True,
                text=True,
                timeout=USER_SCANNER_TIMEOUT,
                env={**os.environ, "NO_COLOR": "1"},
            )
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "found": {}, "seconds": time.perf_counter() - started}

        found: dict[str, str] = {}
        try:
            with open(out, encoding="utf-8") as report_file:
                entries = json.loads(report_file.read())
        except (OSError, ValueError):
            entries = None

        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and entry.get("status") == "Found":
                    url = str(entry.get("url") or "")
                    if url:
                        found.setdefault(domain_of(url), url)
        else:  # no JSON file (zero hits?) — fall back to the console lines
            for match in USER_SCANNER_HIT.finditer(proc.stdout):
                url = match.group("url")
                found.setdefault(domain_of(url), url)

        error = "" if proc.returncode == 0 else f"exit {proc.returncode}"
        return {"found": found, "error": error, "seconds": time.perf_counter() - started}


ENGINES = [
    ("spyglass-lite", run_lite),
    ("sherlock", run_sherlock),
    ("user-scanner", run_user_scanner),
]
ENGINE_BY_NAME = dict(ENGINES)


# ── reusing an earlier report ───────────────────────────────────────────

_TOOL_HEADER = re.compile(r"^  (?P<name>[a-z0-9-]+): \d+ found\s+\((?P<seconds>[\d.]+)s\)")
_HANDLE_HEADER = re.compile(r"^  (?P<handle>[A-Za-z0-9_-]+)$")
_DOMAIN_LINE = re.compile(r"^ {6}(?P<domain>\S+)\s+(?P<url>https?://\S+)\s*$")


def parse_previous(path: str | Path) -> dict[str, dict[str, dict]]:
    """Recover {handle: {tool: {found, seconds}}} from an old report file."""
    previous: dict[str, dict[str, dict]] = {}
    handle: str | None = None
    tool: str | None = None

    try:
        with open(path, encoding="utf-8") as report_file:
            lines = report_file.read().splitlines()
    except OSError:
        return previous

    for line in lines:
        if match := _HANDLE_HEADER.match(line):
            handle = match.group("handle")
            previous.setdefault(handle, {})
            tool = None
            continue
        if match := _TOOL_HEADER.match(line):
            if handle and match.group("name") in REUSED_TOOLS:
                tool = match.group("name")
                previous[handle][tool] = {
                    "found": {},
                    "seconds": float(match.group("seconds")),
                }
            else:
                tool = None
            continue
        if line.startswith("      "):
            if tool and (match := _DOMAIN_LINE.match(line)):
                previous[handle][tool]["found"].setdefault(
                    domain_of(match.group("url")), match.group("url")
                )
            continue
        # Any other indented header (the comparison block) ends the section.
        if line.startswith("  "):
            tool = None
    return previous


# ── reporting ──────────────────────────────────────────────────────────


def report(handle: str, results: dict[str, dict]) -> None:
    say("")
    say("=" * 72)
    say(f"  {handle}")
    say("=" * 72)
    for name, data in results.items():
        found = data["found"]
        note = data.get("error") or ""
        say(
            f"\n  {name}: {len(found)} found  ({data['seconds']:.1f}s)"
            + (f"  [{note}]" if note else "")
        )
        if "unknown" in data:
            say(
                f"      unknown={data['unknown']} checked={data['checked']} errors={data['errors']}"
            )
        for domain in sorted(found):
            say(f"      {domain:<28} {found[domain]}")

    sets = {name: set(data["found"]) for name, data in results.items()}
    all_three = set.intersection(*sets.values())
    say("\n  --- comparison ---")
    say(f"  found by all three: {len(all_three)}")
    for domain in sorted(all_three):
        say(f"      {domain}")

    for name, domains in sets.items():
        others = set().union(*(d for other, d in sets.items() if other != name))
        unique = domains - others
        say(f"  only {name} found ({len(unique)}): {', '.join(sorted(unique)) or '—'}")

    union = set().union(*sets.values())
    say(f"  union of all engines: {len(union)} unique domains")


def main() -> int:
    reuse = "--reuse" in sys.argv[1:]
    results: dict[str, dict[str, dict]] = {handle: {} for handle in HANDLES}
    jobs: list[tuple[str, str, Callable[..., dict]]] = []

    if reuse:
        previous = parse_previous(REPORT_PATH)
        for handle in HANDLES:
            for tool in REUSED_TOOLS:
                data = previous.get(handle, {}).get(tool)
                if data is not None:
                    results[handle][tool] = data
                    print(
                        f"[{handle}] reusing saved {tool}: {len(data['found'])} found "
                        f"({data['seconds']:.1f}s)"
                    )
                else:
                    print(f"[{handle}] no saved {tool} result — running live")

    for handle in HANDLES:
        for name, engine in ENGINES:
            if name not in results[handle]:
                jobs.append((handle, name, engine))

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        pending = {}
        for handle, name, engine in jobs:
            say(f"[{handle}] running {name} ...")
            pending[pool.submit(engine, handle)] = (handle, name)

        for future in as_completed(pending):
            handle, name = pending[future]
            data = future.result()
            results[handle][name] = data
            if data.get("error"):
                say(f"[{handle}] {name}: ERROR {data['error']}")
            else:
                say(f"[{handle}] {name}: {len(data['found'])} found ({data['seconds']:.1f}s)")

    for handle, per_tool in results.items():
        report(handle, per_tool)

    say("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Benchmark spyglass-lite against the tools it replaces.

    python -m bench.run                       # cached, fast
    python -m bench.run --refresh             # fresh oracles + tool runs
    python -m bench.run --tools lite,sherlock # subset
    python -m bench.run --handles torvalds,simonw --lite-limit 400

Artifacts land in ``bench/results/``: a Markdown report, the raw JSON, and the
oracle matrix it was scored against.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from .oracles import ORACLES, matrix
from .score import Score, false_positives, misses, score_run, table
from .tools import ToolRun, run_lite, run_maigret, run_sherlock, run_upstream, site_domains

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / ".cache"
RESULTS = ROOT / "results"

DEFAULT_HANDLES = [
    "torvalds",
    "sindresorhus",
    "jessfraz",
    "simonw",
    "zq9x7v3k2m1p",
    "n0trealuser8x7q",
]

ALL_TOOLS = ["lite", "lite-raw", "sherlock", "maigret", "spyglass"]


def load_cache(name: str, refresh: bool):
    path = CACHE / name
    if refresh or not path.exists():
        return None
    return json.loads(path.read_text())


def save_cache(name: str, payload) -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    (CACHE / name).write_text(json.dumps(payload, indent=1))


def cached_oracle(handles: list[str], refresh: bool) -> dict[str, dict[str, bool | None]]:
    payload = load_cache("oracles.json", refresh) or {}
    missing = [handle for handle in handles if handle not in payload]
    if missing:
        print(f"probing {len(missing)} handle(s) against {len(ORACLES)} oracles")
        payload.update(asyncio.run(matrix(missing)))
        save_cache("oracles.json", payload)
    return {handle: payload[handle] for handle in handles}


def run_tool(tool: str, handle: str, args, refresh: bool) -> ToolRun:
    suffix = f"-limit{args.lite_limit}" if args.lite_limit else ""
    cache_name = f"{tool}-{handle}{suffix}.json"
    cached = load_cache(cache_name, refresh)
    if cached is not None:
        return ToolRun.from_dict(cached)

    print(f"  running {tool:9} on {handle}", flush=True)
    started = time.perf_counter()

    if tool == "lite":
        run = run_lite(handle, strict=True, limit=args.lite_limit)
    elif tool == "lite-raw":
        run = run_lite(handle, strict=False, limit=args.lite_limit)
    elif tool == "sherlock":
        run = run_sherlock(handle, timeout=args.timeout)
    elif tool == "maigret":
        run = run_maigret(handle, timeout=args.timeout, top_sites=args.maigret_top)
    elif tool == "spyglass":
        run = run_upstream(handle, timeout=args.upstream_timeout)
    else:
        raise SystemExit(f"unknown tool {tool!r}")

    run.seconds = time.perf_counter() - started
    save_cache(cache_name, run.to_dict())
    print(
        f"    {len(run.found):3} found, {len(run.unknown):3} unknown"
        f" in {run.seconds:.1f}s" + (f"  [{run.error}]" if run.error else ""),
        flush=True,
    )
    return run


def coverage(oracle_rows: dict[str, dict[str, bool | None]]) -> dict[str, int]:
    """How many oracle domains each engine's database actually covers."""
    domains = {domain for row in oracle_rows.values() for domain in row}
    out: dict[str, int] = {}
    for tool in ("lite", "sherlock", "maigret"):
        out[tool] = len(site_domains(tool) & domains)
    out["spyglass"] = len((site_domains("sherlock") | site_domains("maigret")) & domains)
    return out


def lite_only(
    runs: dict[str, dict[str, ToolRun]], handles: list[str]
) -> list[tuple[str, str, str, str]]:
    """(handle, domain, url, oracle verdict) for claims only lite makes."""
    others = ("sherlock", "maigret", "spyglass")
    rows: list[tuple[str, str, str, str]] = []
    for handle in handles:
        claimed_elsewhere: set[str] = set()
        for tool in others:
            run = runs.get(tool, {}).get(handle)
            if run is None:
                # The tool was not part of this invocation; its cached run is
                # still valid evidence about corroboration.
                cached = load_cache(f"{tool}-{handle}.json", refresh=False)
                if cached:
                    run = ToolRun.from_dict(cached)
            if run:
                claimed_elsewhere |= set(run.found)
        run = runs.get("lite", {}).get(handle)
        if not run:
            continue
        for domain, url in sorted(run.found.items()):
            if domain not in claimed_elsewhere:
                rows.append((handle, domain, url, ""))
    return rows


def corroboration(runs: dict[str, dict[str, ToolRun]], handles: list[str]) -> tuple[int, int]:
    """How many lite claims are independently made by another engine."""
    total = corroborated = 0
    for handle in handles:
        lite_run = runs.get("lite", {}).get(handle)
        if not lite_run:
            continue
        other_claims: set[str] = set()
        for tool in ("sherlock", "maigret", "spyglass"):
            run = runs.get(tool, {}).get(handle)
            if run is None:
                cached = load_cache(f"{tool}-{handle}.json", refresh=False)
                run = ToolRun.from_dict(cached) if cached else None
            if run:
                other_claims |= set(run.found)
        total += len(lite_run.found)
        corroborated += sum(1 for domain in lite_run.found if domain in other_claims)
    return corroborated, total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handles", default=",".join(DEFAULT_HANDLES))
    parser.add_argument("--tools", default=",".join(ALL_TOOLS))
    parser.add_argument("--refresh", action="store_true", help="ignore every cache")
    parser.add_argument("--lite-limit", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=15, help="per-request, sherlock/maigret")
    parser.add_argument("--maigret-top", type=int, default=1000)
    parser.add_argument("--upstream-timeout", type=int, default=900)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    handles = [h.strip() for h in args.handles.split(",") if h.strip()]
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    for tool in tools:
        if tool not in ALL_TOOLS:
            raise SystemExit(f"unknown tool {tool!r}; choose from {ALL_TOOLS}")

    started = time.perf_counter()
    oracle_rows = cached_oracle(handles, args.refresh)

    runs: dict[str, dict[str, ToolRun]] = {}
    for tool in tools:
        runs[tool] = {}
        for handle in handles:
            run = run_tool(tool, handle, args, args.refresh)
            runs[tool][handle] = run

    rows: list[Score] = []
    for tool in tools:
        for handle in handles:
            rows.append(score_run(runs[tool][handle], oracle_rows[handle]))

    totals: list[Score] = []
    for tool in tools:
        total = Score(tool=tool, handle="all")
        for row in rows:
            if row.tool == tool:
                total = total.merge(row)
        totals.append(total)

    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    elapsed = time.perf_counter() - started

    sections: list[str] = [
        "# spyglass-lite benchmark",
        "",
        f"Generated {stamp} · {len(handles)} handle(s) · {len(ORACLES)} oracles",
        "",
        "`unknown*` counts oracle-confirmed accounts the tool reported as "
        "unreachable rather than absent. `unscored` counts claims outside the "
        "oracle set (real sites, but not independently verified here).",
        "",
        "## Aggregate",
        "",
        table(totals),
        "",
        "## Per handle",
        "",
        table(rows),
        "",
    ]

    coverage_line = coverage(oracle_rows)
    sections += [
        "## Oracle-domain coverage",
        "",
        "| engine | oracle domains in its database |",
        "|---|---:|",
        *[f"| {tool} | {count}/{len(ORACLES)} |" for tool, count in coverage_line.items()],
        "",
    ]

    sections += ["## False positives vs oracle", ""]
    any_fp = False
    for tool in tools:
        for handle in handles:
            hits = false_positives(runs[tool][handle], oracle_rows[handle])
            if hits:
                any_fp = True
                sections.append(
                    f"- **{tool} / {handle}**: " + ", ".join(f"`{domain}`" for domain, _ in hits)
                )
    if not any_fp:
        sections.append("None.")

    sections += ["", "## Oracle-confirmed accounts missed", ""]
    for tool in tools:
        missed = {handle: misses(runs[tool][handle], oracle_rows[handle]) for handle in handles}
        missed = {handle: domains for handle, domains in missed.items() if domains}
        if missed:
            sections.append(f"- **{tool}**:")
            for handle, domains in missed.items():
                sections.append(f"  - {handle}: " + ", ".join(f"`{d}`" for d in domains))
        else:
            sections.append(f"- **{tool}**: none")

    sections += ["", "## Claims only lite makes", ""]
    corroborated, total = corroboration(runs, handles)
    sections.append(
        f"lite claims corroborated by at least one other engine: "
        f"**{corroborated}/{total}** ({corroborated / total:.0%})."
        if total
        else "No lite runs."
    )
    sections.append("")
    unique = lite_only(runs, handles)
    if unique:
        sections.append("| handle | domain | url | oracle |")
        sections.append("|---|---|---|---|")
        for handle, domain, url, _ in unique:
            verdict = oracle_rows[handle].get(domain)
            label = "yes" if verdict else ("no" if verdict is False else "not scored")
            sections.append(f"| {handle} | {domain} | {url} | {label} |")
    else:
        sections.append("None — every lite claim was corroborated by another engine.")

    sections += [
        "",
        f"Wall clock for this invocation: {elapsed:.0f}s.",
        "",
        "Oracle probes are cached in `bench/.cache/`; tool runs are cached too. "
        "Pass `--refresh` to re-measure.",
        "",
    ]

    report = "\n".join(sections)
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = Path(args.out) if args.out else RESULTS / "report.md"
    out.write_text(report)
    (RESULTS / "raw.json").write_text(
        json.dumps(
            {
                "generated": stamp,
                "handles": handles,
                "tools": tools,
                "oracles": oracle_rows,
                "runs": {
                    tool: {h: run.to_dict() for h, run in by_handle.items()}
                    for tool, by_handle in runs.items()
                },
                "scores": [row.__dict__ for row in rows],
                "totals": [row.__dict__ for row in totals],
                "coverage": coverage_line,
                "lite_only": unique,
            },
            indent=1,
        )
    )

    print()
    print(table(totals))
    print(f"\nreport: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

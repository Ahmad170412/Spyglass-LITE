#!/usr/bin/env python3
"""Rebuild ``src/spyglass_lite/data/sites.json.gz``.

Sources (both MIT, see NOTICE):

  * Sherlock  — sherlock_project/resources/data.json
  * Maigret   — maigret/resources/data.json

The merge is intentionally conservative. For each domain it keeps **one**
rule set, not a blend: mixing Sherlock's URL with Maigret's presence strings
produces a rule that neither project tested. The richer rule wins, and a tie
goes to Sherlock because its 480 entries are the more battle-tested.

Usage:
    python scripts/build_sites.py            # use build/cache when present
    python scripts/build_sites.py --refresh  # re-download the sources
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "build" / "cache"
OUT = ROOT / "src" / "spyglass_lite" / "data" / "sites.json.gz"

# Sites whose human-facing HTML is bot-walled but whose own JSON API is not.
# A curated probe is a small, auditable exception to "trust the upstream
# rule": without it these profiles are always reported as blocked, and a
# blocked site is a hole in every scan. Only endpoints the site documents for
# anonymous reads are listed here.
OVERRIDES: dict[str, dict[str, Any]] = {
    "codeberg.org": {
        "probe": "https://codeberg.org/api/v1/users/{username}",
        "check": "status_code",
    },
    "lichess.org": {
        "probe": "https://lichess.org/api/user/{username}",
        "check": "status_code",
    },
    "mastodon.social": {
        "probe": "https://mastodon.social/api/v1/accounts/lookup?acct={username}",
        "check": "status_code",
        # The canonical page keeps the account's original capitalisation;
        # /@lowercase 410s even though the account exists.
        "profile_field": "url",
    },
}

SOURCES = {
    "sherlock": {
        "url": "https://raw.githubusercontent.com/sherlock-project/sherlock/master/"
        "sherlock_project/resources/data.json",
        "license": "MIT",
        "homepage": "https://github.com/sherlock-project/sherlock",
    },
    "maigret": {
        "url": "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json",
        "license": "MIT",
        "homepage": "https://github.com/soxoj/maigret",
    },
}

USER_AGENT = "spyglass-lite-build/1.0 (+https://github.com/Ahmad170412/Spyglass-OSINT)"


def download(name: str, refresh: bool) -> dict[str, Any]:
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"{name}.json"
    if refresh or not path.exists():
        request = urllib.request.Request(SOURCES[name]["url"], headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            path.write_bytes(response.read())
        print(f"  downloaded {name}: {path.stat().st_size / 1024:.0f} KiB")
    return json.loads(path.read_text(encoding="utf-8"))


def host_of(url: str) -> str:
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hostname = (urlparse(url).hostname or "").lower()
    # A subdomain template (``{username}.deviantart.com``) is not a domain.
    # Drop the templated labels so dedupe and the throttle key on the real
    # registrable host.
    labels = [label for label in hostname.split(".") if label and "{" not in label]
    hostname = ".".join(labels)
    return hostname[4:] if hostname.startswith("www.") else hostname


def placeholder(url: str) -> str:
    return url.replace("{}", "{username}")


def has_placeholder(url: str) -> bool:
    return "{username}" in url or "{}" in url


def clean_headers(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(key).lower(): str(value) for key, value in raw.items() if key and value}


def from_sherlock(name: str, raw: dict[str, Any]) -> dict[str, Any] | None:
    url = str(raw.get("url") or "")
    if not url.startswith(("http://", "https://")) or not has_placeholder(url):
        return None
    domain = host_of(url)
    if not domain:
        return None

    check = str(raw.get("errorType") or "status_code")
    absent = [str(raw["errorMsg"])] if raw.get("errorMsg") else []

    record = {
        "name": name,
        "domain": domain,
        "url": placeholder(url),
        "probe": placeholder(str(raw["urlProbe"])) if raw.get("urlProbe") else None,
        "method": str(raw.get("request_method") or "GET").upper(),
        "payload": raw.get("request_payload") or None,
        "headers": clean_headers(raw.get("headers")),
        "check": check,
        "present": [],
        "absent": absent,
        "absent_url": raw.get("errorUrl") or None,
        "regex": raw.get("regexCheck") or None,
        "ignore403": False,
        "errors": {},
        "protected": [],
        "tags": [],
        "sample": raw.get("username_claimed") or None,
        "source": ["sherlock"],
    }
    return record if valid(record) else None


def from_maigret(name: str, raw: dict[str, Any]) -> dict[str, Any] | None:
    if raw.get("disabled") or raw.get("engine"):
        return None
    url = str(raw.get("url") or "")
    if not url.startswith(("http://", "https://")) or not has_placeholder(url):
        return None
    domain = host_of(url)
    if not domain:
        return None

    record = {
        "name": name,
        "domain": domain,
        "url": placeholder(url),
        "probe": placeholder(str(raw["urlProbe"])) if raw.get("urlProbe") else None,
        "method": str(raw.get("requestMethod") or "GET").upper(),
        "payload": raw.get("requestPayload") or None,
        "headers": clean_headers(raw.get("headers")),
        "check": str(raw.get("checkType") or "status_code"),
        # Maigret spells it "presenseStrs"; keep the meaning, fix the key.
        "present": [str(s) for s in raw.get("presenseStrs") or [] if s],
        "absent": [str(s) for s in raw.get("absenceStrs") or [] if s],
        "absent_url": raw.get("errorUrl") or None,
        "regex": raw.get("regexCheck") or None,
        "ignore403": bool(raw.get("ignore403")),
        "errors": {str(k): str(v) for k, v in (raw.get("errors") or {}).items() if k and v},
        "protected": [str(p) for p in raw.get("protection") or [] if p],
        "tags": [str(t) for t in raw.get("tags") or [] if t],
        "sample": raw.get("usernameClaimed") or None,
        "rank": raw.get("alexaRank"),
        "source": ["maigret"],
    }
    return record if valid(record) else None


def valid(record: dict[str, Any]) -> bool:
    if record.get("check") not in {"status_code", "message", "response_url"}:
        return False
    if record["check"] != "message":
        return True
    # A "message" rule with no strings can never decide anything.
    return bool(record["present"] or record["absent"])


def specificity(record: dict[str, Any]) -> int:
    """How much evidence a rule can produce."""
    score = 0
    if record["present"] or record["absent"]:
        score += 3
    if record["probe"]:
        score += 2
    if record["check"] in {"message", "response_url"}:
        score += 1
    if record["errors"]:
        score += 1
    return score


def merge(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the strongest rule, then union the metadata."""
    primary = max(
        records,
        key=lambda r: (specificity(r), 1 if "sherlock" in r["source"] else 0),
    )
    merged = dict(primary)
    merged["errors"] = dict(primary.get("errors") or {})
    merged["source"] = sorted({source for r in records for source in r["source"]})
    merged["tags"] = sorted({tag for r in records for tag in r.get("tags", [])})
    merged["protected"] = sorted({p for r in records for p in r.get("protected", [])})
    merged["aliases"] = sorted({r["name"] for r in records if r["name"] != merged["name"]})
    merged["sample"] = merged.get("sample") or next(
        (r.get("sample") for r in records if r.get("sample")), None
    )
    merged["rank"] = min(
        (r.get("rank") for r in records if isinstance(r.get("rank"), int)),
        default=100_000,
    )
    for record in records:
        for marker, reason in record.get("errors", {}).items():
            merged["errors"].setdefault(marker, reason)
    return merged


def build(refresh: bool) -> int:
    print("building site list")
    sherlock = download("sherlock", refresh)
    maigret = download("maigret", refresh)

    by_domain: dict[str, list[dict[str, Any]]] = {}

    for name, raw in sherlock.items():
        if name.startswith("__") or not isinstance(raw, dict):
            continue
        record = from_sherlock(name, raw)
        if record:
            by_domain.setdefault(record["domain"], []).append(record)

    sites = maigret.get("sites", {}) if isinstance(maigret, dict) else {}
    for name, raw in sites.items():
        if not isinstance(raw, dict):
            continue
        record = from_maigret(name, raw)
        if record:
            by_domain.setdefault(record["domain"], []).append(record)

    merged = [merge(records) for records in by_domain.values()]
    merged.sort(key=lambda r: (int(r.get("rank") or 100_000), r["name"].lower()))

    curated = 0
    for record in merged:
        patch = OVERRIDES.get(record["domain"])
        if patch:
            record.update(patch)
            record["curated"] = True
            curated += 1

    payload = {
        "meta": {
            "version": 1,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sources": SOURCES,
            "counts": {
                "sites": len(merged),
                "from_both": sum(1 for r in merged if len(r["source"]) > 1),
                "from_sherlock": sum(1 for r in merged if "sherlock" in r["source"]),
                "from_maigret": sum(1 for r in merged if "maigret" in r["source"]),
                "with_probe": sum(1 for r in merged if r["probe"]),
                "with_markers": sum(1 for r in merged if r["present"] or r["absent"]),
                "curated": curated,
            },
        },
        "sites": merged,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # mtime=0 keeps the artefact byte-identical across rebuilds.
    with (
        open(OUT, "wb") as handle,
        gzip.GzipFile(fileobj=handle, mode="wb", compresslevel=9, mtime=0) as gz,
    ):
        gz.write(raw)

    counts = payload["meta"]["counts"]
    print(f"  sites      {counts['sites']}")
    print(f"  both       {counts['from_both']}")
    print(f"  sherlock   {counts['from_sherlock']}")
    print(f"  maigret    {counts['from_maigret']}")
    print(f"  probes     {counts['with_probe']}")
    print(f"  markers    {counts['with_markers']}")
    print(f"  curated    {counts['curated']}")
    print(f"  wrote      {OUT} ({OUT.stat().st_size / 1024:.0f} KiB)")
    return len(merged)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="re-download the sources")
    args = parser.parse_args()
    count = build(args.refresh)
    if count < 1000:
        print("refusing to ship a suspiciously small dataset", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

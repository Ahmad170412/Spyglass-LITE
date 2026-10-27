"""Field-level parity between spyglass-lite and upstream Spyglass-OSINT.

The username benchmark answers "who finds more accounts". This answers a
different question: for the modules both projects ship, do they agree on the
facts? A lite module that returns a different city for an IP, or a different
carrier for a number, is not a rewrite — it is a regression with better
packaging.

Run:

    python -m bench.fields
    python -m bench.fields --refresh      # no upstream caching, fresh calls
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .tools import UPSTREAM

RESULTS = Path(__file__).resolve().parent / "results"

IP_TARGETS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "140.82.121.4"]
ASN_TARGETS = ["AS13335", "AS15169", "1.1.1.0/24", "8.8.8.8"]
PHONE_TARGETS = ["+14155552671", "+442071838750", "+61412345678", "+819012345678"]
EMAIL_TARGETS = ["test@example.com", "torvalds@linux-foundation.org", "me@mailinator.com"]

NOISE = {"", "n/a", "none", "unknown", "-"}


def norm(value: Any) -> str:
    return str(value or "").strip().lower()


def comparable(value: Any) -> bool:
    return norm(value) not in NOISE


def diff_fields(
    left: dict[str, Any],
    right: dict[str, Any],
    fields: list[tuple[str, str]],
) -> tuple[list[str], list[str], int]:
    """Return (matches, mismatches, compared) for the field pairs."""
    matches: list[str] = []
    mismatches: list[str] = []
    compared = 0
    for lite_key, upstream_key in fields:
        lite_value = left.get(lite_key)
        up_value = right.get(upstream_key)
        if not comparable(lite_value) or not comparable(up_value):
            continue
        compared += 1
        if norm(lite_value) == norm(up_value):
            matches.append(lite_key)
        else:
            mismatches.append(f"{lite_key}: lite={lite_value!r} upstream={up_value!r}")
    return matches, mismatches, compared


# ─── upstream handles ─────────────────────────────────────


def _upstream_modules():
    if str(UPSTREAM) not in sys.path:
        sys.path.insert(0, str(UPSTREAM))
    from spyglass import asn as up_asn
    from spyglass import email_recon as up_email
    from spyglass import ip as up_ip
    from spyglass import phone as up_phone

    return up_ip, up_asn, up_phone, up_email


def _run(fn: Callable[[], Any]) -> tuple[Any, str]:
    try:
        return fn(), ""
    except Exception as exc:  # noqa: BLE001 - upstream failure is data here
        return {}, f"{type(exc).__name__}: {exc}"


# ─── per-domain comparisons ───────────────────────────────


def compare_ip(lite, up_ip) -> dict[str, Any]:
    rows = []
    for target in IP_TARGETS:
        mine = lite.ip(target)
        theirs, error = _run(lambda t=target: up_ip.address(t))
        geo = mine.geo.to_dict() if mine.geo else {}
        their_geo = theirs.get("geo") or {}

        fields = [
            ("ip", "ip"),
            ("hostname", "hostname"),
            ("a_records", "a_records"),
            ("ports", "open_ports"),
        ]
        fields += [
            (f"geo.{key}", key)
            for key in ("country", "region", "city", "isp", "org", "asn", "timezone")
        ]
        matches, mismatches, compared = diff_fields(
            {
                **mine.to_dict(),
                **{f"geo.{key}": value for key, value in geo.items()},
            },
            {**theirs, **their_geo},
            fields,
        )
        rows.append(
            {
                "target": target,
                "compared": compared,
                "matches": matches,
                "mismatches": mismatches,
                "error": error or (theirs.get("error") or ""),
                "lite_extra": {
                    "cpes": mine.cpes,
                    "tags": mine.tags,
                    "internetdb_hostnames": mine.hostnames,
                },
            }
        )
    return {"rows": rows}


def compare_asn(lite, up_asn) -> dict[str, Any]:
    rows = []
    for target in ASN_TARGETS:
        mine = lite.asn(target)
        theirs, error = _run(lambda t=target: up_asn.asn(t))
        origin = ""
        if theirs.get("origin_asns"):
            origin = f"AS{theirs['origin_asns'][0].get('asn')}"
        elif theirs.get("asn"):
            origin = f"AS{theirs['asn']}"

        left = {
            "prefix": mine.prefix,
            "origin_asn": mine.origin_asn,
            "holder": mine.holder,
            "announced": mine.announced,
        }
        right = {
            "prefix": theirs.get("prefix"),
            "origin_asn": origin,
            "holder": theirs.get("holder"),
            "announced": theirs.get("announced"),
        }
        matches, mismatches, compared = diff_fields(left, right, [(k, k) for k in left])
        upstream_summary = theirs.get("rpki_summary", "")
        rows.append(
            {
                "target": target,
                "compared": compared,
                "matches": matches,
                "mismatches": mismatches,
                "error": error or (theirs.get("error") or ""),
                "rpki": {
                    "lite": mine.worst_rpki,
                    "upstream": upstream_summary.split(" (")[0] if upstream_summary else "",
                },
                "lite_extra": {"rpki_validations": [v.to_dict() for v in mine.rpki]},
            }
        )
    return {"rows": rows}


def compare_phone(lite, up_phone) -> dict[str, Any]:
    rows = []
    for target in PHONE_TARGETS:
        mine = lite.phone(target)
        theirs, error = _run(lambda t=target: up_phone._phonenumbers_info(t))
        left = {
            "valid": mine.valid,
            "e164": mine.e164,
            "international": mine.international,
            "national": mine.national,
            "country_code": mine.country_code,
            "region": mine.region,
            "location": mine.location,
            "carrier": mine.carrier,
            "timezone": mine.timezone,
            "line_type": mine.line_type,
        }
        right = {
            "valid": theirs.get("valid"),
            "e164": theirs.get("e164"),
            "international": theirs.get("international"),
            "national": theirs.get("national"),
            "country_code": theirs.get("country_code"),
            "region": theirs.get("region"),
            "location": theirs.get("location"),
            "carrier": theirs.get("carrier"),
            "timezone": theirs.get("timezone"),
            "line_type": theirs.get("type"),
        }
        matches, mismatches, compared = diff_fields(left, right, [(k, k) for k in left])
        rows.append(
            {
                "target": target,
                "compared": compared,
                "matches": matches,
                "mismatches": mismatches,
                "error": error or (theirs.get("error") or ""),
                "lite_extra": {"possible": mine.possible},
            }
        )
    return {"rows": rows}


def compare_email(lite, up_email) -> dict[str, Any]:
    rows = []
    for target in EMAIL_TARGETS:
        mine = lite.email(target, gravatar=True, breaches=False)
        theirs, error = _run(lambda t=target: up_email._gravatar(t))
        mine_grav = {
            "found": mine.gravatar.exists if mine.gravatar else None,
            "hash": mine.gravatar.hash if mine.gravatar else "",
            "display_name": mine.gravatar.display_name if mine.gravatar else "",
            "location": mine.gravatar.location if mine.gravatar else "",
        }
        right = {
            "found": theirs.get("found"),
            "hash": theirs.get("hash"),
            "display_name": theirs.get("display_name"),
            "location": theirs.get("location"),
        }
        matches, mismatches, compared = diff_fields(mine_grav, right, [(k, k) for k in mine_grav])
        rows.append(
            {
                "target": target,
                "compared": compared,
                "matches": matches,
                "mismatches": mismatches,
                "error": error or (theirs.get("reason") or ""),
                "lite_extra": {
                    "mx": [m.host for m in mine.mx],
                    "provider": mine.provider,
                    "spf": mine.spf,
                    "dmarc": mine.dmarc,
                    "role": mine.role,
                    "disposable": mine.disposable,
                    "upstream_fields_missing": [
                        name
                        for name in ("mx", "spf", "dmarc", "provider", "disposable")
                        if name not in (theirs or {})
                    ],
                },
            }
        )
    return {"rows": rows}


def render(sections: dict[str, dict[str, Any]]) -> str:
    lines = [
        "# Field parity: spyglass-lite vs Spyglass-OSINT",
        "",
        "Only fields both projects produce are compared. Values either side "
        "reports as `N/A`, empty or `unknown` are skipped rather than scored. "
        "`lite_extra` is what lite adds that upstream does not report at all.",
        "",
    ]
    for name, section in sections.items():
        total_cmp = sum(row["compared"] for row in section["rows"])
        total_match = sum(len(row["matches"]) for row in section["rows"])
        pct = f"{total_match / total_cmp:.0%}" if total_cmp else "n/a"
        lines += [
            f"## {name}",
            "",
            f"Field agreement: **{total_match}/{total_cmp}** ({pct}).",
            "",
            "| target | compared | agree | disagreements |",
            "|---|---:|---:|---|",
        ]
        for row in section["rows"]:
            note = "; ".join(row["mismatches"]) or (
                "error: " + row["error"] if row["error"] else "—"
            )
            lines.append(
                f"| `{row['target']}` | {row['compared']} | {len(row['matches'])} | {note} |"
            )
        extra = [
            (row["target"], row["lite_extra"])
            for row in section["rows"]
            if any(v for v in row["lite_extra"].values())
        ]
        if extra:
            lines += ["", "Lite-only fields:", ""]
            for target, values in extra:
                lines.append(f"- `{target}`: " + json.dumps(values, default=str))
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    up_ip, up_asn, up_phone, up_email = _upstream_modules()
    from spyglass_lite import Spyglass

    lite = Spyglass()
    started = time.perf_counter()
    sections = {
        "IP": compare_ip(lite, up_ip),
        "ASN": compare_asn(lite, up_asn),
        "Phone": compare_phone(lite, up_phone),
        "Email (Gravatar overlap)": compare_email(lite, up_email),
    }
    report = render(sections)

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = Path(args.out) if args.out else RESULTS / "fields.md"
    out.write_text(report)
    (RESULTS / "fields.json").write_text(json.dumps(sections, indent=1, default=str))
    print(report)
    print(f"\nwrote {out} in {time.perf_counter() - started:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

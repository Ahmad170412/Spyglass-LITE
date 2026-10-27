"""``python -m spyglass_lite`` — the library, one command away.

Deliberately small: ``argparse``, ``json`` and ``sys`` only. No colour, no
spinners, no terminal probing; the same command has to behave identically in
bash, zsh, PowerShell and ``cmd.exe``.

Two Windows details are handled on purpose:

* text output is written with ``errors="replace"``, so a hostname outside the
  console code page cannot raise ``UnicodeEncodeError`` mid-scan;
* ``--json`` is always encoded as UTF-8 bytes, so redirected output parses
  the same way it does on macOS and Linux.

Exit codes: ``0`` success, ``1`` the call failed, ``2`` bad usage (argparse).
A scan that finishes and finds nothing is a success — ``unknown`` and
``absent`` are results, not errors.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from typing import Any

from . import __version__, asn, email, ip, phone, username
from .errors import SpyglassError


def main(argv: list[str] | None = None) -> int:
    """Run one command and return a process exit code."""
    _harden_console()
    parser = _parser()
    args = parser.parse_args(argv)

    try:
        result = _dispatch(args)
    except SpyglassError as exc:
        print(f"spyglass-lite: {exc}", file=sys.stderr)
        return 1

    if args.json:
        _write_json(result.to_dict())
    else:
        _render(args, result)
    return 0


# ─── arguments ─────────────────────────────────────────────


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spyglass-lite",
        description="OSINT recon from the command line: username, email, IP, ASN, phone.",
        epilog=(
            "examples:\n"
            "  python -m spyglass_lite username torvalds --limit 300 --deadline 20\n"
            "  python -m spyglass_lite email me@example.com --dns-only\n"
            "  python -m spyglass_lite ip 1.1.1.1 --json\n"
            "  python -m spyglass_lite asn 1.1.1.0/24\n"
            "  python -m spyglass_lite phone +14155552671\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"spyglass-lite {__version__}")
    verbs = parser.add_subparsers(dest="verb", required=True, metavar="VERB")

    who = verbs.add_parser("username", help="platforms where a handle exists")
    who.add_argument("target")
    who.add_argument("--limit", type=int, metavar="N", help="scan the N most popular sites")
    who.add_argument(
        "--deadline",
        type=float,
        metavar="SECONDS",
        help="stop after N seconds, keep what was decided",
    )
    who.add_argument(
        "--sites", action="append", metavar="LIST", help="comma-separated names, domains or URLs"
    )
    who.add_argument("--only", action="append", metavar="LIST", help="same as --sites, by name")
    who.add_argument(
        "--exclude", action="append", metavar="LIST", help="comma-separated sites to skip"
    )
    who.add_argument(
        "--tags", action="append", metavar="LIST", help="comma-separated tags to include"
    )
    who.add_argument(
        "--unknown", action="store_true", help="also list sites that could not be decided"
    )
    who.add_argument("--raw", action="store_true", help="dataset rule only, no verification layer")
    who.add_argument("--json", action="store_true", help="machine-readable output")

    mail = verbs.add_parser("email", help="validate an address and enrich the domain")
    mail.add_argument("target")
    mail.add_argument("--dns-only", action="store_true", help="skip Gravatar and breach lookups")
    mail.add_argument("--no-gravatar", action="store_true", help="skip the Gravatar lookup")
    mail.add_argument("--no-breaches", action="store_true", help="skip the breach lookups")
    mail.add_argument("--registrations", action="store_true", help="check active account existence")
    mail.add_argument("--json", action="store_true", help="machine-readable output")

    addr = verbs.add_parser("ip", help="geolocate, reverse-resolve and enrich an address")
    addr.add_argument("target")
    addr.add_argument("--no-whois", action="store_true", help="skip the WHOIS lookup")
    addr.add_argument("--no-ports", action="store_true", help="skip the passive port probe")
    addr.add_argument("--json", action="store_true", help="machine-readable output")

    net = verbs.add_parser("asn", help="prefix, origin AS and RPKI state")
    net.add_argument("target", help="an IP, a prefix such as 1.1.1.0/24, or an AS number")
    net.add_argument("--json", action="store_true", help="machine-readable output")

    tel = verbs.add_parser("phone", help="carrier, region and line type (needs the [phone] extra)")
    tel.add_argument("target")
    tel.add_argument("--json", action="store_true", help="machine-readable output")

    return parser


def _split(values: list[str] | None) -> list[str] | None:
    """``--sites a,b --sites c`` → ``["a", "b", "c"]``; ``None`` when absent."""
    if not values:
        return None
    items = [part.strip() for value in values for part in value.split(",")]
    return [item for item in items if item] or None


def _dispatch(args: argparse.Namespace) -> Any:
    if args.verb == "username":
        return username(
            args.target,
            judge=False if args.raw else None,
            sites=_split(args.sites),
            only=_split(args.only),
            exclude=_split(args.exclude),
            tags=_split(args.tags),
            limit=args.limit,
            deadline=args.deadline,
            include_unknown=True,
        )
    if args.verb == "email":
        return email(
            args.target,
            gravatar=not (args.dns_only or args.no_gravatar),
            breaches=not (args.dns_only or args.no_breaches),
            registrations=args.registrations,
        )
    if args.verb == "ip":
        return ip(args.target, whois=not args.no_whois, ports=not args.no_ports)
    if args.verb == "asn":
        return asn(args.target)
    return phone(args.target)


# ─── output ────────────────────────────────────────────────


def _harden_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(
            OSError, ValueError
        ):  # pragma: no cover - detached or closed stream
            reconfigure(errors="replace")


def _write_json(payload: dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n"
    data = text.encode("utf-8")
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
    else:  # pragma: no cover - only when stdout is replaced by a text object
        sys.stdout.write(text)
        sys.stdout.flush()


def _flag(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def _render(args: argparse.Namespace, result: Any) -> None:
    renderer = {
        "username": _render_username,
        "email": _render_email,
        "ip": _render_ip,
        "asn": _render_asn,
        "phone": _render_phone,
    }[args.verb]
    lines = renderer(args, result)
    print("\n".join(lines))


def _render_username(args: argparse.Namespace, result: Any) -> list[str]:
    seconds = result.duration_ms / 1000
    stats = f"{result.checked} checked, {len(result.unknown)} unknown"
    if result.skipped:
        stats += f", {result.skipped} skipped"
    note = ", partial" if result.partial else ""
    lines = [
        f"{result.target}: {len(result.found)} found  ({stats}, {seconds:.1f}s{note})",
        "",
    ]

    if result.found:
        width = min(max(len(profile.domain) for profile in result.found), 26)
        for profile in result.found:
            lines.append(f"  {profile.domain:<{width}}  {profile.url}  ({profile.confidence})")
    else:
        lines.append("  no accounts found")

    if args.unknown:
        if result.unknown:
            lines.extend(["", f"unknown ({len(result.unknown)})"])
            width = min(max(len(item.domain) for item in result.unknown), 26)
            for item in result.unknown:
                lines.append(f"  {item.domain:<{width}}  {item.reason}")
    elif result.unknown:
        lines.extend(
            ["", f"  {len(result.unknown)} undecided site(s); pass --unknown to list them"]
        )

    if result.errors:
        lines.extend(["", "errors:"])
        lines.extend(f"  {error}" for error in result.errors[:10])
    return lines


def _render_email(args: argparse.Namespace, result: Any) -> list[str]:
    lines = [f"{result.normalized or result.target}: {'valid' if result.valid else 'invalid'}"]
    lines.append(f"  provider    {result.provider or '-'}")
    lines.append(f"  mx          {len(result.mx)} record(s)")
    lines.append(f"  spf         {_flag(result.spf)}")
    lines.append(f"  dmarc       {_flag(result.dmarc)}")
    lines.append(f"  disposable  {_flag(result.disposable)}")
    lines.append(f"  role        {_flag(result.role)}")
    if result.gravatar is not None:
        lines.append(f"  gravatar    {'found' if result.gravatar.exists else 'not found'}")
    if result.breach is not None:
        sources = ", ".join(result.breach.sources[:5]) or "-"
        lines.append(f"  breaches    {result.breach.found} ({sources})")
    for registration in result.registrations:
        lines.append(f"  account     {registration.site}: {_flag(registration.exists)}")
    if result.errors:
        lines.append(f"  errors      {len(result.errors)} (run with --json for detail)")
    return lines


def _render_ip(args: argparse.Namespace, result: Any) -> list[str]:
    host = f"  {result.hostname}" if result.hostname else ""
    lines = [f"{result.ip}{host}"]
    if result.geo is not None:
        where = ", ".join(
            part for part in (result.geo.city, result.geo.region, result.geo.country) if part
        )
        operator = ", ".join(
            part for part in (result.geo.org or result.geo.isp, result.geo.asn) if part
        )
        lines.append(f"  location    {where or '-'}")
        if operator:
            lines.append(f"  operator    {operator}")
    if result.a_records:
        lines.append(f"  a records   {', '.join(result.a_records[:4])}")
    if result.ports:
        lines.append(f"  ports       {', '.join(str(port) for port in result.ports)}")
    if result.whois:
        pairs = [f"{key}={value}" for key, value in list(result.whois.items())[:6]]
        lines.append(f"  whois       {', '.join(pairs)}")
    if result.errors:
        lines.append(f"  errors      {len(result.errors)} (run with --json for detail)")
    return lines


def _render_asn(args: argparse.Namespace, result: Any) -> list[str]:
    rpki = result.worst_rpki
    lines = [f"{result.prefix or result.query}  {result.origin_asn or '-'}  {result.holder or '-'}"]
    lines.append(f"  rpki        {rpki}")
    if result.announced is not None:
        lines.append(f"  announced   {_flag(result.announced)}")
    if result.errors:
        lines.append(f"  errors      {len(result.errors)} (run with --json for detail)")
    return lines


def _render_phone(args: argparse.Namespace, result: Any) -> list[str]:
    lines = [f"{result.e164 or result.query}: {'valid' if result.valid else 'invalid'}"]
    lines.append(f"  national    {result.national or '-'}")
    lines.append(f"  region      {result.region or '-'}")
    lines.append(f"  line type   {result.line_type or '-'}")
    if result.carrier:
        lines.append(f"  carrier     {result.carrier}")
    return lines

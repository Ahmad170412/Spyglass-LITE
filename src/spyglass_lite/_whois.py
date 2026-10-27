"""WHOIS over raw TCP/43.

Deliberately not a dependency on the ``whois`` binary or on a parsing
library: the protocol is a line of text in and a blob out, and the fields
worth showing are stable across registries once normalised.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from urllib.parse import urlsplit


async def _query(server: str, payload: str, timeout: float = 12.0) -> str:
    if not server:
        return ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return ""
    try:
        writer.write(payload.encode("utf-8", "replace") + b"\r\n")
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", "replace")
    except (OSError, asyncio.TimeoutError):
        return ""
    finally:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await writer.wait_closed()


def _server(value: str) -> str:
    """Normalise a referral such as ``whois://whois.ripe.net:43`` to a host."""
    value = value.strip()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.split()[0] if value else ""
    return value.split(":")[0].strip().lower()


def _first_match(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else ""


_FIELD_PATTERNS = {
    "domain": r"^\s*(?:Domain Name|domain)\s*:\s*(.+)$",
    "registrar": r"^\s*(?:Registrar|Sponsoring Registrar)\s*:\s*(.+)$",
    "created": r"^\s*(?:Creation Date|Created|created)\s*:\s*(.+)$",
    "updated": r"^\s*(?:Updated Date|Last Modified|changed)\s*:\s*(.+)$",
    "expires": r"^\s*(?:Registry Expiry Date|Expiry Date|Expiration Date|paid-till)\s*:\s*(.+)$",
    "status": r"^\s*(?:Domain Status|Status)\s*:\s*(.+)$",
    "netname": r"^\s*NetName\s*:\s*(.+)$",
    "netrange": r"^\s*(?:NetRange|inetnum)\s*:\s*(.+)$",
    "cidr": r"^\s*CIDR\s*:\s*(.+)$",
    "organization": r"^\s*(?:OrgName|Organization|Organisation|org-name|descr)\s*:\s*(.+)$",
    "country": r"^\s*Country\s*:\s*(.+)$",
    "abuse": r"^\s*(?:OrgAbuseEmail|abuse-mailbox)\s*:\s*(.+)$",
}

_REPEATABLE = {"status", "nameserver"}


def parse(text: str) -> dict[str, str]:
    """Extract the fields worth reporting, normalised across registries."""
    out: dict[str, str] = {}
    for key, pattern in _FIELD_PATTERNS.items():
        value = _first_match(text, pattern)
        if value:
            out[key] = value

    nameservers = re.findall(
        r"^\s*(?:Name Server|nserver)\s*:\s*([^\s,]+)", text, re.IGNORECASE | re.MULTILINE
    )
    if nameservers:
        cleaned = sorted({n.rstrip(".").lower() for n in nameservers})
        out["nameservers"] = ", ".join(cleaned)

    statuses = re.findall(
        r"^\s*(?:Domain Status|status)\s*:\s*([^\s]+)", text, re.IGNORECASE | re.MULTILINE
    )
    if statuses:
        out["status"] = ", ".join(sorted({s.split()[0] for s in statuses}))

    return out


async def domain(name: str, timeout: float = 12.0) -> dict[str, str]:
    """WHOIS for a domain, following the registry referral once."""
    name = name.strip().strip(".").lower()
    if not name:
        return {}

    tld = name.rsplit(".", 1)[-1]
    root = await _query("whois.iana.org", tld, timeout)
    server = _first_match(root, r"^\s*refer\s*:\s*(\S+)") or ""
    server = _server(server)

    text = await _query(server, name, timeout) if server else ""
    if not text:
        text = await _query("whois.verisign-grs.com", "domain " + name, timeout)

    # Thin registries hand off to the registrar for the detail block.
    registrar_server = _server(_first_match(text, r"^\s*Registrar WHOIS Server\s*:\s*(\S+)"))
    if registrar_server and registrar_server not in {"whois.verisign-grs.com", server}:
        detail = await _query(registrar_server, name, timeout)
        if detail:
            text = text + "\n" + detail

    return parse(text)


async def address(ip: str, timeout: float = 12.0) -> dict[str, str]:
    """WHOIS for an IP, following ARIN's referral once."""
    text = await _query("whois.arin.net", "n + " + ip.strip(), timeout)
    referral = _server(_first_match(text, r"^\s*(?:ReferralServer|refer)\s*:\s*(\S+)"))
    if referral and referral != "whois.arin.net":
        detail = await _query(referral, ip.strip(), timeout)
        if detail:
            text = text + "\n" + detail
    return parse(text)

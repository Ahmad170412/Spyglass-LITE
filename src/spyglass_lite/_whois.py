"""WHOIS over raw TCP/43.

Deliberately not a dependency on the ``whois`` binary or on a parsing
library: the protocol is a line of text in and a blob out, and the fields
worth showing are stable across registries once normalised.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from urllib.parse import urlsplit

# A WHOIS server that never stops sending is a memory-exhaustion bug, not a
# protocol quirk. Two minutes and a quarter megabyte are far above any real
# registry response.
MAX_RESPONSE = 262_144


async def _query(server: str, payload: str, timeout: float = 12.0) -> str:
    if not server:
        return ""
    # A newline in the query is a second protocol command, not part of a name.
    payload = payload.replace("\r", " ").replace("\n", " ").strip()
    if not payload:
        return ""
    deadline = time.monotonic() + timeout * 2
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return ""
    chunks: list[bytes] = []
    total = 0
    try:
        writer.write(payload.encode("utf-8", "replace") + b"\r\n")
        await writer.drain()
        while total < MAX_RESPONSE:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            chunk = await asyncio.wait_for(reader.read(4096), timeout=min(remaining, timeout))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await writer.wait_closed()
    return b"".join(chunks)[:MAX_RESPONSE].decode("utf-8", "replace")


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


async def address(ip: str, timeout: float = 12.0) -> dict[str, str]:
    """WHOIS for an IP, following ARIN's referral once."""
    text = await _query("whois.arin.net", "n + " + ip.strip(), timeout)
    referral = _server(_first_match(text, r"^\s*(?:ReferralServer|refer)\s*:\s*(\S+)"))
    if referral and referral != "whois.arin.net":
        detail = await _query(referral, ip.strip(), timeout)
        if detail:
            text = text + "\n" + detail
    return parse(text)

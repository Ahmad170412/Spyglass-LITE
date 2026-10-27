"""Async DNS helpers built on dnspython.

The stdlib ``socket`` module only answers A/AAAA queries. MX, SPF and DMARC
records are not reachable through it at all, and they are the whole basis of
the email module's provider and deliverability checks.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver


def _resolver(timeout: float) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 3.0)
    return resolver


async def query(name: str, rtype: str, *, timeout: float = 4.0) -> list[str]:
    """Answer a DNS query, returning ``[]`` for NXDOMAIN / no-answer / timeout."""
    if not name:
        return []
    try:
        answer = await _resolver(timeout).resolve(name, rtype, raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError, ValueError):
        return []
    if answer.rrset is None:
        return []
    return [str(rdata) for rdata in answer.rrset]


async def mx(domain: str, *, timeout: float = 4.0) -> list[tuple[int, str]]:
    """MX records as ``(priority, host)``, sorted by priority."""
    records: list[tuple[int, str]] = []
    try:
        answer = await _resolver(timeout).resolve(domain, "MX", raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError, ValueError):
        return []
    if answer.rrset is None:
        return []
    for rdata in answer.rrset:
        host = str(rdata.exchange).rstrip(".")
        if host and host != ".":
            records.append((int(rdata.preference), host))
    return sorted(records)


async def txt(name: str, *, timeout: float = 4.0) -> list[str]:
    """TXT records joined into single strings."""
    out: list[str] = []
    try:
        answer = await _resolver(timeout).resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError, ValueError):
        return []
    if answer.rrset is None:
        return []
    for rdata in answer.rrset:
        try:
            out.append("".join(part.decode("utf-8", "replace") for part in rdata.strings))
        except AttributeError:  # pragma: no cover - older dnspython
            out.append(str(rdata).strip('"'))
    return out


async def a(host: str, *, timeout: float = 4.0) -> list[str]:
    return await query(host, "A", timeout=timeout)


async def aaaa(host: str, *, timeout: float = 4.0) -> list[str]:
    return await query(host, "AAAA", timeout=timeout)


async def ns(domain: str, *, timeout: float = 4.0) -> list[str]:
    return [r.rstrip(".") for r in await query(domain, "NS", timeout=timeout)]


async def reverse(ip: str, *, timeout: float = 4.0) -> str:
    """PTR lookup, best-effort."""
    import socket

    try:
        name, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return name
    except (OSError, UnicodeError):
        return ""


async def gather_limited(aws: Iterable, limit: int = 10) -> list:
    """Run awaitables with a small concurrency cap."""
    sem = asyncio.Semaphore(limit)

    async def _one(aw):
        async with sem:
            return await aw

    return await asyncio.gather(*(_one(aw) for aw in aws), return_exceptions=True)

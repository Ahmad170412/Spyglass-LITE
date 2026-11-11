"""Async DNS helpers built on dnspython.

The stdlib ``socket`` module only answers A/AAAA queries. MX, SPF and DMARC
records are not reachable through it at all, and they are the whole basis of
the email module's provider and deliverability checks.
"""

from __future__ import annotations

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver


def _resolver(timeout: float) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 3.0)
    return resolver


async def query(name: str, rtype: str, *, timeout: float = 4.0, cache: Any = None) -> list[str]:
    """Answer a DNS query, returning ``[]`` for NXDOMAIN / no-answer / timeout."""
    if not name:
        return []
    from ._cache import MISSING

    cache_key = None
    if cache is not None:
        cache_key = cache.key("dns", name.lower(), rtype.upper())
        cached = cache.get(cache_key)
        if cached is not MISSING:
            return list(cached)
    try:
        answer = await _resolver(timeout).resolve(name, rtype, raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError, ValueError):
        return []
    result = [] if answer.rrset is None else [str(rdata) for rdata in answer.rrset]
    if cache is not None and cache_key is not None:
        cache.set(cache_key, result)
    return result


async def mx(domain: str, *, timeout: float = 4.0, cache: Any = None) -> list[tuple[int, str]]:
    """MX records as ``(priority, host)``, sorted by priority."""
    from ._cache import MISSING

    cache_key = cache.key("mx", domain.lower()) if cache is not None else None
    if cache is not None and cache_key is not None:
        cached = cache.get(cache_key)
        if cached is not MISSING:
            return [tuple(x) for x in cached]
    records: list[tuple[int, str]] = []
    try:
        answer = await _resolver(timeout).resolve(domain, "MX", raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError, ValueError):
        return []
    if answer.rrset is None:
        if cache is not None and cache_key is not None:
            cache.set(cache_key, [])
        return []
    for rdata in answer.rrset:
        host = str(rdata.exchange).rstrip(".")
        if host and host != ".":
            records.append((int(rdata.preference), host))
    result = sorted(records)
    if cache is not None and cache_key is not None:
        cache.set(cache_key, result)
    return result


async def txt(name: str, *, timeout: float = 4.0, cache: Any = None) -> list[str]:
    """TXT records joined into single strings."""
    from ._cache import MISSING

    cache_key = cache.key("txt", name.lower()) if cache is not None else None
    if cache is not None and cache_key is not None:
        cached = cache.get(cache_key)
        if cached is not MISSING:
            return list(cached)
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
    if cache is not None and cache_key is not None:
        cache.set(cache_key, out)
    return out


async def a(host: str, *, timeout: float = 4.0, cache: Any = None) -> list[str]:
    return await query(host, "A", timeout=timeout, cache=cache)


async def aaaa(host: str, *, timeout: float = 4.0, cache: Any = None) -> list[str]:
    return await query(host, "AAAA", timeout=timeout, cache=cache)


async def ns(domain: str, *, timeout: float = 4.0) -> list[str]:
    return [r.rstrip(".") for r in await query(domain, "NS", timeout=timeout)]


async def reverse(ip: str, *, timeout: float = 4.0, cache: Any = None) -> str:
    """PTR lookup, best-effort.

    ``socket.gethostbyaddr`` has no timeout of its own, and how long the OS
    resolver waits differs by platform (Windows is far more patient than
    Linux). A scan must not inherit that, so the call is bounded here.
    """
    import socket

    from ._cache import MISSING

    cache_key = cache.key("ptr", ip) if cache is not None else None
    if cache is not None and cache_key is not None:
        cached = cache.get(cache_key)
        if cached is not MISSING:
            return str(cached)
    try:
        name, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip), timeout=timeout
        )
        result = name
    except (TimeoutError, OSError, UnicodeError):
        result = ""
    if cache is not None and cache_key is not None:
        cache.set(cache_key, result)
    return result

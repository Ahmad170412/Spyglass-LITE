"""Domain intelligence: DNS records, subdomain discovery and WHOIS.

Entirely passive — DNS queries, a Certificate Transparency lookup and a
WHOIS query. Nothing probes the target host; the port list is not touched.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from . import _dns, _whois
from ._http import fetch
from .errors import InvalidTarget
from .models import DnsRecord, DomainResult, Subdomain

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config

_CT_URL = "https://crt.sh/?q=%25.{domain}&output=json"

_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA")

# A handful of common labels for an opt-in brute-force pass. Deliberately
# short: this is a hint, not a wordlist engine.
_WORDLIST = (
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "blog",
    "app",
    "cdn",
    "static",
    "portal",
    "login",
    "secure",
    "vpn",
    "git",
    "docs",
    "status",
)


def _normalise(target: str) -> str:
    value = str(target).strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or value
    value = value.strip("[]").rstrip(".")
    if not value:
        raise InvalidTarget("domain target is empty")
    if "/" in value:
        value = value.split("/", 1)[0]
    return value


def _validate(domain: str) -> str:
    if not domain or "." not in domain:
        raise InvalidTarget(f"{domain!r} is not a domain name")
    if any(ch.isspace() for ch in domain):
        raise InvalidTarget(f"{domain!r} is not a valid domain")
    return domain


async def _ct_subdomains(
    http: httpx.AsyncClient, domain: str, config: Config, cache: Any = None
) -> set[str]:
    from ._cache import MISSING

    cache_key = cache.key("ct", domain) if cache is not None else None
    if cache is not None and cache_key is not None:
        cached = cache.get(cache_key)
        if cached is not MISSING:
            return set(cached)
    result = await fetch(http, "GET", _CT_URL.format(domain=domain), timeout=config.timeout)
    names: set[str] = set()
    if result.error or not 200 <= result.status < 300:
        return names
    try:
        data = json.loads(result.text)
    except (ValueError, TypeError):
        return names
    if not isinstance(data, list):
        return names
    for entry in data:
        if not isinstance(entry, Mapping):
            continue
        raw = entry.get("name_value") or entry.get("common_name") or ""
        for line in str(raw).splitlines():
            line = line.strip().lower().lstrip("*.")
            if not line:
                continue
            if line == domain or line.endswith("." + domain):
                names.add(line)
    if cache is not None and cache_key is not None:
        cache.set(cache_key, sorted(names))
    return names


async def scan(
    http: httpx.AsyncClient,
    target: str,
    config: Config,
    cache: Any = None,
    *,
    ct: bool = True,
    whois: bool = True,
    resolve: bool = True,
    wordlist: bool = False,
    dns_timeout: float = 4.0,
    max_subdomains: int = 200,
) -> DomainResult:
    """Run every domain check for one hostname."""
    started = time.perf_counter()
    domain = _validate(_normalise(target))

    result = DomainResult(target=str(target), domain=domain)

    # DNS records
    records: list[DnsRecord] = []
    for rtype in _RECORD_TYPES:
        try:
            answers = await _dns.query(domain, rtype, timeout=dns_timeout, cache=cache)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"dns {rtype}: {type(exc).__name__}: {exc}")
            continue
        for answer in answers:
            records.append(DnsRecord(type=rtype, name=domain, value=answer))
    result.dns = records

    # Subdomain discovery
    discovered: set[str] = set()
    if ct:
        try:
            discovered |= await _ct_subdomains(http, domain, config, cache=cache)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"crt.sh: {type(exc).__name__}: {exc}")

    if wordlist:
        for label in _WORDLIST:
            candidate = f"{label}.{domain}"
            try:
                answers = await _dns.query(candidate, "A", timeout=dns_timeout, cache=cache)
            except Exception:  # noqa: BLE001
                answers = []
            if answers:
                discovered.add(candidate)

    discovered.discard(domain)
    discovered = set(sorted(discovered)[:max_subdomains])

    subdomains: list[Subdomain] = []
    for host in discovered:
        ips: list[str] = []
        if resolve:
            try:
                ips = await _dns.a(host, timeout=dns_timeout, cache=cache)
            except Exception:  # noqa: BLE001
                ips = []
        subdomains.append(Subdomain(host=host, ips=ips, source="crt.sh" if ct else "dns"))
    subdomains.sort(key=lambda s: s.host)
    result.subdomains = subdomains

    # WHOIS
    if whois:
        try:
            result.whois = await _whois.domain(domain, cache=cache)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"whois: {type(exc).__name__}: {exc}")

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result

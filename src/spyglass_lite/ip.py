"""IP intelligence: geolocation, reverse DNS, WHOIS and passive port data.

Ports come from Shodan's InternetDB, which reports what Shodan's own scan
already saw. Nothing here probes the target. That means the port list is a
historical record, not a live measurement — a port closed last month and a
port open today are indistinguishable, and the module says so by labelling
the source rather than implying freshness.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

import httpx

from . import _dns, _whois
from ._http import Fetch, fetch
from .errors import InvalidTarget
from .models import Geo, IpResult

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config

_INTERNETDB = "https://internetdb.shodan.io"


def _json(result: Fetch) -> Any:
    if result.error or not 200 <= result.status < 300:
        return None
    try:
        return json.loads(result.text)
    except ValueError:
        return None


async def resolve(target: str, cache: Any = None) -> str:
    """Accept an IP or a hostname and return an IPv4/IPv6 string."""
    value = str(target).strip().strip("[]")
    if not value:
        raise InvalidTarget("IP target is empty")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    addresses = await _dns.a(value, cache=cache)
    if not addresses:
        raise InvalidTarget(f"could not resolve {target!r} to an address")
    return addresses[0]


async def _geo(
    http: httpx.AsyncClient, ip: str, config: Config, cache: Any = None
) -> tuple[Geo | None, str]:
    """Two geolocation opinions, primary first.

    ipwho.is is primary because it is HTTPS and does not rate-limit per minute
    like ip-api.com's free tier. The ip-api.com fallback has been replaced with
    ipapi.co, which offers HTTPS and a generous free tier without an API key.
    """
    result = await fetch(http, "GET", f"https://ipwho.is/{ip}", timeout=config.timeout)
    data = _json(result)
    if isinstance(data, Mapping) and data.get("success"):
        connection = data.get("connection") or {}
        asn = connection.get("asn")
        return (
            Geo(
                country=str(data.get("country") or ""),
                region=str(data.get("region") or ""),
                city=str(data.get("city") or ""),
                isp=str(data.get("isp") or ""),
                org=str(connection.get("org") or data.get("isp") or ""),
                asn=f"AS{asn}" if asn else "",
                location=(
                    f"{data.get('latitude')},{data.get('longitude')}"
                    if data.get("latitude") is not None and data.get("longitude") is not None
                    else ""
                ),
                timezone=_timezone(data.get("timezone")),
                source="ipwho.is",
            ),
            "",
        )

    result = await fetch(http, "GET", f"https://ipapi.co/{ip}", timeout=config.timeout)
    data = _json(result)
    if isinstance(data, Mapping) and data.get("status") == "success":
        return (
            Geo(
                country=str(data.get("country_name") or ""),
                region=str(data.get("region") or ""),
                city=str(data.get("city") or ""),
                isp=str(data.get("isp") or ""),
                org=str(data.get("org") or data.get("company") or ""),
                asn=str(data.get("asn") or ""),
                location=(
                    f"{data.get('latitude')},{data.get('longitude')}"
                    if data.get("latitude") is not None and data.get("longitude") is not None
                    else ""
                ),
                timezone=str(data.get("timezone") or ""),
                source="ipapi.co",
            ),
            "",
        )

    return None, "geolocation unavailable"


def _timezone(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(value.get("id") or "")
    return str(value or "")


async def _internetdb(
    http: httpx.AsyncClient, ip: str, config: Config, cache: Any = None
) -> Mapping[str, Any] | None:
    from ._cache import MISSING

    cache_key = cache.key("internetdb", ip) if cache is not None else None
    if cache is not None and cache_key is not None:
        cached = cache.get(cache_key)
        if cached is not MISSING:
            return cached
    result = await fetch(http, "GET", f"{_INTERNETDB}/{ip}", timeout=config.timeout)
    data = _json(result)
    out = None if not isinstance(data, Mapping) or "detail" in data and "ip" not in data else data
    if cache is not None and cache_key is not None:
        cache.set(cache_key, out)
    return out
    if not isinstance(data, Mapping):
        return None
    # A miss is {"detail": "No information available..."}; that is different
    # from "known host with no open ports" and must not read the same way.
    if "detail" in data and "ip" not in data:
        return None
    return data


async def scan(
    http: httpx.AsyncClient,
    target: str,
    config: Config,
    cache: Any = None,
    *,
    whois: bool = True,
    ports: bool = True,
) -> IpResult:
    """Run every IP check for one address or hostname."""
    started = time.perf_counter()
    ip = await resolve(target, cache=cache)

    is_domain = ip != str(target).strip().strip("[]")
    from ._cache import MISSING

    geo_cache_key = cache.key("geo", ip) if cache is not None else None
    cached_geo = MISSING
    if cache is not None and geo_cache_key is not None:
        cached_geo = cache.get(geo_cache_key)

    async def _cached_geo() -> tuple[Geo | None, str]:
        if isinstance(cached_geo, dict) and cached_geo:
            return Geo(**{k: v for k, v in cached_geo.items() if k in Geo.__dataclass_fields__}), ""
        if cached_geo is None:
            return None, "geolocation unavailable"
        return await _geo(http, ip, config)

    geo_task = _geo(http, ip, config) if cached_geo is MISSING else _cached_geo()
    rdns_task = _dns.reverse(ip, cache=cache)
    whois_task = _whois.address(ip, cache=cache) if whois else _empty()
    netdb_task = _internetdb(http, ip, config, cache=cache) if ports else _empty()
    a_task = _dns.a(target, cache=cache) if is_domain else _empty()

    geo_pair, hostname, who, netdb, a_records = await asyncio.gather(
        geo_task, rdns_task, whois_task, netdb_task, a_task
    )
    geo, geo_error = geo_pair

    if cache is not None and geo_cache_key is not None and cached_geo is MISSING:
        cache.set(geo_cache_key, geo.to_dict() if geo is not None else None)

    result = IpResult(
        ip=ip,
        geo=geo,
        hostname=hostname,
        a_records=a_records or [],
        whois=who or {},
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    if geo_error:
        result.errors.append(geo_error)

    if isinstance(netdb, Mapping):
        raw_ports = [p for p in netdb.get("ports") or [] if isinstance(p, int)]
        if raw_ports:
            result.ports = sorted(set(raw_ports))
        result.hostnames = sorted({h for h in netdb.get("hostnames") or [] if isinstance(h, str)})[
            :10
        ]
        result.cpes = sorted({c for c in netdb.get("cpes") or [] if isinstance(c, str)})[:10]
        result.tags = sorted({t for t in netdb.get("tags") or [] if isinstance(t, str)})

    # Optional VirusTotal enrichment (needs VT_API_KEY).
    vt_key = os.environ.get("VT_API_KEY", "").strip()
    if vt_key and getattr(config, "enrich", False):
        vt_result = await fetch(
            http,
            "GET",
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": vt_key},
            timeout=config.timeout,
        )
        if 200 <= vt_result.status < 300:
            try:
                parsed = json.loads(vt_result.text)
            except ValueError:
                parsed = None
            if isinstance(parsed, Mapping):
                data = parsed.get("data", {}).get("attributes", {})
                for tag in data.get("tags") or []:
                    if isinstance(tag, str) and tag not in result.tags:
                        result.tags.append(tag)
                stats = data.get("last_analysis_stats") or {}
                malicious = stats.get("malicious", 0)
                if malicious:
                    result.tags.append(f"vt:malicious={malicious}")
                reputation = data.get("reputation")
                if (
                    isinstance(reputation, int)
                    and reputation < 0
                    and "vt:low-reputation" not in result.tags
                ):
                    result.tags.append("vt:low-reputation")

    # Shodan's historical view is worth stating, because an absent port list
    # is not the same claim as "no ports are open".
    if ports and not netdb:
        result.errors.append("internetdb: no historical scan for this address")

    return result


async def _empty() -> Any:
    return None

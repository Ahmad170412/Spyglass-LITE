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


async def resolve(target: str) -> str:
    """Accept an IP or a hostname and return an IPv4/IPv6 string."""
    value = str(target).strip().strip("[]")
    if not value:
        raise InvalidTarget("IP target is empty")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    addresses = await _dns.a(value)
    if not addresses:
        raise InvalidTarget(f"could not resolve {target!r} to an address")
    return addresses[0]


async def _geo(http: httpx.AsyncClient, ip: str, config: Config) -> tuple[Geo | None, str]:
    """Two geolocation opinions, primary first.

    ipwho.is is primary because ip-api.com's free tier rate-limits per
    minute, and a rate-limited lookup used to erase the whole geo block.
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

    fields = "status,country,regionName,city,isp,org,as,lat,lon,timezone,query"
    result = await fetch(
        http, "GET", f"http://ip-api.com/json/{ip}?fields={fields}", timeout=config.timeout
    )
    data = _json(result)
    if isinstance(data, Mapping) and data.get("status") == "success":
        return (
            Geo(
                country=str(data.get("country") or ""),
                region=str(data.get("regionName") or ""),
                city=str(data.get("city") or ""),
                isp=str(data.get("isp") or ""),
                org=str(data.get("org") or ""),
                asn=str(data.get("as") or ""),
                location=(
                    f"{data.get('lat')},{data.get('lon')}" if data.get("lat") is not None else ""
                ),
                timezone=str(data.get("timezone") or ""),
                source="ip-api.com (fallback)",
            ),
            "",
        )

    return None, "geolocation unavailable"


def _timezone(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(value.get("id") or "")
    return str(value or "")


async def _internetdb(http: httpx.AsyncClient, ip: str, config: Config) -> Mapping[str, Any] | None:
    result = await fetch(http, "GET", f"{_INTERNETDB}/{ip}", timeout=config.timeout)
    data = _json(result)
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
    *,
    whois: bool = True,
    ports: bool = True,
) -> IpResult:
    """Run every IP check for one address or hostname."""
    started = time.perf_counter()
    ip = await resolve(target)

    is_domain = ip != str(target).strip().strip("[]")
    geo_task = _geo(http, ip, config)
    rdns_task = _dns.reverse(ip)
    whois_task = _whois.address(ip) if whois else _empty()
    netdb_task = _internetdb(http, ip, config) if ports else _empty()
    a_task = _dns.a(target) if is_domain else _empty()

    geo_pair, hostname, who, netdb, a_records = await asyncio.gather(
        geo_task, rdns_task, whois_task, netdb_task, a_task
    )
    geo, geo_error = geo_pair

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

    # Shodan's historical view is worth stating, because an absent port list
    # is not the same claim as "no ports are open".
    if ports and not netdb:
        result.errors.append("internetdb: no historical scan for this address")

    return result


async def _empty() -> Any:
    return None

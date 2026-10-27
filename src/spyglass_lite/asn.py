"""ASN and routing intelligence via RIPEStat.

Answers three questions: which prefix covers this address, which AS originates
it, and whether the route has a valid RPKI origin validation. All three are
HTTP calls to a public, keyless API.

RPKI states are kept distinct. ``no ROA`` is not ``valid``: an unvalidated
route is not a safe route, and an AS-only query has no prefix to validate at
all, which is reported as unknown with a reason rather than quietly as valid.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx

from ._http import Fetch, fetch
from .errors import InvalidTarget
from .models import AsnResult, RpkiValidation

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config

_RIPESTAT = "https://stat.ripe.net/data"
_ASN_RE = re.compile(r"^AS(\d{1,10})$", re.IGNORECASE)
_VALID_STATES = {"valid", "invalid", "unknown"}


def _json(result: Fetch) -> Any:
    if result.error or not 200 <= result.status < 300:
        return None
    try:
        return json.loads(result.text)
    except ValueError:
        return None


async def _data(
    http: httpx.AsyncClient, path: str, params: Mapping[str, str], config: Config
) -> Any:
    query = urlencode(params)
    result = await fetch(
        http, "GET", f"{_RIPESTAT}/{path}/data.json?{query}", timeout=config.timeout
    )
    payload = _json(result)
    if isinstance(payload, Mapping):
        return payload.get("data")
    return None


async def _prefix_overview(
    http: httpx.AsyncClient, resource: str, config: Config
) -> tuple[str, str, str]:
    """Return ``(prefix, asn, holder)`` for an address or a prefix.

    RIPEStat answers the two questions with different shapes: an address gets
    a ``prefixes`` list of covering prefixes, while a prefix gets its own
    ``resource`` and ``asns`` at the top level. Reading only the first shape
    made a prefix query silently report no origin AS at all.
    """
    data = await _data(http, "prefix-overview", {"resource": resource}, config)
    if not isinstance(data, Mapping):
        return "", "", ""

    first: Mapping[str, Any] | None = None
    prefixes = data.get("prefixes")
    if isinstance(prefixes, list) and prefixes and isinstance(prefixes[0], Mapping):
        first = prefixes[0]

    if first is not None:
        prefix = str(first.get("prefix") or "")
        asns = first.get("asns")
    else:
        prefix = str(data.get("resource") or "")
        asns = data.get("asns")

    if isinstance(asns, list) and asns and isinstance(asns[0], Mapping):
        number = asns[0].get("asn")
        holder = str(asns[0].get("holder") or "")
        return prefix, (f"AS{number}" if number is not None else ""), holder
    return prefix, "", ""


async def _as_overview(
    http: httpx.AsyncClient, asn: str, config: Config
) -> tuple[str, bool | None]:
    data = await _data(http, "as-overview", {"resource": asn}, config)
    if not isinstance(data, Mapping):
        return "", None
    announced = data.get("announced")
    return str(data.get("holder") or ""), (announced if isinstance(announced, bool) else None)


async def _rpki(
    http: httpx.AsyncClient, asn: str, prefix: str, config: Config
) -> RpkiValidation | None:
    if not prefix or not asn:
        return None
    data = await _data(http, "rpki-validation", {"resource": asn, "prefix": prefix}, config)
    if not isinstance(data, Mapping):
        return None
    raw = str(data.get("status") or data.get("state") or "unknown").lower()
    state = raw if raw in _VALID_STATES else "unknown"
    description = str(data.get("description") or data.get("reason") or "")
    return RpkiValidation(
        prefix=str(data.get("prefix") or prefix),
        asn=asn,
        state=state,
        description=description,
    )


async def scan(http: httpx.AsyncClient, target: str, config: Config) -> AsnResult:
    """Classify the target as an address, a prefix, or an AS, then resolve it."""
    started = time.perf_counter()
    query = str(target).strip().replace(" ", "")
    if not query:
        raise InvalidTarget("ASN target is empty")

    result = AsnResult(query=query)

    asn_match = _ASN_RE.match(query)
    if asn_match:
        result.query_type = "asn"
        asn = "AS" + asn_match.group(1)
        holder, announced = await _as_overview(http, asn, config)
        result.origin_asn = asn
        result.holder = holder
        result.announced = announced
        # An AS alone has no prefix, so RPKI cannot be evaluated. Saying that
        # is more useful than returning "unknown" with no explanation.
        result.rpki = [
            RpkiValidation(
                asn=asn,
                state="unknown",
                description="an AS alone has no prefix to validate; query an IP or prefix",
            )
        ]
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    if "/" in query:
        try:
            network = ipaddress.ip_network(query, strict=False)
        except ValueError as exc:
            raise InvalidTarget(f"{target!r} is not a valid prefix") from exc
        result.query_type = "prefix"
        resource = str(network)
    else:
        try:
            resource = str(ipaddress.ip_address(query))
        except ValueError as exc:
            raise InvalidTarget(f"{target!r} is not an IP, prefix or AS number") from exc
        result.query_type = "address"

    prefix, origin, holder = await _prefix_overview(http, resource, config)
    result.prefix = prefix or (resource if result.query_type == "prefix" else "")
    result.origin_asn = origin
    result.holder = holder

    if origin:
        as_holder, announced = await _as_overview(http, origin, config)
        result.announced = announced
        if as_holder:
            result.holder = as_holder

    validation = await _rpki(http, result.origin_asn, result.prefix, config)
    if validation is not None:
        result.rpki = [validation]

    if not result.prefix and not result.origin_asn and not result.holder:
        result.errors.append("ripestat returned no routing data for this target")

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result

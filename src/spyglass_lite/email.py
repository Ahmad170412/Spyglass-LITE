"""Email intelligence.

Tier A (always on) is passive and safe: syntax, normalisation, disposable and
role detection, MX/provider identification, SPF and DMARC, Gravatar (including
the accounts it links to), and breach lookups against keyless public APIs.

Tier B asks individual sites whether an address has an account. It is off by
default because it can trigger password-reset mail and because
unauthenticated "does this email exist" endpoints are rare and brittle. The
recipe list is deliberately small and data-driven — see
``data/registrations.json`` and ``docs/RECIPES.md`` for the schema — and
``sites=`` accepts inline recipe dicts or bare domains at call time, so the
bundled list is a floor, not a ceiling.

No Holehe code or data is used here; Holehe is GPL-3.0 and this package is
MIT. See NOTICE.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode, urlparse

import httpx

from . import _dns, _registry
from ._http import Fetch, fetch
from .errors import InvalidTarget
from .models import (
    Account,
    Breach,
    EmailResult,
    Gravatar,
    MxRecord,
    Registration,
)

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config

_LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def parse(target: str) -> tuple[str, str, str]:
    """Return ``(local, domain, normalised_address)``.

    Raises :class:`InvalidTarget` rather than returning a confident "no"
    for something that was never an address.
    """
    value = str(target).strip()
    if value.lower().startswith("mailto:"):
        value = value[7:]
    if value.count("@") != 1:
        raise InvalidTarget(f"{target!r} is not an email address")
    local, _, domain = value.rpartition("@")
    if not local or not domain:
        raise InvalidTarget(f"{target!r} is not an email address")
    if not _LOCAL_RE.match(local) or local.startswith(".") or local.endswith(".") or ".." in local:
        raise InvalidTarget(f"{target!r} has an invalid local part")

    domain = domain.strip().strip(".").lower()
    if ".." in domain or not domain:
        raise InvalidTarget(f"{target!r} has an invalid domain")
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidTarget(f"{target!r} has a domain that cannot be encoded") from exc
    if not _DOMAIN_RE.match(ascii_domain):
        raise InvalidTarget(f"{target!r} has an invalid domain")

    return local, domain, f"{local}@{domain}"


def _provider(mx_hosts: Iterable[str]) -> str:
    for host in mx_hosts:
        host = host.lower().rstrip(".")
        for suffix, name in _registry.providers():
            if host == suffix or host.endswith("." + suffix):
                return name
    return ""


def _gravatar_hash(address: str) -> str:
    return hashlib.md5(address.strip().lower().encode("utf-8")).hexdigest()


async def _gravatar(http: httpx.AsyncClient, address: str, config: Config) -> Gravatar:
    """Look up a public Gravatar identity.

    Step one is an existence test that needs no parsing: Gravatar's
    documented ``?d=404`` behaviour returns 404 when the address has no
    avatar. Step two only runs when the avatar exists.
    """
    digest = _gravatar_hash(address)
    profile_url = f"https://gravatar.com/{digest}"

    head = await fetch(
        http,
        "GET",
        f"https://gravatar.com/avatar/{digest}?d=404",
        timeout=config.timeout,
    )
    if head.error or not head.status:
        return Gravatar(hash=digest, profile_url=profile_url)
    if head.status == 404:
        return Gravatar(exists=False, hash=digest, profile_url=profile_url)
    if not 200 <= head.status < 400:
        return Gravatar(hash=digest, profile_url=profile_url)

    data: Mapping[str, Any] = {}
    for endpoint in (
        f"https://en.gravatar.com/{digest}.json",
        f"https://gravatar.com/{digest}.json",
    ):
        detail = await fetch(http, "GET", endpoint, timeout=config.timeout)
        if detail.error or not 200 <= detail.status < 300:
            continue
        try:
            parsed = json.loads(detail.text)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            data = parsed
            break

    entries = data.get("entry") or []
    if not entries or not isinstance(entries[0], Mapping):
        return Gravatar(
            exists=True,
            hash=digest,
            profile_url=profile_url,
        )

    entry = entries[0]
    accounts: list[Account] = []
    for raw in entry.get("accounts") or []:
        if not isinstance(raw, Mapping):
            continue
        url = str(raw.get("url") or "")
        domain = str(raw.get("domain") or "")
        handle = str(raw.get("username") or raw.get("shortname") or "")
        if not domain and url:
            match = re.match(r"https?://([^/:]+)", url)
            domain = match.group(1) if match else ""
        service = domain.split(".")[0] if domain else handle
        if service or handle or url:
            accounts.append(Account(service=service, username=handle, url=url))

    return Gravatar(
        exists=True,
        hash=digest,
        profile_url=str(entry.get("profileUrl") or profile_url),
        display_name=str(entry.get("displayName") or ""),
        username=str(entry.get("preferredUsername") or ""),
        location=str(entry.get("currentLocation") or ""),
        about=str(entry.get("aboutMe") or "")[:200],
        accounts=accounts,
    )


def _json_or_none(result: Fetch) -> Any:
    if result.error or not 200 <= result.status < 300:
        return None
    try:
        return json.loads(result.text)
    except ValueError:
        return None


async def _breaches(http: httpx.AsyncClient, address: str, config: Config) -> Breach:
    """Keyless breach lookups, best-effort.

    ``found`` is the number of records reported, which is not the number of
    distinct breaches. Sources are reported separately so a reader can tell
    a single leak from a corpus hit.
    """
    encoded = quote(address, safe="")

    leakcheck = fetch(
        http, "GET", f"https://leakcheck.io/api/public?check={encoded}", timeout=config.timeout
    )
    scylla = fetch(
        http, "GET", f"https://scylla.so/api/search/email/{encoded}", timeout=config.timeout
    )
    leak_result, scylla_result = await asyncio.gather(leakcheck, scylla)

    found = 0
    sources: set[str] = set()
    fields: set[str] = set()

    data = _json_or_none(leak_result)
    if isinstance(data, Mapping) and data.get("success"):
        found += int(data.get("found") or 0)
        for source in data.get("sources") or []:
            if isinstance(source, Mapping):
                name = source.get("name") or source.get("source")
                if name:
                    sources.add(str(name))
            elif source:
                sources.add(str(source))
        for field in data.get("fields") or []:
            fields.add(str(field).replace("_", " ").title())

    data = _json_or_none(scylla_result)
    if isinstance(data, list):
        found += len(data)
        for entry in data:
            if isinstance(entry, Mapping):
                for key in ("database", "source", "breach"):
                    if entry.get(key):
                        sources.add(str(entry[key]))
                for key, value in entry.items():
                    if value and key not in {"database", "source", "breach", "_id"}:
                        fields.add(str(key).replace("_", " ").title())

    return Breach(
        found=found,
        sources=sorted(sources)[:10],
        fields=sorted(fields)[:10],
    )


# ─── Tier B: account-existence recipes ────────────────────


def _walk(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else None
        else:
            return None
    return current


def _recipe_matches(spec: Mapping[str, Any] | None, result: Fetch, payload: Any) -> bool:
    if not spec:
        return False
    if "json_path" in spec:
        value = _walk(payload, str(spec["json_path"]))
        if "equals" in spec:
            return value == spec["equals"]
        if spec.get("non_empty"):
            return bool(value)
        if spec.get("empty"):
            return not value
        return False
    if "body_contains" in spec:
        return str(spec["body_contains"]).lower() in result.text.lower()
    if "status" in spec:
        return result.status == spec["status"]
    return False


def load_recipes(path: str | None = None) -> list[dict[str, Any]]:
    """Bundled recipes, or a JSON file supplied by the caller.

    A file may be either a list of recipes or ``{"recipes": [...]}``.
    """
    if path is None:
        return list(_registry.registrations())
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    recipes = data.get("recipes") if isinstance(data, dict) else data
    if not isinstance(recipes, list):
        raise ValueError("recipe file must contain a list of recipes")
    return recipes


def _domain_of(value: str) -> str:
    """Host from a bare domain, a URL, or a URL-ish string."""
    text = value.strip().lower()
    text = urlparse(text).hostname or "" if "://" in text else text.split("/", 1)[0]
    return text.removeprefix("www.")


def _hosts_recipe(url: str, domain: str) -> bool:
    host = _domain_of(url)
    return bool(host) and (host == domain or host.endswith("." + domain))


def resolve_sites(
    sites: Iterable[Mapping[str, Any] | str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Turn a ``sites=`` list into ``(recipes, unmatched_domains)``.

    Entries are either inline recipe dicts — same schema as
    ``registrations.json``, see docs/RECIPES.md — or bare domains/URLs, which
    are matched against the bundled recipes by hostname. A domain with no
    recipe cannot be probed: "does this email exist here" is site-specific
    logic, not a URL pattern, so it is reported as unmatched rather than
    guessed at.
    """
    recipes: list[dict[str, Any]] = []
    unmatched: list[str] = []
    bundled = _registry.registrations()
    for entry in sites:
        if isinstance(entry, Mapping):
            recipe = dict(entry)
            if not str(recipe.get("url") or ""):
                label = recipe.get("name") or recipe.get("id") or "?"
                raise InvalidTarget(f"recipe for {label!r} is missing 'url'")
            recipes.append(recipe)
            continue
        domain = _domain_of(str(entry))
        if not domain:
            raise InvalidTarget(f"{entry!r} is not a domain or a recipe")
        matches = [r for r in bundled if _hosts_recipe(str(r.get("url") or ""), domain)]
        if matches:
            recipes.extend(dict(recipe) for recipe in matches)
        else:
            unmatched.append(domain)
    return recipes, unmatched


async def _run_recipe(
    http: httpx.AsyncClient,
    recipe: Mapping[str, Any],
    address: str,
    config: Config,
) -> Registration:
    name = str(recipe.get("name") or recipe.get("id") or "unknown")
    url = str(recipe.get("url") or "")
    method = str(recipe.get("method") or "GET").upper()
    headers = dict(recipe.get("headers") or {})

    url = url.replace("{email}", quote(address, safe=""))
    if recipe.get("params"):
        values = {
            key: str(value).replace("{email}", address)
            for key, value in dict(recipe["params"]).items()
        }
        url += ("&" if "?" in url else "?") + urlencode(values)

    payload = recipe.get("payload")
    if isinstance(payload, dict):
        payload = {key: str(value).replace("{email}", address) for key, value in payload.items()}

    result = await fetch(
        http,
        method,
        url,
        headers=headers,
        payload=payload,
        timeout=config.timeout,
    )

    if result.error:
        return Registration(site=name, exists=None, evidence=f"request failed: {result.error}")

    try:
        parsed = json.loads(result.text) if result.text else None
    except ValueError:
        parsed = None

    if _recipe_matches(recipe.get("exists_when"), result, parsed):
        return Registration(site=name, exists=True, evidence="exists marker matched", url=url)
    if _recipe_matches(recipe.get("absent_when"), result, parsed):
        return Registration(site=name, exists=False, evidence="absent marker matched", url=url)

    return Registration(
        site=name,
        exists=None,
        evidence=f"inconclusive (http {result.status})",
        url=url,
    )


# ─── public entry point ───────────────────────────────────


async def scan(
    http: httpx.AsyncClient,
    target: str,
    config: Config,
    *,
    gravatar: bool = True,
    breaches: bool = True,
    registrations: bool = False,
    recipes_path: str | None = None,
    sites: Sequence[Mapping[str, Any] | str] | None = None,
    dns_timeout: float = 4.0,
) -> EmailResult:
    """Run every enabled email check for one address.

    ``sites`` checks specific sites only: inline recipe dicts (schema in
    docs/RECIPES.md) and/or bare domains matched against the bundled
    recipes. Domains with no recipe are reported as inconclusive with the
    reason, never guessed.
    """
    started = time.perf_counter()
    local, domain, normalized = parse(target)

    mx, spf_records, dmarc_records = await asyncio.gather(
        _dns.mx(domain, timeout=dns_timeout),
        _dns.txt(domain, timeout=dns_timeout),
        _dns.txt("_dmarc." + domain, timeout=dns_timeout),
    )

    mx_records = [MxRecord(host=host, priority=priority) for priority, host in mx]
    spf = any(record.lower().startswith("v=spf1") for record in spf_records)
    dmarc = any(record.lower().startswith("v=dmarc1") for record in dmarc_records)

    gravatar_result: Gravatar | None = None
    breach_result: Breach | None = None
    registration_results: list[Registration] = []

    tasks: list[Any] = []
    if gravatar:
        tasks.append(_gravatar(http, normalized, config))
    if breaches:
        tasks.append(_breaches(http, normalized, config))

    recipes: list[dict[str, Any]] = []
    if registrations:
        recipes.extend(load_recipes(recipes_path))

    unmatched: list[str] = []
    if sites is not None:
        extra, unmatched = resolve_sites(sites)
        known = {(r.get("id") or r.get("name"), r.get("url")) for r in recipes}
        recipes.extend(
            recipe
            for recipe in extra
            if (recipe.get("id") or recipe.get("name"), recipe.get("url")) not in known
        )

    tasks.extend(_run_recipe(http, recipe, normalized, config) for recipe in recipes)

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    else:
        results = []

    index = 0
    if gravatar:
        value = results[index]
        index += 1
        gravatar_result = (
            value if isinstance(value, Gravatar) else Gravatar(hash=_gravatar_hash(normalized))
        )
    if breaches:
        value = results[index]
        index += 1
        breach_result = value if isinstance(value, Breach) else Breach()

    for value in results[index:]:
        if isinstance(value, Registration):
            registration_results.append(value)

    for site in unmatched:
        registration_results.append(
            Registration(
                site=site,
                exists=None,
                evidence="no recipe for this domain; pass a recipe dict via sites=",
            )
        )

    errors = [str(value) for value in results if isinstance(value, BaseException)]

    return EmailResult(
        target=normalized,
        valid=True,
        normalized=normalized,
        local=local,
        domain=domain,
        disposable=domain in _registry.disposable_domains(),
        role=local.lower() in _registry.role_accounts(),
        provider=_provider(record.host for record in mx_records),
        mx=mx_records,
        spf=spf,
        dmarc=dmarc,
        gravatar=gravatar_result,
        breach=breach_result,
        registrations=registration_results,
        duration_ms=int((time.perf_counter() - started) * 1000),
        errors=errors,
    )

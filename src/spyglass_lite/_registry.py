"""Access to the bundled datasets.

Everything ships inside the wheel and is read through ``importlib.resources``
so it works from a zipimport, an editable install, or a plain checkout. No
dataset is fetched at runtime: a scan cannot be broken by an upstream repo
renaming a file, and no request is made before the user asks for one.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Sequence
from functools import lru_cache
from importlib.resources import files
from typing import Any
from urllib.parse import urlparse

_DATA = "spyglass_lite.data"


def _read_json(name: str) -> Any:
    resource = files(_DATA).joinpath(name)
    raw = resource.read_bytes()
    if name.endswith(".gz"):
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8"))


@lru_cache(maxsize=1)
def sites() -> tuple[dict[str, Any], ...]:
    """Every bundled username site, most popular first."""
    data = _read_json("sites.json.gz")
    records: Sequence[dict[str, Any]] = data["sites"]
    return tuple(records)


@lru_cache(maxsize=1)
def site_count() -> int:
    return len(sites())


def _norm(value: str) -> str:
    """Normalise a site reference: display name, domain, or full URL.

    ``only=["https://www.github.com/login"]`` and ``only=["GitHub"]`` must
    both find the same site, so the host is extracted and ``www.`` dropped.
    """
    text = value.strip().lower()
    text = urlparse(text).hostname or "" if "://" in text else text.split("/", 1)[0]
    return text.removeprefix("www.")


def select(
    *,
    tags: Iterable[str] | None = None,
    only: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Filter the site list.

    ``only``/``exclude`` match a site's domain or its display name, so both
    ``only=["github.com"]`` and ``only=["GitHub"]`` work. ``tags`` matches any
    of the given tags. ``limit`` keeps the most popular N sites after
    filtering, which is the fast-scan knob.
    """
    only_set = {_norm(v) for v in only} if only else None
    exclude_set = {_norm(v) for v in exclude} if exclude else set()
    tag_set = {t.lower() for t in tags} if tags else None

    out: list[dict[str, Any]] = []
    for site in sites():
        domain = _norm(site["domain"])
        name = _norm(site["name"])
        if exclude_set and (domain in exclude_set or name in exclude_set):
            continue
        if only_set is not None and domain not in only_set and name not in only_set:
            continue
        if tag_set is not None and not (tag_set & {t.lower() for t in site.get("tags", ())}):
            continue
        out.append(site)
        if limit is not None and len(out) >= limit:
            break
    return out


@lru_cache(maxsize=1)
def registrations() -> tuple[dict[str, Any], ...]:
    """Opt-in account-existence recipes (Tier B)."""
    data = _read_json("registrations.json")
    return tuple(data.get("recipes", ()))


@lru_cache(maxsize=1)
def disposable_domains() -> frozenset[str]:
    data = _read_json("disposable.json")
    return frozenset(d.lower() for d in data["domains"])


@lru_cache(maxsize=1)
def providers() -> tuple[tuple[str, str], ...]:
    """(mx suffix, provider name), longest suffix first."""
    data = _read_json("providers.json")
    pairs = sorted(
        ((k.lower(), v) for k, v in data["mx"].items()),
        key=lambda kv: len(kv[0]),
        reverse=True,
    )
    return tuple(pairs)


@lru_cache(maxsize=1)
def role_accounts() -> frozenset[str]:
    return frozenset(_read_json("roles.json")["local_parts"])


def dataset_meta() -> dict[str, Any]:
    """Provenance and build metadata for the bundled site list."""
    return dict(_read_json("sites.json.gz")["meta"])

"""Typed results returned by every module.

Every model is a ``slots`` dataclass and ``to_dict()`` produces plain
JSON-safe structures, so a result can be consumed directly or handed to
``json.dumps`` without a custom encoder.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Literal

Confidence = Literal["high", "medium", "low"]


def _plain(obj: Any) -> Any:
    """Recursively convert dataclasses to plain Python containers."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _plain(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, (list, tuple, set)):
        return [_plain(item) for item in obj]
    if isinstance(obj, dict):
        return {str(k): _plain(v) for k, v in obj.items()}
    return obj


class Model:
    """Shared behaviour for result objects."""

    def to_dict(self) -> dict[str, Any]:
        data = _plain(self)
        assert isinstance(data, dict)
        return data

    def to_json(self, *, indent: int = 2) -> str:
        """Serialise the result to a JSON string."""
        import json

        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:  # pragma: no cover - defensive
            raise KeyError(key) from exc


# ─── username ──────────────────────────────────────────────


@dataclass(slots=True)
class Profile(Model):
    """A platform where the handle was found."""

    platform: str
    domain: str
    url: str
    confidence: Confidence
    evidence: str
    status: int | None = None

    def __str__(self) -> str:
        return self.url


@dataclass(slots=True)
class Unknown(Model):
    """A platform that could not be decided, and why.

    Kept separate from "not found" on purpose: a Cloudflare wall and a
    nonexistent account are different answers, and collapsing them is how a
    recon tool reports a thin result as a confident one.
    """

    platform: str
    domain: str
    reason: str


@dataclass(slots=True)
class UsernameResult(Model):
    target: str
    found: list[Profile] = field(default_factory=list)
    unknown: list[Unknown] = field(default_factory=list)
    checked: int = 0
    skipped: int = 0
    duration_ms: int = 0
    strict: bool = True
    errors: list[str] = field(default_factory=list)
    # True when a deadline cut the scan short: the lists are what had been
    # decided by then, not the full answer.
    partial: bool = False

    def __len__(self) -> int:
        return len(self.found)

    def __iter__(self) -> Iterator[Profile]:
        return iter(self.found)

    def __bool__(self) -> bool:
        return bool(self.found)

    def __str__(self) -> str:
        cut = ", partial" if self.partial else ""
        return (
            f"<UsernameResult {self.target!r}: "
            f"{len(self.found)} found, {len(self.unknown)} unknown{cut}>"
        )

    def __repr__(self) -> str:
        # Jupyter prints repr(), and the dataclass default dumps every profile
        # and every undecided site into the cell. The summary is what a caller
        # actually reads; ``.to_dict()`` is there for the details.
        return str(self)

    @property
    def domains(self) -> list[str]:
        return [p.domain for p in self.found]

    @property
    def high_confidence(self) -> list[Profile]:
        return [p for p in self.found if p.confidence == "high"]


# ─── email ─────────────────────────────────────────────────


@dataclass(slots=True)
class MxRecord(Model):
    host: str
    priority: int


@dataclass(slots=True)
class Account(Model):
    """A social account linked from a Gravatar profile."""

    service: str
    username: str = ""
    url: str = ""


@dataclass(slots=True)
class Gravatar(Model):
    exists: bool = False
    hash: str = ""
    profile_url: str = ""
    display_name: str = ""
    username: str = ""
    location: str = ""
    about: str = ""
    accounts: list[Account] = field(default_factory=list)


@dataclass(slots=True)
class Breach(Model):
    found: int = 0
    sources: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Registration(Model):
    """Result of an opt-in account-existence check (Tier B)."""

    site: str
    exists: bool | None = None
    evidence: str = ""
    url: str = ""


@dataclass(slots=True)
class EmailResult(Model):
    target: str
    valid: bool = False
    normalized: str = ""
    local: str = ""
    domain: str = ""
    disposable: bool = False
    role: bool = False
    provider: str = ""
    mx: list[MxRecord] = field(default_factory=list)
    spf: bool | None = None
    dmarc: bool | None = None
    gravatar: Gravatar | None = None
    breach: Breach | None = None
    registrations: list[Registration] = field(default_factory=list)
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.valid

    def __str__(self) -> str:
        return f"<EmailResult {self.target!r}: valid={self.valid} provider={self.provider!r}>"


# ─── ip ────────────────────────────────────────────────────


@dataclass(slots=True)
class Geo(Model):
    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    location: str = ""
    timezone: str = ""
    source: str = ""


@dataclass(slots=True)
class IpResult(Model):
    ip: str = ""
    geo: Geo | None = None
    hostname: str = ""
    a_records: list[str] = field(default_factory=list)
    whois: dict[str, str] = field(default_factory=dict)
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.ip)


# ─── asn ───────────────────────────────────────────────────


@dataclass(slots=True)
class RpkiValidation(Model):
    prefix: str = ""
    asn: str = ""
    state: str = "unknown"
    description: str = ""


@dataclass(slots=True)
class AsnResult(Model):
    query: str = ""
    query_type: str = ""
    prefix: str = ""
    origin_asn: str = ""
    holder: str = ""
    announced: bool | None = None
    rpki: list[RpkiValidation] = field(default_factory=list)
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.prefix or self.origin_asn or self.holder)

    @property
    def worst_rpki(self) -> str:
        """Worst validation state, so callers do not have to rank it."""
        order = {"invalid": 0, "unknown": 1, "valid": 2}
        states = [v.state for v in self.rpki] or ["unknown"]
        return sorted(states, key=lambda s: order.get(s, 1))[0]


# ─── domain ───────────────────────────────────────────────


@dataclass(slots=True)
class DnsRecord(Model):
    """One DNS answer for a domain."""

    type: str
    name: str
    value: str
    ttl: int | None = None


@dataclass(slots=True)
class Subdomain(Model):
    """A hostname discovered under a domain."""

    host: str
    ips: list[str] = field(default_factory=list)
    source: str = ""


@dataclass(slots=True)
class DomainResult(Model):
    target: str
    domain: str = ""
    dns: list[DnsRecord] = field(default_factory=list)
    subdomains: list[Subdomain] = field(default_factory=list)
    whois: dict[str, str] = field(default_factory=dict)
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.domain)

    def __str__(self) -> str:
        return (
            f"<DomainResult {self.domain!r}: {len(self.dns)} records, "
            f"{len(self.subdomains)} subdomains>"
        )


# ─── phone ────────────────────────────────────────────────


@dataclass(slots=True)
class PhoneResult(Model):
    query: str
    valid: bool = False
    possible: bool = False
    e164: str = ""
    international: str = ""
    national: str = ""
    country_code: int = 0
    region: str = ""
    location: str = ""
    carrier: str = ""
    timezone: str = ""
    line_type: str = ""
    duration_ms: int = 0

    def __bool__(self) -> bool:
        return self.valid

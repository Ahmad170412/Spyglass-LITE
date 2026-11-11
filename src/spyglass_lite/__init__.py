"""spyglass-lite — importable OSINT recon without external binaries.

    import spyglass_lite as sg

    result = sg.username("johndoe")
    for profile in result:
        print(profile.url, profile.confidence)

    client = sg.lite(timeout=8, concurrency=100)
    client.email("me@example.com")

Every module returns a typed dataclass with ``to_dict()`` for JSON. Blocked
or rate-limited sites are reported in ``unknown`` rather than silently
counted as absent.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from .client import AsyncSpyglass, Spyglass, lite
from .config import Config
from .errors import InvalidTarget, MissingDependency, NetworkError, SpyglassError
from .models import (
    Account,
    AsnResult,
    Breach,
    DnsRecord,
    DomainResult,
    EmailResult,
    Geo,
    Gravatar,
    IpResult,
    MxRecord,
    PhoneResult,
    Profile,
    Registration,
    RpkiValidation,
    Subdomain,
    Unknown,
    UsernameResult,
)

__version__ = "1.1.0"

__all__ = [
    # client
    "lite",
    "Spyglass",
    "AsyncSpyglass",
    "Config",
    "configure",
    "default",
    # functions
    "detect",
    "lookup",
    "username",
    "email",
    "ip",
    "asn",
    "domain",
    "phone",
    "phone_info",
    # models
    "UsernameResult",
    "Profile",
    "Unknown",
    "EmailResult",
    "Gravatar",
    "Account",
    "MxRecord",
    "Breach",
    "Registration",
    "IpResult",
    "Geo",
    "AsnResult",
    "DomainResult",
    "DnsRecord",
    "Subdomain",
    "RpkiValidation",
    "PhoneResult",
    # errors
    "SpyglassError",
    "InvalidTarget",
    "MissingDependency",
    "NetworkError",
    "__version__",
]

_default: Spyglass | None = None


def default() -> Spyglass:
    """The client used by the module-level functions."""
    global _default
    if _default is None:
        _default = lite()
    return _default


def configure(**options: Any) -> Spyglass:
    """Replace the default client's configuration and return it.

    ``sg.configure(concurrency=100, timeout=8)`` affects every subsequent
    module-level call.
    """
    global _default
    _default = lite(**options)
    return _default


def username(
    target: str,
    *,
    judge: bool | None = None,
    strict: bool | None = None,
    verify_catchall: bool | None = None,
    sites: Iterable[str] | None = None,
    deadline: float | None = None,
    tags: Iterable[str] | None = None,
    only: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
    limit: int | None = None,
    include_unknown: bool = True,
    on_result: Callable[[Profile], None] | None = None,
) -> UsernameResult:
    """Enumerate platforms where a handle exists.

    ``deadline`` stops after N seconds and returns what was decided by then
    (``result.partial`` reports whether it cut short), ``sites`` limits the
    scan to named sites (display names, domains or URLs), and ``judge=False``
    runs the raw dataset rule with no verification layer. See
    :meth:`Spyglass.ausername` for every option.
    """
    return default().username(
        target,
        judge=judge,
        strict=strict,
        verify_catchall=verify_catchall,
        sites=sites,
        deadline=deadline,
        tags=tags,
        only=only,
        exclude=exclude,
        limit=limit,
        include_unknown=include_unknown,
        on_result=on_result,
    )


def email(
    target: str,
    *,
    gravatar: bool = True,
    breaches: bool = True,
    registrations: bool = False,
    recipes_path: str | None = None,
    sites: Sequence[Mapping[str, Any] | str] | None = None,
    dns_timeout: float = 4.0,
) -> EmailResult:
    """Validate an address and collect the passive intelligence around it.

    ``registrations=True`` adds active account-existence recipes, and
    ``sites`` passes recipe dicts and/or bundled domains inline. See
    :meth:`Spyglass.aemail` for every option.
    """
    return default().email(
        target,
        gravatar=gravatar,
        breaches=breaches,
        registrations=registrations,
        recipes_path=recipes_path,
        sites=sites,
        dns_timeout=dns_timeout,
    )


def ip(
    target: str,
    *,
    whois: bool = True,
    ports: bool = True,
) -> IpResult:
    """Geolocate, reverse-resolve and enrich an address or hostname."""
    return default().ip(target, whois=whois, ports=ports)


def asn(target: str) -> AsnResult:
    """Resolve the prefix, origin AS and RPKI state for an IP, prefix or AS."""
    return default().asn(target)


def domain(
    target: str,
    *,
    ct: bool = True,
    whois: bool = True,
    resolve: bool = True,
    wordlist: bool = False,
    dns_timeout: float = 4.0,
) -> DomainResult:
    """Resolve DNS, discover subdomains and run WHOIS for a domain."""
    return default().domain(
        target,
        ct=ct,
        whois=whois,
        resolve=resolve,
        wordlist=wordlist,
        dns_timeout=dns_timeout,
    )


def phone_info(target: str) -> PhoneResult:
    """Offline provider/region info for a number (no network search)."""
    return default().phone_info(target)


# Common TLDs used to guess whether a bare token is a domain name.
_KNOWN_TLDS = frozenset(
    {
        "com",
        "net",
        "org",
        "io",
        "co",
        "dev",
        "app",
        "info",
        "me",
        "uk",
        "de",
        "fr",
        "nl",
        "eu",
        "ru",
        "cn",
        "jp",
        "br",
        "au",
        "ca",
        "us",
        "in",
        "it",
        "es",
        "pl",
        "se",
        "no",
        "fi",
        "dk",
        "ch",
        "at",
        "be",
        "pt",
        "cz",
        "nz",
        "za",
        "kr",
        "tw",
        "hk",
        "sg",
        "my",
        "th",
        "id",
        "ph",
        "vn",
        "mx",
        "ar",
        "cl",
        "pe",
        "edu",
        "gov",
        "mil",
        "biz",
        "name",
        "pro",
        "xyz",
        "tech",
        "online",
        "site",
        "top",
        "club",
        "live",
        "cloud",
        "ai",
        "sh",
        "gg",
        "tv",
    }
)


def detect(target: str) -> str:
    """Guess the kind of a target: email, phone, ip, asn, domain or username.

    Returns one of ``"email"``, ``"phone"``, ``"ip"``, ``"asn"``, ``"domain"``
    or ``"username"``. Ambiguous single-token inputs default to ``"username"``.
    """
    value = str(target).strip()
    if not value:
        return "username"
    if "@" in value:
        return "email"
    if value.startswith("+"):
        return "phone"
    # IP address
    try:
        import ipaddress

        ipaddress.ip_address(value.strip("[]"))
        return "ip"
    except ValueError:
        pass
    # ASN or prefix
    if value.upper().startswith("AS") and value[2:].isdigit():
        return "asn"
    if "/" in value:
        try:
            import ipaddress

            ipaddress.ip_network(value, strict=False)
            return "asn"
        except ValueError:
            pass
    # Domain: final label must be a known TLD
    host = value.lower()
    if "://" in host:
        from urllib.parse import urlparse

        host = urlparse(host).hostname or host
    host = host.strip("[]").rstrip(".")
    if "." in host and " " not in host and "/" not in host:
        tld = host.rsplit(".", 1)[-1]
        if tld in _KNOWN_TLDS:
            return "domain"
    return "username"


def lookup(target: str, *, kind: str = "auto", **options: Any) -> Any:
    """One call that picks the right module for a target.

    ``kind="auto"`` (the default) uses :func:`detect` to choose. Pass an
    explicit ``kind`` (``"username"``, ``"email"``, ``"ip"``, ``"asn"``,
    ``"domain"``, ``"phone"``) to override, and any module-specific options
    via keyword arguments::

        sg.lookup("torvalds")
        sg.lookup("me@example.com", breaches=False)
        sg.lookup("example.com", kind="domain", wordlist=True)
    """
    chosen = detect(target) if kind == "auto" else kind
    if chosen == "email":
        return email(target, **options)
    if chosen == "phone":
        return phone(target)
    if chosen == "ip":
        return ip(target, **options)
    if chosen == "asn":
        return asn(target)
    if chosen == "domain":
        return domain(target, **options)
    return username(target, **options)


def phone(target: str) -> PhoneResult:
    """Describe a phone number offline (needs the ``[phone]`` extra)."""
    return default().phone(target)

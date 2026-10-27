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
    EmailResult,
    Geo,
    Gravatar,
    IpResult,
    MxRecord,
    PhoneResult,
    Profile,
    Registration,
    RpkiValidation,
    Unknown,
    UsernameResult,
)

__version__ = "0.9.0b0"

__all__ = [
    # client
    "lite",
    "Spyglass",
    "AsyncSpyglass",
    "Config",
    "configure",
    "default",
    # functions
    "username",
    "email",
    "ip",
    "asn",
    "phone",
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


def phone(target: str) -> PhoneResult:
    """Describe a phone number offline (needs the ``[phone]`` extra)."""
    return default().phone(target)

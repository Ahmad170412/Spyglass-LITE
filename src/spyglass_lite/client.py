"""The importable client.

Two entry points, one engine:

    import spyglass_lite as sg
    sg.username("johndoe")                 # module-level, default client

    client = sg.lite(concurrency=100)      # configured client
    client.username("johndoe")

    async with sg.AsyncSpyglass() as c:    # asyncio
        await c.ausername("johndoe")

Sync calls build a fresh HTTP client per scan. That is deliberate: an
``httpx.AsyncClient`` is bound to the event loop that created it, and a
long-lived client shared across ``asyncio.run()`` calls is the classic way
to get "Event loop is closed" in a library. Connection pooling inside a
scan (thousands of requests) is what matters; reconnecting between scans is
not.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from . import asn as _asn
from . import email as _email
from . import ip as _ip
from . import phone as _phone
from . import username as _username
from .config import Config
from .models import (
    AsnResult,
    EmailResult,
    IpResult,
    PhoneResult,
    Profile,
    UsernameResult,
)


def _run_sync(factory: Any) -> Any:
    """Run an async scan from sync code, including inside a running loop.

    ``asyncio.run`` raises if a loop is already running (Jupyter, async web
    handlers). In that case the scan runs in a worker thread with its own
    loop, which keeps the caller's loop untouched.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(factory())).result()


class Spyglass:
    """A configured recon client."""

    def __init__(self, **options: Any) -> None:
        self.config = Config.build(**options)

    # ── transport ─────────────────────────────────────────

    def _http(self) -> httpx.AsyncClient:
        cfg = self.config
        return httpx.AsyncClient(
            headers={
                "user-agent": cfg.user_agent,
                "accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            },
            timeout=httpx.Timeout(cfg.timeout),
            proxy=cfg.proxy,
            verify=cfg.verify_tls,
            follow_redirects=cfg.follow_redirects,
            limits=httpx.Limits(
                max_connections=max(20, cfg.concurrency * 2),
                max_keepalive_connections=max(10, cfg.concurrency),
            ),
        )

    # ── username ──────────────────────────────────────────

    async def ausername(
        self,
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
        """Check one handle across the bundled site list.

        ``deadline`` stops the scan after that many seconds and returns what
        has been decided by then; ``result.partial`` says whether the clock
        cut it short.

        ``sites`` narrows the scan to named sites — display names, domains or
        full URLs (``sites=["github.com", "https://x.com/someone"]``) — and is
        merged with ``only``.

        ``judge=False`` reproduces the raw dataset rule with no verification
        layer and no catch-all probe, which is the mode used to compare
        against Sherlock/Maigret output. ``strict`` is the old name for the
        same knob and is still accepted; passing both with different values
        raises ``InvalidTarget``.

        ``verify_catchall`` costs one extra request per rule the first time
        it is seen (then a short-lived cache) and rejects sites that serve the
        same page for every handle.

        ``only``, ``exclude``, ``tags`` and ``limit`` narrow the site list;
        see :func:`spyglass_lite._registry.select`. ``include_unknown`` keeps
        the undecided sites in ``result.unknown``, and ``on_result`` is called
        for each profile as it is confirmed.
        """
        async with self._http() as http:
            return await _username.scan(
                http,
                target,
                self.config,
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

    def username(
        self,
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
        """Blocking :meth:`ausername`; see there for the options."""
        return _run_sync(
            lambda: self.ausername(
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
        )

    async def ausername_many(
        self,
        targets: Sequence[str],
        *,
        workers: int = 4,
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
    ) -> list[UsernameResult]:
        """Run :meth:`ausername` for several handles concurrently.

        ``workers`` caps how many handles are in flight at once; every other
        option is passed through unchanged to each scan.
        """
        semaphore = asyncio.Semaphore(max(1, workers))

        async with self._http() as http:

            async def one(target: str) -> UsernameResult:
                async with semaphore:
                    return await _username.scan(
                        http,
                        target,
                        self.config,
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

            return list(await asyncio.gather(*(one(t) for t in targets)))

    def username_many(
        self,
        targets: Sequence[str],
        *,
        workers: int = 4,
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
    ) -> list[UsernameResult]:
        """Blocking :meth:`ausername_many`."""
        return _run_sync(
            lambda: self.ausername_many(
                targets,
                workers=workers,
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
        )

    # ── email ─────────────────────────────────────────────

    async def aemail(
        self,
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

        Tier A (syntax, MX, SPF/DMARC, Gravatar, breaches) runs by default.
        ``registrations=True`` adds the Tier B account-existence recipes from
        ``recipes_path`` (bundled list when omitted), and ``sites`` checks
        specific sites only: inline recipe dicts (schema in docs/RECIPES.md)
        and/or bare domains matched against the bundled recipes. A domain
        with no recipe is reported inconclusive with the reason, never
        guessed.
        """
        async with self._http() as http:
            return await _email.scan(
                http,
                target,
                self.config,
                gravatar=gravatar,
                breaches=breaches,
                registrations=registrations,
                recipes_path=recipes_path,
                sites=sites,
                dns_timeout=dns_timeout,
            )

    def email(
        self,
        target: str,
        *,
        gravatar: bool = True,
        breaches: bool = True,
        registrations: bool = False,
        recipes_path: str | None = None,
        sites: Sequence[Mapping[str, Any] | str] | None = None,
        dns_timeout: float = 4.0,
    ) -> EmailResult:
        """Blocking :meth:`aemail`; see there for the options."""
        return _run_sync(
            lambda: self.aemail(
                target,
                gravatar=gravatar,
                breaches=breaches,
                registrations=registrations,
                recipes_path=recipes_path,
                sites=sites,
                dns_timeout=dns_timeout,
            )
        )

    # ── ip ────────────────────────────────────────────────

    async def aip(
        self,
        target: str,
        *,
        whois: bool = True,
        ports: bool = True,
    ) -> IpResult:
        """Geolocate, reverse-resolve and enrich an address or hostname.

        ``ports=False`` skips the passive Shodan InternetDB lookup, and
        ``whois=False`` skips the WHOIS query; both are on by default.
        """
        async with self._http() as http:
            return await _ip.scan(http, target, self.config, whois=whois, ports=ports)

    def ip(
        self,
        target: str,
        *,
        whois: bool = True,
        ports: bool = True,
    ) -> IpResult:
        """Blocking :meth:`aip`; see there for the options."""
        return _run_sync(lambda: self.aip(target, whois=whois, ports=ports))

    # ── asn ───────────────────────────────────────────────

    async def aasn(self, target: str) -> AsnResult:
        """Resolve the prefix, origin AS and RPKI state for an IP, prefix or AS."""
        async with self._http() as http:
            return await _asn.scan(http, target, self.config)

    def asn(self, target: str) -> AsnResult:
        """Blocking :meth:`aasn`."""
        return _run_sync(lambda: self.aasn(target))

    # ── phone ─────────────────────────────────────────────

    async def aphone(self, target: str) -> PhoneResult:
        """Describe a phone number offline (needs the ``[phone]`` extra)."""
        return _phone.scan(target)

    def phone(self, target: str) -> PhoneResult:
        """Blocking :meth:`aphone`."""
        return _run_sync(lambda: self.aphone(target))

    # ── lifecycle ─────────────────────────────────────────

    async def __aenter__(self) -> Spyglass:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    def __enter__(self) -> Spyglass:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def __repr__(self) -> str:
        cfg = self.config
        return (
            f"Spyglass(timeout={cfg.timeout}, concurrency={cfg.concurrency}, "
            f"per_host={cfg.per_host}, proxy={cfg.proxy!r})"
        )


# The async entry point is the same object; the alias exists so the documented
# ``async with sg.AsyncSpyglass()`` reads as what it is.
AsyncSpyglass = Spyglass


def lite(**options: Any) -> Spyglass:
    """Create a configured client.

    ``sg.lite()`` with no arguments is equivalent to using the module-level
    functions, which share a lazily-created default client.
    """
    return Spyglass(**options)

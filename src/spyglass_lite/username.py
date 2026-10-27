"""Username enumeration.

One async engine executes the bundled per-site rules. There is no subprocess
and no external binary: the rules are data, and the engine is this file.

The interesting part is not the request, it is the verdict. Every candidate
is judged against three layers:

1. the rule the site's own entry defines (status code, message, or redirect)
2. generic page sanity — bot walls, not-found titles, registration prompts,
   empty single-page-app shells
3. a handle-echo check used as a confidence signal, not a gate

Layer 3 is deliberately not a gate. YouTube profiles are titled with a display
name ("Nat"), not the handle, so requiring the handle in the title throws away
real accounts. It is evidence when present and silence when absent.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

import httpx

from . import _registry
from ._http import Fetch, Throttle, Verdict, request_with_retries, urls_for
from ._http import judge as _judge
from .errors import InvalidTarget
from .models import Profile, Unknown, UsernameResult

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config

# Handles are nearly always ASCII. Anything with a slash or whitespace is a
# URL accident, not a handle, and letting it through turns a typo into 2,000
# malformed requests.
_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}

# A handle that will not exist anywhere, used to test whether a site's rule
# can distinguish a real account from its catch-all route.
_CATCHALL_HANDLE = "zq9x7v3k2m1p"

# The control probe always asks with the same garbage handle, so its answer
# does not depend on the handle being scanned. Cache it per rule: otherwise
# every scan pays a second request per hit for a page that was already
# fetched on the last one.
_CONTROL_TTL = 600.0  # seconds
_CONTROL_MAX = 4096

# A slow control probe must not turn a real profile into "unknown" — and it
# is the slowest request in a scan, since the garbage handle often takes a
# redirect chain that a real profile skips. Keep the old 10s floor for it
# even when the scan itself runs at the 6s default; it is one request per
# rule and cached, so the cost is bounded and mostly paid once.
_CONTROL_TIMEOUT_FLOOR = 10.0
_controls: dict[str, tuple[float, str, int]] = {}  # key -> (at, state, body size)


def _control_key(site: dict[str, Any]) -> str:
    """Identity of a site's control probe (fixed handle, so stable per rule)."""
    url, _ = urls_for(site, _CATCHALL_HANDLE)
    method = str(site.get("method") or "GET").upper()
    payload = json.dumps(site.get("payload"), sort_keys=True, default=str)
    return f"{method}|{url}|{payload}"


def _distinctive(real: Fetch, control_size: int, handle: str) -> bool:
    """Is the real page meaningfully different from the catch-all page?

    Two signals, both required-ish: the real page mentions the handle, and it
    is materially larger than the page served for a garbage handle. A site
    that returns the same app shell for everyone fails both, which is the
    correct answer — its rule cannot tell an account from a 404.
    """
    mentions = real.text.lower().count(handle.lower())
    ratio = len(real.text) / max(control_size, 1)
    return (mentions >= 3 and ratio >= 1.2) or (mentions >= 1 and ratio >= 2.0)


def _canonical_url(site: dict[str, Any], result: Fetch, fallback: str) -> str:
    """Prefer a URL the site itself reports over the templated one.

    Some APIs return the canonical profile URL in their payload (Mastodon
    preserves the account's original capitalisation, so ``/@lowercase`` can
    404 while the account exists). ``profile_field`` is a dot path into the
    probe's JSON, only set on curated entries.
    """
    field = site.get("profile_field")
    if not field or not result.json_like:
        return fallback
    try:
        value: Any = json.loads(result.text)
    except (ValueError, TypeError):
        return fallback
    for part in str(field).split("."):
        if not isinstance(value, dict):
            return fallback
        value = value.get(part)
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        return value
    return fallback


def validate(target: str) -> str:
    """Normalise and validate a handle.

    A leading ``@`` is stripped because that is how handles are written in
    the wild, not because sites accept it in a URL.
    """
    value = str(target).strip().lstrip("@")
    if not value:
        raise InvalidTarget("username is empty")
    if not _HANDLE_RE.match(value):
        raise InvalidTarget(
            f"{target!r} is not a valid handle: expected 1-64 characters of "
            "letters, digits, dot, underscore or hyphen, starting with a letter or digit"
        )
    return value


async def _catchall_probe(
    http: httpx.AsyncClient,
    site: dict[str, Any],
    config: Config,
    throttle: Throttle,
) -> Fetch:
    """Ask the site for a handle that cannot exist.

    If the site's own rule passes for a garbage handle, the rule proves
    nothing — the route is a catch-all. This is the check Sherlock does not
    do, and it is why its results include empty profile shells.
    """
    url, _ = urls_for(site, _CATCHALL_HANDLE)
    async with throttle.slot(url):
        result, _ = await request_with_retries(
            http,
            site,
            _CATCHALL_HANDLE,
            timeout=max(config.timeout, _CONTROL_TIMEOUT_FLOOR),
            retries=1,
            backoff=config.backoff,
            follow_redirects=config.follow_redirects,
        )
    return result


async def _control_verdict(
    http: httpx.AsyncClient,
    site: dict[str, Any],
    config: Config,
    throttle: Throttle,
) -> tuple[str, int]:
    """``(state, body size)`` for the site's catch-all control, cached.

    A transport failure is not cached — one flaky connection must not poison
    the rule for the next ten minutes — but any real answer is, because the
    control probe is handle-independent.
    """
    key = _control_key(site)
    now = time.monotonic()
    hit = _controls.get(key)
    if hit is not None and now - hit[0] < _CONTROL_TTL:
        return hit[1], hit[2]

    control = await _catchall_probe(http, site, config, throttle)
    state = _judge(site, control, _CATCHALL_HANDLE, strict=False).state
    if not control.error:
        if len(_controls) >= _CONTROL_MAX:
            cutoff = now - _CONTROL_TTL
            for stale in [k for k, (at, _, _) in _controls.items() if at < cutoff]:
                del _controls[stale]
            while len(_controls) >= _CONTROL_MAX:
                _controls.popitem()
        _controls[key] = (now, state, len(control.text))
    return state, len(control.text)


async def scan(
    http: httpx.AsyncClient,
    target: str,
    config: Config,
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

    ``judge`` runs the verification layer — titles, shells, search pages,
    visible-copy handle echoes. ``judge=False`` reproduces the raw dataset
    rule with no verification *and* no catch-all probe (unless you ask for
    it explicitly), which is the mode used to compare against Sherlock
    apples-to-apples. ``strict=`` is the old name for the same knob and is
    still accepted; passing both with different values raises.

    ``sites`` narrows the scan to named sites — display names, domains or
    full URLs (``sites=["github.com", "https://x.com/someone"]``) — and is
    merged with ``only``.

    ``deadline`` stops the scan after that many seconds and returns what had
    been decided by then; ``result.partial`` says whether it cut short.

    ``verify_catchall`` costs one extra request per candidate hit the first
    time a rule is seen (then serves from a short-lived cache) and rejects
    sites that serve the same page for every handle.

    ``only``, ``exclude``, ``tags`` and ``limit`` narrow the site list; see
    :func:`spyglass_lite._registry.select`.
    """
    started = time.perf_counter()
    handle = validate(target)

    if judge is not None and strict is not None and bool(judge) != bool(strict):
        raise InvalidTarget("judge= and strict= disagree; pass only one (strict= is the old name)")
    chosen = judge if judge is not None else strict
    run_verification = True if chosen is None else bool(chosen)
    catchall = run_verification if verify_catchall is None else verify_catchall

    if sites is not None:
        picked = list(sites)
        if not picked:
            raise InvalidTarget("sites list is empty")
        only = list(only or ()) + picked

    if deadline is not None and deadline <= 0:
        raise InvalidTarget("deadline must be greater than zero")

    selected = _registry.select(tags=tags, only=only, exclude=exclude, limit=limit)
    if not selected:
        raise InvalidTarget("no sites matched the given filters")

    throttle = Throttle(config.concurrency, config.per_host)
    found: list[Profile] = []
    unknown: list[Unknown] = []
    errors: list[str] = []
    checked = 0
    skipped = 0
    seen: set[str] = set()

    async def check(site: dict[str, Any]) -> None:
        nonlocal checked, skipped

        pattern = site.get("regex")
        if pattern:
            try:
                if not re.search(pattern, handle):
                    skipped += 1
                    return
            except re.error:
                # A broken regex in the dataset must not drop the site.
                pass

        checked += 1
        request_url, _ = urls_for(site, handle)
        try:
            async with throttle.slot(request_url):
                result, profile_url = await request_with_retries(
                    http,
                    site,
                    handle,
                    timeout=config.timeout,
                    retries=config.retries,
                    backoff=config.backoff,
                    follow_redirects=config.follow_redirects,
                )
        except Exception as exc:  # noqa: BLE001 - one site must not kill a scan
            errors.append(f"{site['domain']}: {type(exc).__name__}: {exc}")
            return

        verdict = _judge(site, result, handle, strict=run_verification)
        domain = str(site["domain"])

        if verdict.state == "found":
            profile_url = _canonical_url(site, result, profile_url)

        if verdict.state == "found" and catchall:
            control_state, control_size = await _control_verdict(http, site, config, throttle)
            if control_state == "unknown":
                # Fail closed: without a usable control, the rule cannot be
                # shown to distinguish an account from a catch-all route.
                verdict = Verdict(
                    "unknown",
                    "low",
                    "could not verify (control probe unavailable)",
                )
            elif control_state == "found" and not _distinctive(result, control_size, handle):
                verdict = Verdict(
                    "unknown",
                    "low",
                    "catch-all route (same page for any handle)",
                )

        if verdict.state == "found":
            if domain in seen:
                return
            seen.add(domain)
            profile = Profile(
                platform=str(site["name"]),
                domain=domain,
                url=profile_url,
                confidence=verdict.confidence,  # type: ignore[arg-type]
                evidence=verdict.evidence,
                status=result.status or None,
            )
            found.append(profile)
            if on_result is not None:
                on_result(profile)
        elif verdict.state == "unknown" and include_unknown:
            unknown.append(
                Unknown(platform=str(site["name"]), domain=domain, reason=verdict.evidence)
            )

    partial = False
    tasks = [asyncio.create_task(check(site)) for site in selected]
    if deadline is None:
        await asyncio.gather(*tasks)
    else:
        # Stop the clock and keep what was decided: an OSINT question that can
        # wait 30 seconds is answered from the sites that answered in 30
        # seconds, not with a timeout error after all of them tried.
        _, pending = await asyncio.wait(tasks, timeout=deadline)
        partial = bool(pending)
        for task in pending:
            task.cancel()
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        for value in outcomes:
            if isinstance(value, BaseException) and not isinstance(value, asyncio.CancelledError):
                errors.append(f"scan task failed: {type(value).__name__}: {value}")

    found.sort(key=lambda p: (_CONF_RANK.get(p.confidence, 3), p.platform.lower()))
    unknown.sort(key=lambda u: u.platform.lower())

    return UsernameResult(
        target=handle,
        found=found,
        unknown=unknown,
        checked=checked,
        skipped=skipped,
        duration_ms=int((time.perf_counter() - started) * 1000),
        strict=run_verification,
        errors=sorted(set(errors)),
        partial=partial,
    )

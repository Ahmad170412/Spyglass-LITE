"""HTTP fetching and the existence verdict ladder.

A 2xx response is not evidence that an account exists. Single-page apps
return their shell, bot walls return an interstitial, and catch-all profile
routes return somebody else's page — all with a success status. This module
turns a response into one of three honest answers:

``found``    the rule matched and the page survived verification
``absent``   the site said no
``unknown``  the site refused to answer (403/429/challenge/timeout)

The distinction is the point. A scan that reports a Cloudflare wall as "not
found" is lying with a straight face, and a tool that quietly drops those
sites is worse than one that admits it could not tell.

The challenge / not-found / empty-shell heuristics are adapted from Spyglass
OSINT's ``utils._verify`` (MIT, see NOTICE).
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import httpx

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
# Review yearly. Some bot walls (Codeberg, as of 2026) reject a UA whose
# Chrome major is old even though the request is otherwise identical.

MAX_BODY = 200_000

# Titles live in <head>, but a page can put megabytes of inline CSS in front
# of one. Bounded so a hostile (or merely enormous) document cannot turn the
# title scan into a quadratic one.
MAX_TITLE_SCAN = 32_768

# A fetch must not be usable as an SSRF primitive. Only literal addresses and
# a handful of internal names are checked here — resolving every hostname
# would add a DNS round trip to a scan that already makes 2,000 requests.
_INTERNAL_HOSTS = frozenset({"localhost", "metadata", "metadata.google.internal"})

# Statuses that mean "ask again later", not "this page does not exist".
TRANSIENT_CODES = frozenset({0, 408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 524})

_CHALLENGE_BODY = (
    "cf-browser-verification",
    "cf_chl_opt",
    "cf-turnstile",
    "checking your browser before accessing",
    "enable javascript and cookies",
    "ddos protection by",
    "px-captcha",
    "please stand by, we are checking",
)

_CHALLENGE_TITLES = (
    "just a moment",
    "attention required",
    "security verification",
    "client challenge",
    "checking your browser",
    "one more step",
    "are you a robot",
    "verify you are human",
    "access denied",
    "please verify",
    "ddos protection",
    "bot verification",
    "403 forbidden",
    "too many requests",
    "rate limit",
    "please enable cookies",
    "checking if the site connection is secure",
)

# Title-only. In the body these phrases are far too common to be evidence:
# forum templates and ad scripts say "not found" in unrelated copy.
_NOTFOUND_TITLES = (
    "page not found",
    "404",
    "not found",
    "doesn't exist",
    "does not exist",
    "isn't available",
    "is not available",
    "no longer available",
    "user not found",
    "profile not found",
    "nothing found",
    "no results",
    "content not found",
    "not exist",
)

# A signup prompt returned for a profile URL is a page about creating an
# account, not a profile. Observed: strava.com returns 200 with a 610KB
# "Signup for free to see more about <name>" page for any slug.
_INTERSTITIAL_TITLES = (
    "sign up",
    "signup",
    "sign-in",
    "sign in",
    "create an account",
    "create account",
    "join now",
    "join us",
    "get started",
    "log in",
    "login",
    "register",
    "subscribe",
    "start your",
    "unlock the",
)

# A real profile carries navigation, scripts and copy. The observed shells
# were ~1.4KB (an empty SPA frame) and ~6KB (a JS bundle with no profile).
MIN_BODY_BYTES = 1500

# ``[^<]*`` rather than a lazy ``.*`` with DOTALL: a body containing many
# unterminated ``<title`` tags makes the lazy form backtrack quadratically.
_TITLE_RE = re.compile(r"<title[^>]*>([^<]*)</title>", re.IGNORECASE)

# Redirect targets that are never a profile. A rule that lands on one of
# these has told us "no such page", not "here is the account".
_NON_PROFILE_SEGMENTS = frozenset(
    {
        "explore",
        "search",
        "login",
        "signin",
        "sign-in",
        "signup",
        "sign-up",
        "register",
        "auth",
        "error",
        "404",
    }
)

# Host labels that mean "identity provider", not "this person's profile".
_SIGNIN_HOST_LABELS = frozenset(
    {"sso", "passport", "login", "signin", "sign-in", "auth", "accounts", "idp"}
)

# Query parameters that ask a site a question rather than name a profile.
_SEARCH_PARAMS = frozenset(
    {"q", "query", "search", "search_text", "searchtext", "search_query", "keyword", "keywords"}
)

# Path segments that address a listing page, never a person.
_SEARCH_SEGMENTS = frozenset(
    {"search", "searches", "filter", "filters", "query", "results", "find"}
)

_SEARCH_TITLE_RE = re.compile(
    r"search results|\bresults for\b|^\s*search\s*[-|:]|[-|:]\s*search\s*$|^\s*search\s*$",
    re.IGNORECASE,
)

# Echoes inside links and metadata are the URL talking, not the page. A
# template with the handle in three hrefs reaches the old mention threshold
# without ever naming anybody in visible copy.
_LINK_RE = re.compile(r"https?://\S+|(?:href|src|action)\s*=\s*[\"'][^\"']*[\"']", re.IGNORECASE)


# ─── fetch ─────────────────────────────────────────────────


@dataclass(slots=True)
class Fetch:
    status: int = 0
    url: str = ""
    requested_url: str = ""
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""
    elapsed_ms: int = 0

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def json_like(self) -> bool:
        if "json" in self.content_type.lower():
            return True
        head = self.text.lstrip()[:1]
        return head in {"{", "["}

    @property
    def is_html(self) -> bool:
        """Whether the HTML-only heuristics are meaningful for this body.

        Applying a 1.5KB "empty shell" floor to an RSS feed or a JSON API is
        a false negative: a 2-byte ``[]`` is a complete, valid answer.
        """
        content_type = self.content_type.lower()
        if "html" in content_type:
            return True
        # Sniff before trusting the header: servers mislabel HTML as
        # text/plain often enough that the body is the better witness.
        head = self.text[:2000].lower()
        if "<html" in head or "<!doctype html" in head:
            return True
        if any(token in content_type for token in ("xml", "json", "text/plain", "csv")):
            return False
        return False


def render(template: str, username: str, *, quote_value: bool = True) -> str:
    """Substitute the handle into a dataset template.

    Both placeholders used upstream are supported: ``{username}`` (maigret)
    and ``{}`` (sherlock). The value is URL-quoted for URLs; payload values
    are left raw so a form or JSON body is not silently percent-encoded.
    """
    value = quote(username, safe="") if quote_value else username
    return template.replace("{username}", value).replace("{}", value)


def urls_for(site: Mapping[str, Any], username: str) -> tuple[str, str]:
    """Return ``(request_url, profile_url)``.

    ``urlProbe`` is requested when present because it is usually a JSON
    endpoint the site actually lets an anonymous client read, while ``url``
    stays the human-facing profile that gets reported.
    """
    profile = render(str(site["url"]), username)
    probe = site.get("probe")
    return (render(str(probe), username) if probe else profile), profile


def _render_payload(payload: Any, username: str) -> Any:
    if isinstance(payload, dict):
        return {k: _render_payload(v, username) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_render_payload(v, username) for v in payload]
    if isinstance(payload, str):
        return render(payload, username, quote_value=False)
    return payload


def _private_host(host: str) -> bool:
    """Whether a literal host points somewhere a public fetch must not go.

    This is a floor, not a full SSRF defence: a hostname that *resolves* to a
    private address is not caught here, and neither is a redirect into one.
    It does stop the two cases that matter in practice — a recipe pointed at
    ``169.254.169.254`` and one pointed at ``127.0.0.1``.
    """
    host = (host or "").strip("[]").lower().rstrip(".")
    if not host:
        # No host at all is a malformed URL; let httpx report it as such.
        return False
    if host in _INTERNAL_HOSTS:
        return True
    if host.endswith(".localhost") or host.endswith(".internal"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global


def _blocked_reason(url: str) -> str:
    """Why this URL must not be fetched, or ``""`` when it may be."""
    if _private_host(urlparse(url).hostname or ""):
        return "blocked host (private, loopback or internal address)"
    return ""


async def fetch(
    http: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    payload: Any = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
) -> Fetch:
    """One request, with every transport failure turned into data.

    The body is read as a stream and cut off at :data:`MAX_BODY`. Reading the
    whole response first and truncating afterwards lets a single hostile host
    allocate arbitrarily much memory inside a scan that runs fifty of these at
    once — the one failure mode that takes down the process rather than the
    request.
    """
    blocked = _blocked_reason(url)
    if blocked:
        return Fetch(requested_url=url, error=blocked)

    method = (method or "GET").upper()
    start = time.perf_counter()
    kwargs: dict[str, Any] = {}
    if payload and method in {"POST", "PUT", "PATCH"}:
        content_type = str((headers or {}).get("content-type", "")).lower()
        if "json" in content_type:
            kwargs["json"] = payload
        else:
            kwargs["data"] = payload if isinstance(payload, dict) else {"value": payload}

    try:
        async with http.stream(
            method,
            url,
            headers=dict(headers or {}) or None,
            timeout=timeout,
            follow_redirects=follow_redirects,
            **kwargs,
        ) as response:
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY:
                    break
            raw = b"".join(chunks)[:MAX_BODY]
            try:
                text = raw.decode(response.encoding or "utf-8", "replace")
            except LookupError:  # a bogus charset in the header
                text = raw.decode("utf-8", "replace")
            return Fetch(
                status=response.status_code,
                url=str(response.url),
                requested_url=url,
                text=text,
                headers={k.lower(): v for k, v in response.headers.items()},
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
    except httpx.HTTPError as exc:
        elapsed = int((time.perf_counter() - start) * 1000)
        return Fetch(
            requested_url=url,
            error=f"{type(exc).__name__}: {str(exc)[:120]}",
            elapsed_ms=elapsed,
        )


async def request_with_retries(
    http: httpx.AsyncClient,
    site: Mapping[str, Any],
    username: str,
    *,
    timeout: float,
    retries: int,
    backoff: float,
    follow_redirects: bool,
) -> tuple[Fetch, str]:
    """Fetch a site's probe, retrying only transient HTTP statuses.

    A real verdict — a not-found title, a registration prompt, a body too
    small — is the same on the second request, so retrying those only costs
    time. A transport failure (dead host, refused connection, timeout) is
    not retried either: dead sites are the dominant cost of a 2,000-site
    scan, and a second attempt a second later almost never changes the
    answer while holding a concurrency slot for twice as long. Status
    transients — 429, 503 — are the only ones a second attempt can move.
    """
    url, profile = urls_for(site, username)
    headers = dict(site.get("headers") or {})
    payload = _render_payload(site.get("payload"), username)
    method = str(site.get("method") or "GET")

    last = Fetch(requested_url=url)
    for attempt in range(retries + 1):
        last = await fetch(
            http,
            method,
            url,
            headers=headers,
            payload=payload,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )
        transient = not last.error and last.status in TRANSIENT_CODES
        if not transient or attempt == retries:
            return last, profile
        delay = backoff * (attempt + 1)
        retry_after = last.headers.get("retry-after", "").strip()
        if retry_after.isdigit():
            delay = min(float(retry_after), 10.0)
        await asyncio.sleep(delay)
    return last, profile


# ─── verdict ───────────────────────────────────────────────


@dataclass(slots=True)
class Verdict:
    state: str  # found | absent | unknown
    confidence: str  # high | medium | low
    evidence: str


_BASE_CONFIDENCE = {"message": "high", "status_code": "medium", "response_url": "low"}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def _bump(confidence: str) -> str:
    return ("low", "medium", "high", "high")[_CONF_RANK.get(confidence, 0) + 1]


def _title(body: str) -> str:
    match = _TITLE_RE.search(body[:MAX_TITLE_SCAN])
    return match.group(1).strip().lower() if match else ""


def _visible(body: str) -> str:
    """Strip links and bare URLs, leaving the copy a person can read."""
    return _LINK_RE.sub(" ", body)


def _search_page(url: str, username: str) -> str:
    """Is this URL a results/listing page rather than a profile?

    Checked against both the rendered profile URL — what the report will
    claim the account is — and the URL actually fetched when it is HTML.
    An API answer from a search endpoint is judged by its rule instead; a
    human-facing search route is a listing of matches, and reporting it as
    an account is the classic false positive
    (``stackoverflow.com/users/filter?search=…``, ``scholar.google.com?q=…``).
    """
    handle = username.lower()
    parsed = urlparse(url)
    segments = {part for part in parsed.path.lower().split("/") if part}

    # A profile addressed by its handle in the path is that profile, whatever
    # tracking noise rides along in the query.
    if handle in segments:
        return ""

    hits = segments & _SEARCH_SEGMENTS
    if hits:
        return f"results route (/{sorted(hits)[0]}), not a profile"

    for name, values in parse_qs(parsed.query).items():
        if name.lower() in _SEARCH_PARAMS and any(handle in value.lower() for value in values):
            return f"search query ({name}=…), a listing page not a profile"
    return ""


def _non_profile_redirect(result: Fetch) -> str:
    """Name the non-profile destination a request was redirected into, if any."""
    requested = urlparse(result.requested_url)
    final = urlparse(result.url)
    req_path = requested.path.rstrip("/").lower().split("/")
    fin_path = final.path.rstrip("/").lower().split("/")

    if final.hostname and requested.hostname and final.hostname != requested.hostname:
        labels = set(final.hostname.lower().split("."))
        hit = labels & _SIGNIN_HOST_LABELS
        if hit:
            return f"sign-in host {final.hostname}"

    if fin_path == req_path:
        return ""
    introduced = set(fin_path) - set(req_path)
    hits = introduced & _NON_PROFILE_SEGMENTS
    return f"non-profile route (/{sorted(hits)[0]})" if hits else ""


def judge(
    site: Mapping[str, Any],
    result: Fetch,
    username: str,
    *,
    strict: bool = True,
) -> Verdict:
    """Turn one response into found / absent / unknown."""
    if result.error:
        return Verdict("unknown", "low", f"request failed ({result.error})")

    status = result.status
    if status in TRANSIENT_CODES:
        return Verdict("unknown", "low", f"http {status} (transient)")
    if status in {401, 403} and not site.get("ignore403"):
        return Verdict("unknown", "low", f"http {status} (blocked)")

    body = result.text or ""
    low = body.lower()
    check = site.get("check") or "status_code"

    # An empty body is never a profile. 202 is the classic "we accepted your
    # request and gave you nothing" bot response; 200-empty is a dead route.
    if not body.strip():
        state = "unknown" if status == 202 else "absent"
        return Verdict(state, "low", f"empty response (http {status})")

    # Dataset-supplied error pages, e.g. Instagram's "Login required".
    for marker, reason in (site.get("errors") or {}).items():
        if marker and marker.lower() in low:
            return Verdict("unknown", "low", f"site says: {reason}")

    if check == "status_code":
        if 200 <= status < 300:
            state, confidence, evidence = "found", "medium", f"http {status}"
        elif status in {404, 410}:
            state, confidence, evidence = "absent", "high", f"http {status}"
        else:
            return Verdict("unknown", "low", f"http {status}")

    elif check == "message":
        # A 404 cannot be a profile, whatever the body says. Some sites serve
        # a bespoke 404 page whose copy does not match the dataset's absence
        # marker, which used to read as "found".
        if status in {404, 410}:
            return Verdict("absent", "high", f"http {status}")
        absent_hits = [s for s in site.get("absent", ()) if s and s.lower() in low]
        present_hits = [s for s in site.get("present", ()) if s and s.lower() in low]
        if absent_hits:
            state, confidence = "absent", "high"
            evidence = f"absence marker {absent_hits[0][:40]!r}"
        elif site.get("present") and not present_hits:
            state, confidence = "absent", "medium"
            evidence = "presence marker missing"
        else:
            state, confidence = "found", "high"
            evidence = (
                f"presence marker {present_hits[0][:40]!r}" if present_hits else "no absence marker"
            )

    elif check == "response_url":
        absent_url = str(site.get("absent_url") or "").rstrip("/")
        final = result.url.rstrip("/")
        if status in {404, 410}:
            state, confidence, evidence = "absent", "high", f"http {status}"
        elif absent_url and (final == absent_url or final.startswith(absent_url + "/")):
            state, confidence, evidence = "absent", "high", "redirected to error page"
        elif absent_url or 200 <= status < 300:
            state, confidence, evidence = "found", "low", f"landed on {result.url[:60]}"
        else:
            return Verdict("unknown", "low", f"http {status}")

    else:
        return Verdict("unknown", "low", f"unsupported rule {check!r}")

    if not strict:
        return Verdict(state, confidence, evidence + " (unverified)")

    # ── verification layer ────────────────────────────────
    title = _title(body) if result.is_html else ""
    if result.is_html:
        for marker in _CHALLENGE_BODY:
            if marker in low:
                return Verdict("unknown", "low", "bot challenge")

        if title:
            if any(marker in title for marker in _CHALLENGE_TITLES):
                return Verdict("unknown", "low", f"challenge page ({title[:36]!r})")
            if any(marker in title for marker in _INTERSTITIAL_TITLES):
                return Verdict("unknown", "low", f"registration prompt ({title[:36]!r})")
            if state == "found" and _SEARCH_TITLE_RE.search(title):
                return Verdict("unknown", "low", f"search page ({title[:36]!r})")
            if state == "found" and any(marker in title for marker in _NOTFOUND_TITLES):
                state, confidence, evidence = "absent", "high", "title says not found"

        if state == "found" and len(body) < MIN_BODY_BYTES:
            state, confidence = "absent", "medium"
            evidence = f"empty page ({len(body)}B)"

    if state == "found":
        template = str(site.get("url") or "")
        reason = _search_page(render(template, username), username) if template else ""
        if not reason and result.is_html:
            reason = _search_page(result.url or result.requested_url, username)
        if reason:
            return Verdict("unknown", "low", reason)
        reason = _non_profile_redirect(result)
        if reason:
            return Verdict("unknown", "low", f"redirected to a {reason}")
        if not result.is_html and not result.json_like:
            # An HTML absence marker cannot be evaluated against an RSS or
            # XML document, so "no marker found" is not evidence of absence.
            return Verdict("unknown", "low", "non-HTML response; rule not applicable")

        if len(username) >= 3:
            handle = username.lower()
            # The gate counts every echo: a real profile is full of its own
            # URL in links and meta tags, and requiring three *visible*
            # mentions threw away real accounts (Twitch, Patreon). What the
            # visible-copy count decides is only whether the echoes are the
            # page talking or the URL talking: two visible mentions earn a
            # confidence upgrade, link-and-metadata echoes do not.
            mentions = low.count(handle)
            if check != "response_url" and result.is_html and handle not in title and mentions < 3:
                return Verdict("unknown", "low", "no handle in title or page body")

            visible = _visible(low).count(handle) if result.is_html else mentions
            if visible >= 2:
                confidence = _bump(confidence)
            elif mentions == 0 and check == "status_code":
                confidence = "low"
            evidence += f", {mentions} mention(s)"

    return Verdict(state, confidence, evidence)


# ─── concurrency ───────────────────────────────────────────


class Throttle:
    """A global cap plus a per-host cap.

    50 requests spread over 50 hosts is polite. 50 requests at one host is a
    self-inflicted rate limit, and every one of those sites will answer 429
    and be reported as "unknown" — which looks like missing coverage.
    """

    __slots__ = ("_global", "_per_host", "_hosts")

    def __init__(self, concurrency: int, per_host: int) -> None:
        self._global = asyncio.Semaphore(max(1, concurrency))
        self._per_host = max(1, per_host)
        self._hosts: dict[str, asyncio.Semaphore] = {}

    @asynccontextmanager
    async def slot(self, url: str) -> AsyncIterator[None]:
        host = (urlparse(url).hostname or "").lower()
        async with self._global:
            semaphore = self._hosts.get(host)
            if semaphore is None:
                semaphore = self._hosts[host] = asyncio.Semaphore(self._per_host)
            async with semaphore:
                yield

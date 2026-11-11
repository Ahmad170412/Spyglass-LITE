"""Ground truth for the username benchmark.

Every oracle here is a first-party API that answers one question: does this
handle have an account on this service? They are deliberately *not* scraped
profile pages, because a profile page's absence is exactly what the tools
disagree about. Where a service offers no such endpoint it is not in the list
— an oracle that guesses is worse than no oracle at all.

``None`` means "could not tell" (timeout, 403, rate limit). Those cells are
excluded from scoring rather than counted as absent, because a benchmark that
punishes a tool for the benchmark's own rate limit is measuring nothing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

UA = "spyglass-lite-bench/0.1 (+https://github.com/Ahmad170412/Spyglass-OSINT)"

Check = Callable[[httpx.AsyncClient, str], Awaitable[bool | None]]


@dataclass(frozen=True)
class Oracle:
    domain: str
    name: str
    profile: str
    check: Check
    note: str = ""


async def _get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response | None:
    for attempt in range(2):
        try:
            return await client.get(url, **kwargs)
        except httpx.HTTPError:
            if attempt:
                return None
            await asyncio.sleep(1.0)
    return None


def _status(
    url: str,
    *,
    present: tuple[int, ...] = (200,),
    absent: tuple[int, ...] = (404, 410),
):
    async def check(client: httpx.AsyncClient, handle: str) -> bool | None:
        response = await _get(client, url.format(handle=handle))
        if response is None:
            return None
        if response.status_code in present:
            return True
        if response.status_code in absent:
            return False
        return None

    return check


async def _json_list_non_empty(client: httpx.AsyncClient, handle: str) -> bool | None:
    response = await _get(client, f"https://gitlab.com/api/v4/users?username={handle}")
    if response is None or response.status_code != 200:
        return None
    try:
        return len(response.json()) > 0
    except ValueError:
        return None


async def _npm_maintainer(client: httpx.AsyncClient, handle: str) -> bool | None:
    """Exact maintainer match; npm's search is fuzzy and will match typos."""
    response = await _get(
        client,
        f"https://registry.npmjs.org/-/v1/search?text=maintainer:{handle}&size=20",
    )
    if response is None or response.status_code != 200:
        return None
    try:
        objects = response.json().get("objects", ())
    except ValueError:
        return None
    wanted = handle.lower()
    return any(
        maintainer.get("username", "").lower() == wanted
        for package in objects
        for maintainer in package.get("package", {}).get("maintainers", ())
    )


async def _hackernews(client: httpx.AsyncClient, handle: str) -> bool | None:
    response = await _get(client, f"https://hacker-news.firebaseio.com/v0/user/{handle}.json")
    if response is None or response.status_code != 200:
        return None
    try:
        return response.json() is not None
    except ValueError:
        return None


async def _keybase(client: httpx.AsyncClient, handle: str) -> bool | None:
    response = await _get(
        client,
        f"https://keybase.io/_/api/1.0/user/lookup.json?username={handle}&fields=basics",
    )
    if response is None or response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    code = payload.get("status", {}).get("code")
    if code == 0:
        return bool(payload.get("them"))
    if code == 205:
        return False
    return None


async def _wikipedia(client: httpx.AsyncClient, handle: str) -> bool | None:
    response = await _get(
        client,
        "https://en.wikipedia.org/w/api.php",
        params={
            "action": "query",
            "titles": f"User:{handle}",
            "format": "json",
            "formatversion": "2",
        },
    )
    if response is None or response.status_code != 200:
        return None
    try:
        pages = response.json()["query"]["pages"]
    except (ValueError, KeyError):
        return None
    if not pages:
        return None
    return not bool(pages[0].get("missing"))


async def _mastodon(client: httpx.AsyncClient, handle: str) -> bool | None:
    response = await _get(client, f"https://mastodon.social/api/v1/accounts/lookup?acct={handle}")
    if response is None:
        return None
    if response.status_code == 200:
        return True
    if response.status_code == 404:
        return False
    return None


async def _bitbucket(client: httpx.AsyncClient, handle: str) -> bool | None:
    """The user API 404s even for accounts that own a workspace.

    ``https://bitbucket.org/<name>/`` redirects a real workspace to
    ``.../workspace/repositories/`` and leaves an unknown name on a per-name
    404, which makes the page status the honest signal.
    """
    response = await _get(client, f"https://bitbucket.org/{handle}/")
    if response is None:
        return None
    if response.status_code == 200:
        return True
    if response.status_code in {404, 410}:
        return False
    return None


ORACLES: tuple[Oracle, ...] = (
    Oracle(
        "github.com",
        "GitHub",
        "https://github.com/{handle}",
        _status("https://api.github.com/users/{handle}"),
        "REST user endpoint",
    ),
    Oracle(
        "gitlab.com",
        "GitLab",
        "https://gitlab.com/{handle}",
        _json_list_non_empty,
        "users?username=",
    ),
    Oracle(
        "bitbucket.org",
        "Bitbucket",
        "https://bitbucket.org/{handle}/",
        _bitbucket,
        "workspace page status",
    ),
    Oracle(
        "codeberg.org",
        "Codeberg",
        "https://codeberg.org/{handle}",
        _status("https://codeberg.org/api/v1/users/{handle}"),
        "Gitea API",
    ),
    Oracle(
        "gitee.com",
        "Gitee",
        "https://gitee.com/{handle}",
        _status("https://gitee.com/api/v5/users/{handle}"),
        "Gitee API",
    ),
    Oracle(
        "huggingface.co",
        "Hugging Face",
        "https://huggingface.co/{handle}",
        _status("https://huggingface.co/api/users/{handle}/overview"),
        "user overview API",
    ),
    Oracle(
        "hub.docker.com",
        "Docker Hub",
        "https://hub.docker.com/u/{handle}",
        _status("https://hub.docker.com/v2/users/{handle}/"),
        "v2 users API",
    ),
    Oracle(
        "npmjs.com",
        "npm",
        "https://www.npmjs.com/~{handle}",
        _npm_maintainer,
        "registry search, exact maintainer",
    ),
    Oracle(
        "dev.to",
        "DEV Community",
        "https://dev.to/{handle}",
        _status("https://dev.to/api/users/by_username?url={handle}"),
        "users API",
    ),
    Oracle(
        "keybase.io",
        "Keybase",
        "https://keybase.io/{handle}",
        _keybase,
        "lookup API status code",
    ),
    Oracle(
        "mastodon.social",
        "Mastodon",
        "https://mastodon.social/@{handle}",
        _mastodon,
        "accounts/lookup",
    ),
    Oracle(
        "news.ycombinator.com",
        "Hacker News",
        "https://news.ycombinator.com/user?id={handle}",
        _hackernews,
        "Firebase user node",
    ),
    Oracle(
        "chess.com",
        "Chess.com",
        "https://www.chess.com/member/{handle}",
        _status("https://api.chess.com/pub/player/{handle}"),
        "pub player API",
    ),
    Oracle(
        "lichess.org",
        "Lichess",
        "https://lichess.org/@/{handle}",
        _status("https://lichess.org/api/user/{handle}"),
        "user API",
    ),
    Oracle(
        "en.wikipedia.org",
        "Wikipedia",
        "https://en.wikipedia.org/wiki/User:{handle}",
        _wikipedia,
        "user page existence",
    ),
    Oracle(
        "sr.ht",
        "sourcehut",
        "https://sr.ht/~{handle}",
        _status("https://sr.ht/~{handle}/"),
        "profile page status",
    ),
    Oracle(
        "itch.io",
        "itch.io",
        "https://{handle}.itch.io/",
        _status("https://{handle}.itch.io/"),
        "creator subdomain",
    ),
    Oracle(
        "last.fm",
        "Last.fm",
        "https://www.last.fm/user/{handle}",
        _status("https://www.last.fm/user/{handle}"),
        "profile page status",
    ),
)

BY_DOMAIN = {oracle.domain: oracle for oracle in ORACLES}


async def matrix(handles: list[str]) -> dict[str, dict[str, bool | None]]:
    """``{handle: {domain: True/False/None}}`` for every oracle."""
    results: dict[str, dict[str, bool | None]] = {}
    async with httpx.AsyncClient(
        headers={"user-agent": UA},
        timeout=20.0,
        follow_redirects=True,
    ) as client:
        for handle in handles:
            row: dict[str, bool | None] = {}
            for oracle in ORACLES:
                try:
                    row[oracle.domain] = await asyncio.wait_for(
                        oracle.check(client, handle), timeout=30
                    )
                except (TimeoutError, httpx.HTTPError):
                    row[oracle.domain] = None
            results[handle] = row
            print(
                f"  oracle {handle:18} "
                + " ".join(
                    f"{d.split('.')[0]}={'?' if v is None else 'Y' if v else '-'}"
                    for d, v in row.items()
                )
            )
    return results

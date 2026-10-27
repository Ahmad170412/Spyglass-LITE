"""Shared fixtures for the offline suite."""

from __future__ import annotations

from typing import Any

import pytest

from spyglass_lite._http import Fetch


def make_site(**overrides: Any) -> dict[str, Any]:
    site: dict[str, Any] = {
        "name": "Test",
        "domain": "test.example",
        "url": "https://test.example/{username}",
        "probe": None,
        "method": "GET",
        "payload": None,
        "headers": {},
        "check": "status_code",
        "present": [],
        "absent": [],
        "absent_url": None,
        "regex": None,
        "ignore403": False,
        "errors": {},
        "protected": [],
        "tags": [],
        "sample": None,
        "source": ["test"],
    }
    site.update(overrides)
    return site


def make_fetch(
    *,
    status: int = 200,
    body: str = "",
    url: str = "https://test.example/torvalds",
    requested_url: str | None = None,
    content_type: str = "text/html; charset=utf-8",
    error: str = "",
    headers: dict[str, str] | None = None,
) -> Fetch:
    all_headers = {"content-type": content_type} if content_type else {}
    all_headers.update(headers or {})
    return Fetch(
        status=status,
        url=url,
        requested_url=requested_url or url,
        text=body,
        headers=all_headers,
        error=error,
    )


def html_page(title: str, mentions: str = "", filler: int = 3000) -> str:
    return (
        "<!DOCTYPE html><html><head><title>"
        + title
        + "</title></head><body><p>"
        + mentions
        + "</p>"
        + ("<div>content</div>" * (filler // 16))
        + "</body></html>"
    )


@pytest.fixture(autouse=True)
def reset_control_cache():
    """The catch-all control cache is process-wide; tests must not share it."""
    import importlib

    module = importlib.import_module("spyglass_lite.username")
    module._controls.clear()
    yield
    module._controls.clear()


@pytest.fixture
def patch_sites(monkeypatch):
    """Replace the bundled site list with a caller-supplied one."""

    def apply(sites: list[dict[str, Any]]) -> None:
        monkeypatch.setattr("spyglass_lite._registry.select", lambda **_kwargs: list(sites))

    return apply

"""Phone module and client plumbing."""

from __future__ import annotations

import asyncio
import sys

import pytest

import spyglass_lite as sg
from spyglass_lite import InvalidTarget, MissingDependency, Spyglass
from spyglass_lite.client import _run_sync
from spyglass_lite.config import Config


def test_valid_international_number():
    result = Spyglass().phone("+442071838750")

    assert result.valid is True
    assert result.e164 == "+442071838750"
    assert result.country_code == 44
    assert result.region == "GB"
    assert result.line_type in {"fixed-line", "fixed-line-or-mobile"}
    assert result.international.startswith("+44")


def test_number_without_country_code_is_rejected():
    with pytest.raises(InvalidTarget, match="country code"):
        Spyglass().phone("2071838750")


@pytest.mark.parametrize("target", ["", "not a number", "++123"])
def test_invalid_numbers_raise(target):
    with pytest.raises(InvalidTarget):
        Spyglass().phone(target)


def test_missing_phonenumbers_raises_actionable_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "phonenumbers", None)
    with pytest.raises(MissingDependency, match=r"spyglass-lite\[phone\]"):
        Spyglass().phone("+442071838750")


def test_result_to_dict_round_trips():
    data = Spyglass().phone("+442071838750").to_dict()
    assert data["e164"] == "+442071838750"
    assert data["country_code"] == 44


# ─── client ───────────────────────────────────────────────


def test_config_rejects_unknown_options():
    with pytest.raises(TypeError, match="unknown option"):
        Config.build(nope=1)


@pytest.mark.parametrize(
    "options",
    [{"timeout": 0}, {"concurrency": 0}, {"per_host": 0}, {"retries": -1}],
)
def test_config_rejects_nonsense_values(options):
    with pytest.raises(ValueError):
        Config.build(**options)


def test_repr_is_useful():
    assert "Spyglass(" in repr(sg.lite(timeout=7, concurrency=11))


def test_run_sync_outside_a_loop():
    async def work():
        return 41 + 1

    assert _run_sync(work) == 42


def test_run_sync_inside_a_running_loop():
    async def inner():
        return 42

    async def outer():
        return _run_sync(inner)

    assert asyncio.run(outer()) == 42


def test_async_context_manager():
    async def main():
        async with Spyglass() as client:
            assert isinstance(client, Spyglass)

    asyncio.run(main())


def test_configure_replaces_the_default_client():
    original = sg._default
    try:
        client = sg.configure(timeout=3)
        assert sg.default() is client
        assert client.config.timeout == 3
    finally:
        sg._default = original


async def test_username_many(patch_sites, respx_mock):
    import httpx

    from conftest import html_page, make_site

    patch_sites([make_site()])
    for handle in ("alice", "bob"):
        respx_mock.get(f"https://test.example/{handle}").mock(
            return_value=httpx.Response(200, text=html_page(handle, f"{handle} {handle}"))
        )

    results = await Spyglass().ausername_many(["alice", "bob"], workers=2, verify_catchall=False)

    assert [r.target for r in results] == ["alice", "bob"]
    assert all(r.found for r in results)

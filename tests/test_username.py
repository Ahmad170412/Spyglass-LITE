"""Username engine, exercised against mocked HTTP."""

from __future__ import annotations

import asyncio
import importlib

import httpx
import pytest

from conftest import html_page, make_fetch, make_site
from spyglass_lite import InvalidTarget, Spyglass

# ``spyglass_lite.username`` the function shadows the module of the same
# name, so attribute-style imports would bind the wrong object.
username_module = importlib.import_module("spyglass_lite.username")


async def test_finds_status_code_site(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("torvalds", "torvalds torvalds"))
    )

    result = await Spyglass().ausername("torvalds", verify_catchall=False)

    assert result.checked == 1
    assert len(result.found) == 1
    assert result.found[0].domain == "test.example"
    assert result.found[0].url == "https://test.example/torvalds"
    assert result.found[0].confidence == "high"


async def test_absent_site_is_not_reported(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(return_value=httpx.Response(404))

    result = await Spyglass().ausername("torvalds", verify_catchall=False)

    assert result.found == []
    assert result.unknown == []
    assert result.checked == 1


async def test_blocked_site_lands_in_unknown(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(return_value=httpx.Response(403))

    result = await Spyglass().ausername("torvalds", verify_catchall=False)

    assert result.found == []
    assert len(result.unknown) == 1
    assert "blocked" in result.unknown[0].reason


async def test_include_unknown_false_drops_them(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(return_value=httpx.Response(403))

    result = await Spyglass().ausername("torvalds", verify_catchall=False, include_unknown=False)

    assert result.unknown == []


async def test_catch_all_route_is_demoted(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("torvalds", "torvalds"))
    )
    respx_mock.get("https://test.example/zq9x7v3k2m1p").mock(
        return_value=httpx.Response(200, text=html_page("zq9x7v3k2m1p", "x"))
    )

    result = await Spyglass().ausername("torvalds")

    assert result.found == []
    assert len(result.unknown) == 1
    assert "catch-all" in result.unknown[0].reason


async def test_catch_all_can_be_disabled(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("torvalds", "torvalds"))
    )

    result = await Spyglass().ausername("torvalds", verify_catchall=False)

    assert len(result.found) == 1


async def test_unusable_control_probe_demotes_the_hit(patch_sites, respx_mock):
    """A blocked control cannot prove the rule distinguishes accounts."""
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("torvalds", "torvalds torvalds"))
    )
    respx_mock.get("https://test.example/zq9x7v3k2m1p").mock(return_value=httpx.Response(403))

    result = await Spyglass().ausername("torvalds")

    assert result.found == []
    assert len(result.unknown) == 1
    assert "control probe unavailable" in result.unknown[0].reason


async def test_transient_failure_is_retried(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        side_effect=[
            httpx.Response(429),
            httpx.Response(200, text=html_page("torvalds", "torvalds torvalds")),
        ]
    )

    result = await Spyglass(retries=1, backoff=0.01).ausername("torvalds", verify_catchall=False)

    assert len(result.found) == 1


async def test_regex_rejects_handle_without_a_request(patch_sites, respx_mock):
    patch_sites([make_site(regex=r"^[a-z]+$")])

    result = await Spyglass().ausername("Torvalds99", verify_catchall=False)

    assert result.checked == 0
    assert result.skipped == 1
    assert not respx_mock.calls


async def test_on_result_callback(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("torvalds", "torvalds torvalds"))
    )
    seen = []

    await Spyglass().ausername("torvalds", verify_catchall=False, on_result=seen.append)

    assert [p.domain for p in seen] == ["test.example"]


async def test_probe_url_is_requested_but_profile_url_reported(patch_sites, respx_mock):
    patch_sites([make_site(probe="https://api.test.example/users/{username}")])
    respx_mock.get("https://api.test.example/users/torvalds").mock(
        return_value=httpx.Response(
            200,
            text='{"login":"torvalds","torvalds":true}',
            headers={"content-type": "application/json"},
        )
    )

    result = await Spyglass().ausername("torvalds", verify_catchall=False)

    assert result.found[0].url == "https://test.example/torvalds"


async def test_profile_field_overrides_reported_url(patch_sites, respx_mock):
    patch_sites(
        [
            make_site(
                probe="https://api.test.example/users/{username}",
                profile_field="url",
                check="status_code",
            )
        ]
    )
    respx_mock.get("https://api.test.example/users/torvalds").mock(
        return_value=httpx.Response(
            200,
            json={"username": "Torvalds", "url": "https://test.example/@Torvalds"},
        )
    )

    result = await Spyglass().ausername("torvalds", verify_catchall=False)

    assert result.found[0].url == "https://test.example/@Torvalds"


async def test_profile_field_ignores_non_url_values(patch_sites, respx_mock):
    patch_sites(
        [
            make_site(
                probe="https://api.test.example/users/{username}",
                profile_field="url",
                check="status_code",
            )
        ]
    )
    respx_mock.get("https://api.test.example/users/torvalds").mock(
        return_value=httpx.Response(200, json={"url": "/relative", "username": "torvalds"})
    )

    result = await Spyglass().ausername("torvalds", verify_catchall=False)

    assert result.found[0].url == "https://test.example/torvalds"


async def test_no_matching_sites_raises(patch_sites):
    patch_sites([])
    with pytest.raises(InvalidTarget, match="no sites"):
        await Spyglass().ausername("torvalds")


@pytest.mark.parametrize("handle", ["", "   ", "has space", "a/b", "x" * 65, "@"])
async def test_invalid_handles_raise(handle):
    with pytest.raises(InvalidTarget):
        await Spyglass().ausername(handle)


async def test_leading_at_is_stripped(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(return_value=httpx.Response(404))

    result = await Spyglass().ausername("@torvalds", verify_catchall=False)

    assert result.target == "torvalds"


async def test_result_is_iterable_and_json_safe(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("torvalds", "torvalds torvalds"))
    )

    result = await Spyglass().ausername("torvalds", verify_catchall=False)
    data = result.to_dict()

    assert len(result) == 1
    assert [p.domain for p in result] == ["test.example"]
    assert data["found"][0]["domain"] == "test.example"
    assert isinstance(data["duration_ms"], int)


async def test_one_broken_site_does_not_kill_the_scan(patch_sites, respx_mock):
    patch_sites(
        [
            make_site(name="Broken", domain="broken.example", url="not-a-url/{username}"),
            make_site(name="Good", domain="good.example", url="https://good.example/{username}"),
        ]
    )
    respx_mock.get("https://good.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("torvalds", "torvalds torvalds"))
    )

    result = await Spyglass().ausername("torvalds", verify_catchall=False)

    assert result.found[0].domain == "good.example"
    assert result.errors


def test_strict_defaults_to_true_in_the_result(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("torvalds", "torvalds torvalds"))
    )

    result = Spyglass().username("torvalds", verify_catchall=False)

    assert result.strict is True
    assert result.duration_ms >= 0


# ─── judge / sites / deadline knobs ─────────────────────


async def test_judge_false_runs_raw_rules_without_a_control_probe(patch_sites, respx_mock):
    """judge=False means the dataset rule and nothing else."""
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("Just a moment...", "torvalds"))
    )

    result = await Spyglass().ausername("torvalds", judge=False)

    assert len(result.found) == 1
    assert result.strict is False
    assert len(respx_mock.calls) == 1  # no catch-all probe was made


async def test_judge_false_still_verifies_when_asked_explicitly(patch_sites, respx_mock):
    patch_sites([make_site()])
    respx_mock.get("https://test.example/torvalds").mock(
        return_value=httpx.Response(200, text=html_page("Just a moment...", "x"))
    )
    respx_mock.get("https://test.example/zq9x7v3k2m1p").mock(
        return_value=httpx.Response(200, text=html_page("Just a moment...", "x"))
    )

    result = await Spyglass().ausername("torvalds", judge=False, verify_catchall=True)

    assert result.found == []
    assert "catch-all" in result.unknown[0].reason


async def test_judge_and_strict_must_agree(patch_sites):
    patch_sites([make_site()])
    with pytest.raises(InvalidTarget, match="disagree"):
        await Spyglass().ausername("torvalds", judge=True, strict=False)


async def test_sites_are_merged_into_only(monkeypatch, respx_mock):
    seen: dict = {}

    def fake_select(**kwargs):
        seen.update(kwargs)
        return [make_site()]

    monkeypatch.setattr("spyglass_lite._registry.select", fake_select)
    respx_mock.get("https://test.example/torvalds").mock(return_value=httpx.Response(404))

    await Spyglass().ausername(
        "torvalds", sites=["github.com", "https://x.com/someone"], verify_catchall=False
    )

    assert seen["only"] == ["github.com", "https://x.com/someone"]


async def test_empty_sites_list_raises():
    with pytest.raises(InvalidTarget, match="empty"):
        await Spyglass().ausername("torvalds", sites=[])


async def test_deadline_returns_partial_results(patch_sites, monkeypatch):
    patch_sites(
        [
            make_site(name="Fast", domain="fast.example", url="https://fast.example/{username}"),
            make_site(name="Slow", domain="slow.example", url="https://slow.example/{username}"),
        ]
    )

    async def fake_request(http, site, username, *, timeout, retries, backoff, follow_redirects):
        if site["domain"] == "slow.example":
            await asyncio.sleep(30)
        return make_fetch(status=404), site["url"].replace("{username}", username)

    monkeypatch.setattr(username_module, "request_with_retries", fake_request)

    result = await Spyglass().ausername("torvalds", deadline=0.3, verify_catchall=False)

    assert result.partial is True
    assert result.checked == 2  # both started; one was cut off mid-flight
    assert result.duration_ms < 10_000
    assert result.to_dict()["partial"] is True


async def test_bad_deadline_raises():
    with pytest.raises(InvalidTarget, match="deadline"):
        await Spyglass().ausername("torvalds", deadline=0)


async def test_control_probe_keeps_a_longer_timeout_than_the_scan(patch_sites, monkeypatch):
    """A 6s scan must not fail-closed on a slow catch-all control."""
    patch_sites([make_site()])
    seen: list[float] = []

    async def fake_request(http, site, username, *, timeout, retries, backoff, follow_redirects):
        seen.append(timeout)
        url = site["url"].replace("{username}", username)
        if username == username_module._CATCHALL_HANDLE:
            return make_fetch(status=404, url=url), url
        return make_fetch(body=html_page("torvalds", "torvalds torvalds"), url=url), url

    monkeypatch.setattr(username_module, "request_with_retries", fake_request)

    result = await Spyglass(timeout=6).ausername("torvalds")

    assert result.found
    assert 6.0 in seen  # the profile request uses the configured timeout
    assert 10.0 in seen  # the control probe keeps its floor

"""Email module: parsing, DNS-derived facts, Gravatar, breaches, recipes."""

from __future__ import annotations

import json

import httpx
import pytest

from spyglass_lite import InvalidTarget, MissingDependency, Spyglass
from spyglass_lite.email import (
    _gravatar_hash,
    _provider,
    _run_recipe,
    load_recipes,
    parse,
    resolve_sites,
)


@pytest.fixture
def fake_dns(monkeypatch):
    """Deterministic MX/SPF/DMARC without touching DNS."""

    async def mx(domain, *, timeout=4.0, cache=None):
        if domain == "nomx.example":
            return []
        return [(10, "aspmx.l.google.com"), (20, "alt1.aspmx.l.google.com")]

    async def txt(name, *, timeout=4.0, cache=None):
        if name.startswith("_dmarc."):
            return ["v=DMARC1; p=quarantine"]
        return ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"]

    monkeypatch.setattr("spyglass_lite._dns.mx", mx)
    monkeypatch.setattr("spyglass_lite._dns.txt", txt)
    return None


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("  Me@Example.COM ", ("Me", "example.com", "Me@example.com")),
        ("mailto:me@example.com", ("me", "example.com", "me@example.com")),
        (
            "first.last+tag@sub.example.co.uk",
            ("first.last+tag", "sub.example.co.uk", "first.last+tag@sub.example.co.uk"),
        ),
    ],
)
def test_parse_accepts_valid_addresses(raw, expected):
    assert parse(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "no-at-sign",
        "a@b",
        "a@@b.com",
        ".a@b.com",
        "a.@b.com",
        "a..b@c.com",
        "a@-b.com",
        "a@b..com",
    ],
)
def test_parse_rejects_invalid_addresses(raw):
    with pytest.raises(InvalidTarget):
        parse(raw)


def test_parse_normalises_idn():
    local, domain, normalized = parse("me@münchen.de")
    assert normalized == "me@münchen.de"
    assert domain == "münchen.de"


def test_provider_mapping():
    assert _provider(["aspmx.l.google.com"]) == "Google Workspace"
    assert _provider(["mx1.protection.outlook.com"]) == "Microsoft 365"
    assert _provider(["mail.unknown-host.test"]) == ""


def test_gravatar_hash_is_lowercased_md5():
    import hashlib

    assert _gravatar_hash("Me@Example.com") == hashlib.md5(b"me@example.com").hexdigest()


async def test_passive_scan(fake_dns):
    result = await Spyglass().aemail("admin@example.com", gravatar=False, breaches=False)

    assert result.valid is True
    assert result.normalized == "admin@example.com"
    assert result.provider == "Google Workspace"
    assert [m.host for m in result.mx] == [
        "aspmx.l.google.com",
        "alt1.aspmx.l.google.com",
    ]
    assert result.spf is True
    assert result.dmarc is True
    assert result.role is True
    assert result.disposable is False


async def test_no_mx_records(fake_dns):
    monkeypatch_result = await Spyglass().aemail("me@nomx.example", gravatar=False, breaches=False)
    assert monkeypatch_result.mx == []
    assert monkeypatch_result.provider == ""


async def test_disposable_domain(fake_dns):
    result = await Spyglass().aemail("me@mailinator.com", gravatar=False, breaches=False)
    assert result.disposable is True


async def test_missing_spf_and_dmarc(fake_dns, monkeypatch):
    async def empty_txt(name, *, timeout=4.0, cache=None):
        return []

    monkeypatch.setattr("spyglass_lite._dns.txt", empty_txt)

    result = await Spyglass().aemail("admin@example.com", gravatar=False, breaches=False)

    assert result.spf is False
    assert result.dmarc is False


def test_role_detection(fake_dns):
    assert Spyglass().email("admin@example.com", gravatar=False, breaches=False).role is True
    assert Spyglass().email("linus@example.com", gravatar=False, breaches=False).role is False


async def test_invalid_email_raises(fake_dns):
    with pytest.raises(InvalidTarget):
        await Spyglass().aemail("definitely-not-an-address", gravatar=False)


async def test_gravatar_absent(fake_dns, respx_mock):
    respx_mock.get(url__regex=r"https://gravatar\.com/avatar/.*").mock(
        return_value=httpx.Response(404)
    )

    result = await Spyglass().aemail("me@example.com", gravatar=True, breaches=False)

    assert result.gravatar is not None
    assert result.gravatar.exists is False
    assert result.gravatar.hash == _gravatar_hash("me@example.com")


async def test_gravatar_profile_is_parsed(fake_dns, respx_mock):
    respx_mock.get(url__regex=r"https://gravatar\.com/avatar/.*").mock(
        return_value=httpx.Response(200, content=b"PNG")
    )
    respx_mock.get(url__regex=r"https://en\.gravatar\.com/.*\.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "entry": [
                    {
                        "profileUrl": "https://gravatar.com/me",
                        "displayName": "Me",
                        "preferredUsername": "me",
                        "currentLocation": "Brisbane",
                        "aboutMe": "hello",
                        "accounts": [
                            {
                                "domain": "github.com",
                                "username": "me",
                                "url": "https://github.com/me",
                            }
                        ],
                    }
                ]
            },
        )
    )

    result = await Spyglass().aemail("me@example.com", gravatar=True, breaches=False)

    gravatar = result.gravatar
    assert gravatar is not None and gravatar.exists is True
    assert gravatar.display_name == "Me"
    assert gravatar.location == "Brisbane"
    assert gravatar.accounts[0].service == "github"
    assert gravatar.accounts[0].url == "https://github.com/me"


async def test_breach_sources_are_merged(fake_dns, respx_mock):
    respx_mock.get(url__regex=r"https://leakcheck\.io/.*").mock(
        return_value=httpx.Response(
            200, json={"success": True, "found": 2, "sources": ["LinkedIn"], "fields": ["email"]}
        )
    )
    respx_mock.get(url__regex=r"https://scylla\.so/.*").mock(
        return_value=httpx.Response(
            200, json=[{"database": "Collection1", "email": "me@example.com"}]
        )
    )

    result = await Spyglass().aemail("me@example.com", gravatar=False, breaches=True)

    assert result.breach is not None
    assert result.breach.found == 3
    assert "LinkedIn" in result.breach.sources
    assert "Collection1" in result.breach.sources


async def test_breach_api_failure_is_not_fatal(fake_dns, respx_mock):
    respx_mock.get(url__regex=r"https://leakcheck\.io/.*").mock(return_value=httpx.Response(503))
    respx_mock.get(url__regex=r"https://scylla\.so/.*").mock(return_value=httpx.Response(500))

    result = await Spyglass().aemail("me@example.com", gravatar=False, breaches=True)

    assert result.breach is not None
    assert result.breach.found == 0


async def test_recipe_exists(respx_mock):
    recipe = {
        "id": "firefox",
        "name": "Firefox Accounts",
        "url": "https://api.accounts.firefox.com/v1/account/status",
        "method": "POST",
        "headers": {"content-type": "application/json"},
        "payload": {"email": "{email}"},
        "exists_when": {"json_path": "exists", "equals": True},
        "absent_when": {"json_path": "exists", "equals": False},
    }
    route = respx_mock.post("https://api.accounts.firefox.com/v1/account/status").mock(
        return_value=httpx.Response(200, json={"exists": True})
    )

    registration = await _run_recipe(
        httpx.AsyncClient(), recipe, "me@example.com", Spyglass().config
    )

    assert registration.exists is True
    assert registration.site == "Firefox Accounts"
    assert json.loads(route.calls[0].request.content) == {"email": "me@example.com"}


async def test_recipe_absent(respx_mock):
    recipe = {
        "name": "Example",
        "url": "https://example.test/check?email={email}",
        "method": "GET",
        "exists_when": {"body_contains": "taken"},
        "absent_when": {"body_contains": "available"},
    }
    respx_mock.get(url__startswith="https://example.test/check").mock(
        return_value=httpx.Response(200, text="available")
    )

    registration = await _run_recipe(
        httpx.AsyncClient(), recipe, "me@example.com", Spyglass().config
    )

    assert registration.exists is False


async def test_recipe_inconclusive_on_error(respx_mock):
    recipe = {
        "name": "Example",
        "url": "https://example.test/check/{email}",
        "method": "GET",
        "exists_when": {"status": 200},
    }
    respx_mock.get(url__startswith="https://example.test/check").mock(
        return_value=httpx.Response(500)
    )

    registration = await _run_recipe(
        httpx.AsyncClient(), recipe, "me@example.com", Spyglass().config
    )

    assert registration.exists is None
    assert "inconclusive" in registration.evidence


def test_bundled_recipes_load():
    recipes = load_recipes()
    assert len(recipes) >= 2
    ids = {recipe["id"] for recipe in recipes}
    assert {"firefox", "duolingo"} <= ids


def test_custom_recipe_file(tmp_path):
    path = tmp_path / "recipes.json"
    path.write_text(json.dumps({"recipes": [{"id": "x", "url": "https://x.test/{email}"}]}))
    assert load_recipes(str(path))[0]["id"] == "x"


async def test_registrations_are_off_by_default(fake_dns):
    result = await Spyglass().aemail("me@example.com", gravatar=False, breaches=False)
    assert result.registrations == []


async def test_registrations_run_when_requested(fake_dns, respx_mock):
    respx_mock.post("https://api.accounts.firefox.com/v1/account/status").mock(
        return_value=httpx.Response(200, json={"exists": True})
    )
    respx_mock.get(url__startswith="https://www.duolingo.com/2017-06-30/users").mock(
        return_value=httpx.Response(200, json={"users": []})
    )

    result = await Spyglass().aemail(
        "me@example.com", gravatar=False, breaches=False, registrations=True
    )

    by_site = {registration.site: registration for registration in result.registrations}
    assert by_site["Firefox Accounts"].exists is True
    assert by_site["Duolingo"].exists is False


def test_missing_dependency_message_is_actionable():
    error = MissingDependency("phonenumbers", "phone", "phone")
    assert "python -m pip install spyglass-lite[phone]" in str(error)


# ─── sites= : inline recipes and bare domains ────────────


def test_resolve_sites_matches_bundled_domains():
    recipes, unmatched = resolve_sites(["duolingo.com", "https://no-recipe.example/"])

    assert [recipe["id"] for recipe in recipes] == ["duolingo"]
    assert unmatched == ["no-recipe.example"]


def test_resolve_sites_accepts_inline_recipe_dicts():
    recipes, unmatched = resolve_sites([{"name": "X", "url": "https://x.test/{email}"}])

    assert recipes[0]["name"] == "X"
    assert unmatched == []


def test_resolve_sites_rejects_recipe_without_url():
    with pytest.raises(InvalidTarget, match="missing 'url'"):
        resolve_sites([{"name": "X"}])


async def test_sites_runs_inline_recipes_and_reports_unmatched(fake_dns, respx_mock):
    respx_mock.get("https://example.test/check").mock(
        return_value=httpx.Response(200, text="taken")
    )

    result = await Spyglass().aemail(
        "me@example.com",
        gravatar=False,
        breaches=False,
        sites=[
            {
                "name": "Example",
                "url": "https://example.test/check?email={email}",
                "exists_when": {"body_contains": "taken"},
                "absent_when": {"body_contains": "free"},
            },
            "no-recipe.example",
        ],
    )

    by_site = {registration.site: registration for registration in result.registrations}
    assert by_site["Example"].exists is True
    assert by_site["no-recipe.example"].exists is None
    assert "no recipe" in by_site["no-recipe.example"].evidence

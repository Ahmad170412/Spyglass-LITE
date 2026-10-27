"""The verdict ladder, tested without a network."""

from __future__ import annotations

from conftest import html_page, make_fetch, make_site
from spyglass_lite._http import judge


def test_status_code_found_upgrades_on_handle_echo():
    verdict = judge(
        make_site(),
        make_fetch(body=html_page("torvalds · GitHub", "torvalds torvalds")),
        "torvalds",
    )
    assert verdict.state == "found"
    assert verdict.confidence == "high"
    assert "mention" in verdict.evidence


def test_status_code_404_is_absent():
    verdict = judge(make_site(), make_fetch(status=404), "torvalds")
    assert verdict.state == "absent"


def test_403_is_unknown_not_absent():
    verdict = judge(make_site(), make_fetch(status=403), "torvalds")
    assert verdict.state == "unknown"
    assert "blocked" in verdict.evidence


def test_429_is_unknown():
    verdict = judge(make_site(), make_fetch(status=429), "torvalds")
    assert verdict.state == "unknown"
    assert "transient" in verdict.evidence


def test_transport_error_is_unknown():
    verdict = judge(make_site(), make_fetch(error="ConnectError: refused"), "torvalds")
    assert verdict.state == "unknown"
    assert "request failed" in verdict.evidence


def test_message_absence_marker():
    site = make_site(check="message", absent=["nobody goes by that name"])
    verdict = judge(site, make_fetch(body="<html>nobody goes by that name</html>"), "torvalds")
    assert verdict.state == "absent"
    assert "absence marker" in verdict.evidence


def test_message_presence_missing():
    site = make_site(check="message", present=['"name":'])
    verdict = judge(site, make_fetch(body=html_page("x", "nothing here")), "torvalds")
    assert verdict.state == "absent"
    assert verdict.evidence == "presence marker missing"


def test_message_rule_with_404_is_absent():
    """A bespoke 404 page whose copy does not match the marker is still a 404."""
    site = make_site(check="message", absent=["Whoops, that page is gone."])
    verdict = judge(site, make_fetch(status=404, body="<html>custom not here</html>"), "torvalds")
    assert verdict.state == "absent"
    assert "http 404" in verdict.evidence


def test_challenge_title_is_unknown():
    site = make_site()
    body = html_page("Just a moment...", "torvalds torvalds")
    verdict = judge(site, make_fetch(body=body), "torvalds")
    assert verdict.state == "unknown"
    assert "challenge page" in verdict.evidence


def test_challenge_body_marker_is_unknown():
    body = html_page("torvalds", "torvalds torvalds") + "cf_chl_opt"
    verdict = judge(make_site(), make_fetch(body=body), "torvalds")
    assert verdict.state == "unknown"
    assert "bot challenge" in verdict.evidence


def test_registration_interstitial_is_unknown():
    body = html_page("Sign up for free to see more", "torvalds torvalds")
    verdict = judge(make_site(), make_fetch(body=body), "torvalds")
    assert verdict.state == "unknown"
    assert "registration prompt" in verdict.evidence


def test_not_found_title_is_absent():
    body = html_page("Page not found", "torvalds torvalds")
    verdict = judge(make_site(), make_fetch(body=body), "torvalds")
    assert verdict.state == "absent"
    assert "title says not found" in verdict.evidence


def test_empty_shell_is_absent():
    body = html_page("torvalds", "torvalds torvalds", filler=0)
    assert len(body) < 1500
    verdict = judge(make_site(), make_fetch(body=body), "torvalds")
    assert verdict.state == "absent"
    assert "empty page" in verdict.evidence


def test_empty_body_is_absent():
    verdict = judge(make_site(), make_fetch(status=200, body=""), "torvalds")
    assert verdict.state == "absent"
    assert "empty response" in verdict.evidence


def test_202_with_empty_body_is_unknown():
    verdict = judge(make_site(), make_fetch(status=202, body="  "), "torvalds")
    assert verdict.state == "unknown"


def test_generic_title_without_handle_is_unknown():
    """A real-looking page that never names the account is a shell."""
    verdict = judge(
        make_site(),
        make_fetch(body=html_page("Welcome to the app", "torvalds")),
        "torvalds",
    )
    assert verdict.state == "unknown"
    assert "no handle" in verdict.evidence


def test_search_redirect_is_unknown():
    verdict = judge(
        make_site(),
        make_fetch(
            body=html_page("torvalds", "torvalds torvalds"),
            url="https://test.example/explore/torvalds",
            requested_url="https://test.example/torvalds",
        ),
        "torvalds",
    )
    assert verdict.state == "unknown"
    assert "non-profile route" in verdict.evidence


def test_redirect_to_sso_host_is_unknown():
    verdict = judge(
        make_site(),
        make_fetch(
            body=html_page("torvalds", "torvalds torvalds"),
            url="https://sso.passport.example.net/push?uuid=1",
            requested_url="https://test.example/torvalds",
        ),
        "torvalds",
    )
    assert verdict.state == "unknown"
    assert "sign-in host" in verdict.evidence


def test_cross_domain_redirect_to_a_normal_host_is_found():
    """Custom profile domains are legitimate; only identity hosts are not."""
    verdict = judge(
        make_site(),
        make_fetch(
            body=html_page("torvalds", "torvalds torvalds"),
            url="https://profiles.example.net/torvalds",
            requested_url="https://test.example/torvalds",
        ),
        "torvalds",
    )
    assert verdict.state == "found"


def test_xml_response_to_html_rule_is_unknown():
    verdict = judge(
        make_site(check="message", absent=["<body"]),
        make_fetch(
            body='<?xml version="1.0"?><rss><channel></channel></rss>',
            content_type="application/rss+xml",
        ),
        "torvalds",
    )
    assert verdict.state == "unknown"
    assert "non-HTML" in verdict.evidence


def test_json_body_skips_size_and_title_rules():
    site = make_site(check="message", present=['"login":'])
    verdict = judge(
        site,
        make_fetch(
            body='{"login":"torvalds"}',
            content_type="application/json",
            url="https://api.test.example/users/torvalds",
        ),
        "torvalds",
    )
    assert verdict.state == "found"


def test_response_url_rule_matches_absent_url():
    site = make_site(check="response_url", absent_url="https://test.example/")
    verdict = judge(
        site,
        make_fetch(url="https://test.example/", requested_url="https://test.example/torvalds"),
        "torvalds",
    )
    assert verdict.state == "absent"


def test_response_url_rule_without_absent_url_uses_status():
    """An incomplete rule must not report every response as found."""
    site = make_site(check="response_url")
    body = html_page("torvalds", "torvalds")
    missing = judge(
        site,
        make_fetch(status=404, url="https://test.example/torvalds", body=body),
        "torvalds",
    )
    present = judge(
        site,
        make_fetch(status=200, url="https://test.example/torvalds", body=body),
        "torvalds",
    )

    assert missing.state == "absent"
    assert present.state == "found"


def test_response_url_rule_with_absent_url_and_404_is_absent():
    site = make_site(check="response_url", absent_url="https://test.example/gone")
    verdict = judge(
        site,
        make_fetch(status=404, url="https://test.example/torvalds"),
        "torvalds",
    )
    assert verdict.state == "absent"
    assert "http 404" in verdict.evidence


def test_dataset_error_marker_is_unknown():
    site = make_site(errors={"login required": "session blocked"})
    verdict = judge(site, make_fetch(body="Login required to continue"), "torvalds")
    assert verdict.state == "unknown"
    assert "session blocked" in verdict.evidence


def test_strict_false_skips_verification():
    body = html_page("Just a moment...", "torvalds")
    verdict = judge(make_site(), make_fetch(body=body), "torvalds", strict=False)
    assert verdict.state == "found"
    assert verdict.evidence.endswith("(unverified)")


def test_ignore403_is_honoured():
    site = make_site(check="message", present=['"id":'], ignore403=True)
    verdict = judge(
        site,
        make_fetch(
            status=403,
            body='{"id":1}',
            content_type="application/json",
        ),
        "torvalds",
    )
    assert verdict.state == "found"


# ─── search pages and echo hygiene ───────────────────────


def test_search_listing_route_is_unknown():
    verdict = judge(
        make_site(),
        make_fetch(
            body=html_page("Profiles", "torvalds torvalds torvalds"),
            url="https://test.example/users/filter?search=torvalds",
        ),
        "torvalds",
    )
    assert verdict.state == "unknown"
    assert "results route" in verdict.evidence


def test_search_query_param_is_unknown():
    verdict = judge(
        make_site(),
        make_fetch(
            body=html_page("scholar", "torvalds torvalds torvalds"),
            url="https://test.example/scholar?q=torvalds",
        ),
        "torvalds",
    )
    assert verdict.state == "unknown"
    assert "search query" in verdict.evidence


def test_handle_in_path_wins_over_query_noise():
    """A profile URL that names the handle is that profile, whatever rides along."""
    verdict = judge(
        make_site(),
        make_fetch(
            body=html_page("torvalds", "torvalds torvalds torvalds"),
            url="https://test.example/torvalds?ref=search&q=torvalds",
        ),
        "torvalds",
    )
    assert verdict.state == "found"


def test_search_title_is_unknown():
    verdict = judge(
        make_site(),
        make_fetch(body=html_page("Search results for torvalds", "torvalds torvalds torvalds")),
        "torvalds",
    )
    assert verdict.state == "unknown"
    assert "search page" in verdict.evidence


def test_link_only_echoes_do_not_upgrade_confidence():
    """Three hrefs repeating the handle are the URL talking, not the page.

    The found/unknown gate counts every echo — requiring three *visible*
    mentions in the live comparison cost real accounts (Twitch, Patreon) —
    but link-only echoes must not earn the confidence upgrade.
    """
    links = '<a href="https://test.example/u/torvalds">profile</a>' * 3
    verdict = judge(make_site(), make_fetch(body=html_page("Someone", links)), "torvalds")
    assert verdict.state == "found"
    assert verdict.confidence == "medium"  # base only: 0 visible echoes
    assert "3 mention(s)" in verdict.evidence


def test_profile_search_route_is_unknown_even_from_a_json_probe():
    """A search API answering 200 still reports a listing page as its URL."""
    site = make_site(
        url="https://test.example/users/filter?search={username}",
        probe="https://api.test.example/lookup?inname={username}",
        check="message",
        present=['"items":[{'],
        absent=['"items":[]'],
    )
    verdict = judge(
        site,
        make_fetch(
            body='{"items":[{"display_name":"teamleader"}]}',
            content_type="application/json",
            url="https://api.test.example/lookup?inname=teamleader",
        ),
        "teamleader",
    )
    assert verdict.state == "unknown"
    assert "results route" in verdict.evidence

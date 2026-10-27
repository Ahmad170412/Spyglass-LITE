"""The benchmark harness is code too.

If the scorer is wrong, every number in the report is wrong in a way that
looks authoritative. These tests pin the arithmetic and the domain handling
without touching the network.
"""

from __future__ import annotations

from bench.score import false_positives, misses, score_run
from bench.tools import ToolRun, _absorb, domain_of
from spyglass_lite.models import Profile, Unknown, UsernameResult

ORACLE = {
    "github.com": True,
    "gitlab.com": True,
    "bitbucket.org": False,
    "codeberg.org": None,
}


def run(found=None, unknown=None) -> ToolRun:
    return ToolRun("lite", "handle", found=found or {}, unknown=unknown or {})


def test_true_positive_and_false_positive_arithmetic():
    score = score_run(
        run(
            found={
                "github.com": "https://github.com/handle",
                "bitbucket.org": "https://bitbucket.org/handle",
            }
        ),
        ORACLE,
    )

    assert (score.tp, score.fp, score.fn) == (1, 1, 1)
    assert score.precision == 0.5
    assert score.recall == 0.5
    assert score.f1 == 0.5


def test_unreached_oracle_is_counted_but_none_is_ignored():
    score = score_run(run(), ORACLE)

    assert score.fn == 2
    assert score.oracle_present == 2
    assert score.oracle_absent == 1


def test_unknown_on_a_present_account_is_reported_separately():
    score = score_run(run(unknown={"github.com": "http 403 (blocked)"}), ORACLE)

    assert score.fn == 2
    assert score.unknown_present == 1


def test_claims_outside_the_oracle_are_unscored():
    score = score_run(run(found={"z.test": "https://z.test/handle"}), ORACLE)

    assert score.unscored_claims == 1
    assert score.fp == 0


def test_no_claims_is_not_a_division_by_zero():
    score = score_run(run(), {"bitbucket.org": False})
    assert score.claims == 0
    assert score.precision == 1.0


def test_helpers_name_the_right_domains():
    scored = run(
        found={
            "github.com": "https://github.com/handle",
            "bitbucket.org": "https://bitbucket.org/handle",
        },
        unknown={"gitlab.com": "blocked"},
    )

    assert false_positives(scored, ORACLE) == [
        ("bitbucket.org", "https://bitbucket.org/handle")
    ]
    assert misses(scored, ORACLE) == ["gitlab.com"]


def test_tool_run_round_trips_through_json_shape():
    original = ToolRun(
        "sherlock",
        "handle",
        found={"a.test": "https://a.test/handle"},
        unknown={"b.test": "blocked"},
        checked=2,
        seconds=1.5,
    )

    assert ToolRun.from_dict(original.to_dict()) == original


def test_domain_of_strips_www_and_port():
    assert domain_of("https://www.example.com:8443/x") == "example.com"
    assert domain_of("https://sub.example.co.uk/x") == "sub.example.co.uk"


def test_absorb_keeps_bare_unknown_domains():
    """Regression: Unknown.domain is a domain, not a URL."""
    result = UsernameResult(
        target="handle",
        found=[
            Profile(
                platform="A",
                domain="a.test",
                url="https://www.a.test/handle",
                confidence="high",
                evidence="http 200",
            )
        ],
        unknown=[Unknown(platform="B", domain="b.test", reason="http 403 (blocked)")],
    )

    run_ = _absorb(result, "lite", 0.1)

    assert run_.found == {"a.test": "https://www.a.test/handle"}
    assert run_.unknown == {"b.test": "http 403 (blocked)"}

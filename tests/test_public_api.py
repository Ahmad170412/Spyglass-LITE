"""The public surface: signatures, docstrings, and the cheap repr.

These are the things a user meets before any scan runs: what the editor
offers while typing, what ``help()`` says, and what a notebook shows for the
return value. An ``**options: Any`` signature makes all of it invisible, so
the verb must mirror its engine's keyword arguments exactly.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

import spyglass_lite as sg
from spyglass_lite import Spyglass
from spyglass_lite.models import Profile, Unknown, UsernameResult

# ``spyglass_lite.username`` the function shadows the module of the same
# name, so attribute-style imports would bind the wrong object.
username_module = importlib.import_module("spyglass_lite.username")
email_module = importlib.import_module("spyglass_lite.email")
ip_module = importlib.import_module("spyglass_lite.ip")
asn_module = importlib.import_module("spyglass_lite.asn")
phone_module = importlib.import_module("spyglass_lite.phone")

_CLIENT = Spyglass()

CASES = [
    (sg.username, username_module.scan),
    (_CLIENT.username, username_module.scan),
    (_CLIENT.ausername, username_module.scan),
    (sg.email, email_module.scan),
    (_CLIENT.email, email_module.scan),
    (_CLIENT.aemail, email_module.scan),
    (sg.ip, ip_module.scan),
    (_CLIENT.ip, ip_module.scan),
    (_CLIENT.aip, ip_module.scan),
    (sg.asn, asn_module.scan),
    (_CLIENT.asn, asn_module.scan),
    (_CLIENT.aasn, asn_module.scan),
    (sg.phone, phone_module.scan),
    (_CLIENT.phone, phone_module.scan),
    (_CLIENT.aphone, phone_module.scan),
]


def _keyword_only(func: object) -> set[str]:
    return {
        name
        for name, param in inspect.signature(func).parameters.items()  # type: ignore[arg-type]
        if param.kind is inspect.Parameter.KEYWORD_ONLY
    }


def _has_var_keyword(func: object) -> bool:
    return any(
        param.kind is inspect.Parameter.VAR_KEYWORD
        for param in inspect.signature(func).parameters.values()  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "public,engine",
    CASES,
    ids=[f"{getattr(p, '__qualname__', p)}-{e.__module__}" for p, e in CASES],
)
def test_public_signature_mirrors_the_engine(public, engine):
    """No ``**options``, and exactly the engine's keyword-only parameters."""
    assert not _has_var_keyword(public)
    assert _keyword_only(public) == _keyword_only(engine)


@pytest.mark.parametrize("public", [p for p, _ in CASES])
def test_every_public_verb_has_a_docstring(public):
    assert (public.__doc__ or "").strip()


@pytest.mark.parametrize("public", [_CLIENT.username_many, _CLIENT.ausername_many])
def test_batch_forms_take_the_same_options_plus_workers(public):
    assert not _has_var_keyword(public)
    assert _keyword_only(public) - {"workers"} == _keyword_only(username_module.scan)


def test_module_verbs_expose_the_new_knobs():
    parameters = inspect.signature(sg.username).parameters
    for name in ("deadline", "sites", "judge", "strict", "verify_catchall"):
        assert name in parameters


def test_unknown_keyword_fails_at_the_call_site():
    """``deadlin=`` must not reach the engine under a different name."""
    with pytest.raises(TypeError, match="deadlin"):
        sg.username("johndoe", deadlin=5)


def test_username_result_repr_is_a_summary():
    result = UsernameResult(
        target="johndoe",
        found=[
            Profile(
                platform="GitHub",
                domain="github.com",
                url="https://github.com/johndoe",
                confidence="high",
                evidence="http 200",
            )
        ],
        unknown=[Unknown(platform="Reddit", domain="reddit.com", reason="http 403 (blocked)")],
    )

    assert repr(result) == "<UsernameResult 'johndoe': 1 found, 1 unknown>"
    assert str(result) == repr(result)


def test_partial_is_visible_in_the_summary():
    result = UsernameResult(target="johndoe", partial=True)
    assert str(result) == "<UsernameResult 'johndoe': 0 found, 0 unknown, partial>"


def test_default_timeout_stays_ten_seconds():
    """A 6s default was measured as no faster on a full scan and lost hits."""
    assert sg.Config().timeout == 10.0

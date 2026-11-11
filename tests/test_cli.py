"""Tests for ``python -m spyglass_lite``.

Every call into the library is replaced by a recorder, so these run offline
and assert on the contract a shell user depends on: the flags that reach the
library, the shape of the text, the encoding of ``--json`` and the exit code.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

import spyglass_lite._cli as cli
from spyglass_lite import (
    AsnResult,
    EmailResult,
    IpResult,
    PhoneResult,
    Profile,
    Unknown,
    UsernameResult,
)
from spyglass_lite.errors import InvalidTarget, MissingDependency


class Recorder:
    """Stand-in for a library verb that remembers how it was called."""

    def __init__(self, result):
        self.result = result
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, target, **kwargs):
        self.calls.append((target, kwargs))
        return self.result


def _username_result(target: str = "johndoe") -> UsernameResult:
    return UsernameResult(
        target=target,
        found=[
            Profile(
                platform="GitHub",
                domain="github.com",
                url="https://github.com/johndoe",
                confidence="high",
                evidence="http 200, 9 mention(s)",
            )
        ],
        unknown=[Unknown("Reddit", "reddit.com", "http 403 (blocked)")],
        checked=2,
        duration_ms=1500,
        partial=True,
    )


def _cp1252_stdout() -> tuple[io.BytesIO, io.TextIOWrapper]:
    raw = io.BytesIO()
    return raw, io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="")


# ─── parsing and dispatch ─────────────────────────────────


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert "spyglass-lite 1.1.0" in capsys.readouterr().out


def test_a_verb_is_required(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main([])
    assert exit_info.value.code == 2
    assert "usage: spyglass-lite" in capsys.readouterr().err


def test_username_flags_reach_the_library(monkeypatch, capsys):
    recorder = Recorder(_username_result())
    monkeypatch.setattr(cli, "username", recorder)

    code = cli.main(
        [
            "username",
            "johndoe",
            "--sites",
            "github.com,codeberg.org",
            "--sites",
            "x.com",
            "--limit",
            "300",
            "--deadline",
            "20",
            "--exclude",
            "reddit.com",
            "--raw",
        ]
    )

    assert code == 0
    target, kwargs = recorder.calls[0]
    assert target == "johndoe"
    assert kwargs["sites"] == ["github.com", "codeberg.org", "x.com"]
    assert kwargs["exclude"] == ["reddit.com"]
    assert kwargs["limit"] == 300
    assert kwargs["deadline"] == 20
    assert kwargs["judge"] is False
    assert kwargs["include_unknown"] is True


def test_defaults_leave_the_library_in_charge(monkeypatch, capsys):
    recorder = Recorder(_username_result())
    monkeypatch.setattr(cli, "username", recorder)

    cli.main(["username", "johndoe"])

    _, kwargs = recorder.calls[0]
    assert kwargs["judge"] is None  # library default, not a forced True
    assert kwargs["sites"] is None
    assert kwargs["limit"] is None
    assert kwargs["deadline"] is None


def test_email_dns_only_skips_third_parties(monkeypatch, capsys):
    recorder = Recorder(EmailResult(target="me@example.com", valid=True))
    monkeypatch.setattr(cli, "email", recorder)

    cli.main(["email", "me@example.com", "--dns-only"])

    _, kwargs = recorder.calls[0]
    assert kwargs["gravatar"] is False
    assert kwargs["breaches"] is False
    assert kwargs["registrations"] is False


# ─── text output ──────────────────────────────────────────


def test_username_text_shows_counts_and_found(monkeypatch, capsys):
    monkeypatch.setattr(cli, "username", Recorder(_username_result()))

    assert cli.main(["username", "johndoe"]) == 0

    out = capsys.readouterr().out
    assert "johndoe: 1 found" in out
    assert "2 checked, 1 unknown" in out
    assert "partial" in out
    assert "github.com" in out
    assert "https://github.com/johndoe" in out
    assert "(high)" in out
    assert "pass --unknown" in out


def test_unknown_is_listed_only_on_request(monkeypatch, capsys):
    monkeypatch.setattr(cli, "username", Recorder(_username_result()))

    cli.main(["username", "johndoe", "--unknown"])

    out = capsys.readouterr().out
    assert "unknown (1)" in out
    assert "http 403 (blocked)" in out


def test_an_empty_scan_is_not_an_error(monkeypatch, capsys):
    monkeypatch.setattr(cli, "username", Recorder(UsernameResult(target="nobody-here", checked=10)))

    assert cli.main(["username", "nobody-here"]) == 0
    assert "no accounts found" in capsys.readouterr().out


def test_asn_text_uses_the_worst_rpki_state(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "asn",
        Recorder(
            AsnResult(
                query="1.1.1.0/24",
                query_type="prefix",
                prefix="1.1.1.0/24",
                origin_asn="AS13335",
                holder="CLOUDFLARENET",
            )
        ),
    )

    assert cli.main(["asn", "1.1.1.0/24"]) == 0

    out = capsys.readouterr().out
    assert "AS13335" in out
    assert "CLOUDFLARENET" in out
    assert "rpki" in out


def test_ip_and_phone_render_their_own_shapes(monkeypatch, capsys):
    monkeypatch.setattr(cli, "ip", Recorder(IpResult(ip="1.1.1.1", hostname="one.one.one.one")))
    monkeypatch.setattr(
        cli, "phone", Recorder(PhoneResult(query="+14155552671", valid=True, region="US"))
    )

    assert cli.main(["ip", "1.1.1.1"]) == 0
    assert cli.main(["phone", "+14155552671"]) == 0

    out = capsys.readouterr().out
    assert "one.one.one.one" in out
    assert "valid" in out
    assert "US" in out


# ─── JSON ─────────────────────────────────────────────────


def test_json_output_is_valid_and_complete(monkeypatch, capsys):
    monkeypatch.setattr(cli, "username", Recorder(_username_result()))

    assert cli.main(["username", "johndoe", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["target"] == "johndoe"
    assert payload["found"][0]["url"] == "https://github.com/johndoe"
    assert payload["unknown"][0]["reason"] == "http 403 (blocked)"


def test_json_is_utf8_even_when_stdout_is_cp1252(monkeypatch):
    result = UsernameResult(
        target="johndoe",
        found=[
            Profile(
                platform="München",
                domain="example.test",
                url="https://example.test/tokyo-東京",
                confidence="high",
                evidence="ok",
            )
        ],
        checked=1,
    )
    monkeypatch.setattr(cli, "username", Recorder(result))
    raw, stream = _cp1252_stdout()
    monkeypatch.setattr(sys, "stdout", stream)

    assert cli.main(["username", "johndoe", "--json"]) == 0

    stream.flush()
    data = raw.getvalue()
    # Written as UTF-8 bytes, not encoded through the console code page.
    assert "München".encode() in data
    assert "東京".encode() in data
    assert json.loads(data.decode("utf-8"))["found"][0]["platform"] == "München"


def test_text_survives_a_console_that_cannot_encode_the_name(monkeypatch):
    result = UsernameResult(
        target="johndoe",
        found=[
            Profile(
                platform="東京",
                domain="example.test",
                url="https://example.test/johndoe",
                confidence="high",
                evidence="ok",
            )
        ],
        checked=1,
    )
    monkeypatch.setattr(cli, "username", Recorder(result))
    raw, stream = _cp1252_stdout()
    monkeypatch.setattr(sys, "stdout", stream)

    # No UnicodeEncodeError: the stream was switched to errors="replace".
    assert cli.main(["username", "johndoe"]) == 0

    stream.flush()
    assert b"johndoe" in raw.getvalue()


# ─── failures ─────────────────────────────────────────────


def test_missing_extra_is_actionable(monkeypatch, capsys):
    def unavailable(_target):
        raise MissingDependency("phonenumbers", "phone", "phone")

    monkeypatch.setattr(cli, "phone", unavailable)

    assert cli.main(["phone", "+14155552671"]) == 1

    err = capsys.readouterr().err
    assert "python -m pip install spyglass-lite[phone]" in err


def test_invalid_target_exits_one(monkeypatch, capsys):
    def invalid(_target, **_kwargs):
        raise InvalidTarget("not an address")

    monkeypatch.setattr(cli, "ip", invalid)

    assert cli.main(["ip", "nope"]) == 1
    assert "not an address" in capsys.readouterr().err

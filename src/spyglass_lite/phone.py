"""Phone number intelligence.

Pure ``phonenumbers`` metadata: validity, region, carrier, line type and
formatting. No external binary, no lookup service, no request leaves the
machine — which is why this module works offline and cannot leak a target.
"""

from __future__ import annotations

import time
from typing import Any

from .errors import InvalidTarget, MissingDependency
from .models import PhoneResult

_LINE_TYPES = {
    0: "fixed-line",
    1: "mobile",
    2: "fixed-line-or-mobile",
    3: "toll-free",
    4: "premium-rate",
    5: "shared-cost",
    6: "voip",
    7: "personal-number",
    8: "pager",
    9: "voicemail",
    10: "unknown",
}


def scan(target: str, **_: Any) -> PhoneResult:
    """Parse a number and describe it.

    A number without a country code is ambiguous, so it is rejected rather
    than guessed: ``+1 415...`` and ``0415...`` are different numbers, and a
    wrong guess produces confident nonsense.
    """
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder
        from phonenumbers import timezone as pn_timezone
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise MissingDependency("phonenumbers", "phone", "phone") from exc

    started = time.perf_counter()
    raw = str(target).strip()
    if not raw:
        raise InvalidTarget("phone target is empty")
    # phonenumbers is lenient about punctuation and will happily read "++123"
    # as +1 23. A second plus sign is a typo, not a country code.
    if raw.count("+") != 1 or not raw.startswith("+"):
        raise InvalidTarget(
            f"{target!r} must start with a single '+' and a country code, for example +14155554471"
        )

    try:
        parsed = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as exc:
        raise InvalidTarget(
            f"{target!r} is not a parseable phone number. Include the country "
            "code, for example +14155554471"
        ) from exc

    possible = phonenumbers.is_possible_number(parsed)
    valid = phonenumbers.is_valid_number(parsed)
    number_type = phonenumbers.number_type(parsed)

    return PhoneResult(
        query=raw,
        valid=valid,
        possible=possible,
        e164=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        international=phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        national=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        country_code=int(parsed.country_code or 0),
        region=phonenumbers.region_code_for_number(parsed) or "",
        location=geocoder.description_for_number(parsed, "en") or "",
        carrier=carrier.name_for_number(parsed, "en") or "",
        timezone=", ".join(pn_timezone.time_zones_for_number(parsed)),
        line_type=_LINE_TYPES.get(number_type, "unknown"),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )

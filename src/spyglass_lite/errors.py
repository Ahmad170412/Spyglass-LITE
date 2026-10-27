"""Exceptions raised by spyglass-lite.

Recon is best-effort by design: a blocked site or a dead API is reported in
the result, not raised. These exceptions are reserved for caller mistakes and
missing optional dependencies, which cannot be represented as data.
"""

from __future__ import annotations


class SpyglassError(Exception):
    """Base class for every error raised by this package."""


class InvalidTarget(SpyglassError, ValueError):
    """The target is not something the chosen module can scan."""


class MissingDependency(SpyglassError, ImportError):
    """An optional extra is required for this call."""

    def __init__(self, package: str, extra: str, module: str) -> None:
        self.package = package
        self.extra = extra
        self.module = module
        super().__init__(
            f"{module}() requires the optional dependency {package!r}.\n"
            f"Install it with:  python -m pip install spyglass-lite[{extra}]"
        )


class NetworkError(SpyglassError):
    """A transport failure, for callers that choose to raise on one.

    Transport failures are data in this package: they are recorded in
    ``result.errors`` and the scan continues. This type exists so an
    application layering its own strict mode over the library has something
    specific to catch; nothing in ``spyglass_lite`` raises it today.
    """

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
            f"Install it with:  pip install spyglass-lite[{extra}]"
        )


class NetworkError(SpyglassError):
    """A transport failure that the caller asked to be raised.

    Only used when ``raise_on_error=True``; the default is to record the
    failure in ``result.errors`` and continue.
    """

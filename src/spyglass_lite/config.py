"""Client configuration."""

from __future__ import annotations

from dataclasses import dataclass, fields

from ._http import DEFAULT_UA


@dataclass(slots=True)
class Config:
    """Knobs shared by every module.

    Defaults are chosen for a library call, not a demo: 50 in flight keeps a
    full 2,285-site scan to a couple of minutes, while the per-host cap stops
    one site from being hit 50 times at once. A per-request timeout of 6s is
    enough for a real profile (slow ones are usually blocked anyway) and caps
    how long a dead host can hold a concurrency slot.
    """

    timeout: float = 6.0
    concurrency: int = 50
    per_host: int = 2
    retries: int = 1
    backoff: float = 1.0
    proxy: str | None = None
    user_agent: str = DEFAULT_UA
    follow_redirects: bool = True
    verify_tls: bool = True

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.per_host < 1:
            raise ValueError("per_host must be at least 1")
        if self.retries < 0:
            raise ValueError("retries cannot be negative")

    @classmethod
    def build(cls, **options: object) -> Config:
        valid = {f.name for f in fields(cls)}
        unknown = sorted(set(options) - valid)
        if unknown:
            raise TypeError(
                "unknown option(s): " + ", ".join(unknown) + ". "
                "Valid options: " + ", ".join(sorted(valid))
            )
        return cls(**options)  # type: ignore[arg-type]

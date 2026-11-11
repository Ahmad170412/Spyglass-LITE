"""Client configuration."""

from __future__ import annotations

from dataclasses import dataclass, fields

from ._http import DEFAULT_UA


@dataclass(slots=True)
class Config:
    """Knobs shared by every module.

    Defaults are chosen for a library call, not a demo: 50 in flight keeps a
    full 2,285-site scan to a couple of minutes, while the per-host cap stops
    one site from being hit 50 times at once.

    The 10s per-request timeout is deliberate. A paired A/B against the full
    site list measured 6s as no faster (108.9s vs 109.0s) while it dropped
    real profiles into ``unknown`` — slow hosts are slow, not dead. To bound
    a scan, pass ``deadline=`` instead of shortening every request.
    """

    timeout: float = 10.0
    concurrency: int = 50
    per_host: int = 2
    retries: int = 1
    backoff: float = 1.0
    proxy: str | None = None
    user_agent: str = DEFAULT_UA
    follow_redirects: bool = True
    verify_tls: bool = True
    cache: bool = False
    cache_dir: str | None = None
    cache_ttl: float = 3600.0
    enrich: bool = False

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.per_host < 1:
            raise ValueError("per_host must be at least 1")
        if self.retries < 0:
            raise ValueError("retries cannot be negative")
        if self.cache_ttl <= 0:
            raise ValueError("cache_ttl must be greater than zero")

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

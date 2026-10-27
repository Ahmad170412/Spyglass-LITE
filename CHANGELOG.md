# Changelog

All notable changes to `spyglass-lite` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `sites=` on `username()` — restrict a scan to display names, domains or full URLs (`sites=["github.com", "https://x.com/"]`), merged with `only=`.
- `sites=` on `email()` — inline recipe dicts or bare domains matched against the bundled recipes; domains without a recipe are reported inconclusive with the reason.
- `deadline=` on `username()` — stop the scan after N seconds and return what was decided by then; `result.partial` reports whether the clock cut it short. This is the supported way to bound a scan: the per-request `timeout` default stays at 10s, because a paired A/B at 6s saved no wall-clock time on a full scan and dropped slow-but-real profiles into `unknown`.
- `judge=` knob on `username()` — `judge=False` selects the raw dataset rule and implies `verify_catchall=False`; `strict=` remains accepted as the old name.
- The public verbs (`sg.username/email/ip/asn/phone`, `Spyglass.username/email/...`, the `a*` async forms, and `username_many`) now declare their keyword arguments explicitly and carry docstrings, so `sites=`, `deadline=`, `judge=` and friends autocomplete and type-check. An unknown keyword now fails at the call site instead of inside the engine.
- `repr(UsernameResult)` is now the compact one-line summary, and `str()` marks a deadline-cut result with `partial`.

### Changed

- Catch-all control probes keep a 10s timeout floor even when `timeout=` is configured lower: they are the slowest request in a scan (one per cached rule) and a short timeout there turned real profiles into `unknown`.
- Verification now demotes search/listing pages — search query parameters carrying the handle (`scholar.google.com?q=…`), listing routes (`/search`, `/filter`), and results-style titles — checked against both the reported profile URL and the fetched URL, where these previously read as false-positive profiles.
- Handle-echo confidence upgrades count visible-copy mentions only; `href`/`src`/URL echoes no longer raise a page's confidence. The found/unknown gate still counts every echo: requiring three *visible* mentions was tested live and cost real accounts.
- Catch-all control probes are cached per rule for 10 minutes, so repeated scans skip the extra request per hit.
- Transport failures (connect timeouts, refused connections, DNS failures) are no longer retried — only HTTP status transients (429/5xx) are, roughly halving worst-case scan time on large site lists.
- CI now runs on Windows (Python 3.10 and 3.13) in addition to Linux and macOS, and lints `scripts/` alongside the package. `compare.py` moved from the repository root into `scripts/`.

### Fixed

- `asn()` now resolves the origin AS and holder for a **prefix** query (`1.1.1.0/24`). RIPEStat answers prefix queries with `resource`/`asns` rather than the covering `prefixes` list an address query returns; only the address shape was handled, so a prefix silently produced no origin at all.
- Response bodies are streamed and cut off at 200 KB *while reading*. Previously the whole response was decoded first and truncated afterwards, so one hostile host could allocate unbounded memory inside a scan running fifty requests at once.
- WHOIS reads are capped at 256 KB with an overall deadline, and CR/LF is stripped from the query: a hostile registry can no longer stream until the process runs out of memory, hold a connection open with a byte every few seconds, or inject a second protocol command.
- Title extraction no longer uses a backtracking-capable pattern. The old expression was quadratic on a body containing many unterminated `<title` tags.
- `_dns.reverse()` is bounded by its `timeout=`; `socket.gethostbyaddr` previously inherited the OS resolver's patience, which is much longer on Windows than on Unix.
- `bench/tools.py` no longer hardcodes a macOS temp path for the upstream checkout. Set `SPYGLASS_UPSTREAM` or place the checkout at `.upstream/`.
- `scripts/compare.py` resolves its report path relative to the repository rather than the working directory, and closes the files it reads.
- RIPEStat query parameters are URL-encoded rather than concatenated.
- `NetworkError`'s docstring described a `raise_on_error=True` option that does not exist.
- Package metadata pointed Homepage/Source at the upstream repository instead of `spyglass-lite`.
- Removed dead code: `_whois.domain()`, `_dns.gather_limited()`, `_whois._REPEATABLE`.

### Security

- Fetches refuse literal private, loopback, link-local and internal hosts (`127.0.0.1`, `169.254.169.254`, `[::1]`, `*.internal`), closing the naive SSRF path through `email(sites=...)`. This is a floor, not a complete defence: a hostname that *resolves* privately, and a public URL that redirects to one, are still reachable. A public deployment must not pass untrusted recipe URLs.

## [0.9.0b0] — 2026-10-26

Beta release. Significant enhancements to stability, accuracy, and benchmarking infrastructure.

### Changed

- Precision-critical verification layer now includes robust redirects guards (e.g., identity providers vs. profiles) and fail-closed controls for catch-all routes.
- Site dataset now includes curated probe overrides for bot-walled services (Codeberg, Lichess, Mastodon).
- Performance optimizations for async requests and UA management.

### Added

- `bench/`: A full benchmarking harness, including oracle-based ground truth (vs. first-party APIs) and field-level parity comparisons against upstream `Spyglass-OSINT`.
- `docs/RECIPES.md`: Documentation for adding custom account-existence recipes.
- GitHub Actions for CI and Trusted Publishing to PyPI.
- Extensive test suite (159 tests total, fully mocked).


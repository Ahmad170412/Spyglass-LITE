<div align="center">

# spyglass-lite

**OSINT recon you can import.** Username enumeration, email intelligence, IP, ASN and phone lookups — no external binaries, no API keys, no CLI.

![CI Status](https://img.shields.io/github/actions/workflow/status/Ahmad170412/spyglass-lite/ci.yml?branch=main&style=flat-square)
![Release](https://img.shields.io/github/v/release/Ahmad170412/spyglass-lite?style=flat-square)
![License](https://img.shields.io/github/license/Ahmad170412/spyglass-lite?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)

[Quick Start](#quick-start) · [Docs](docs/) · [Report Bug](https://github.com/Ahmad170412/spyglass-lite/issues) · [Request Feature](https://github.com/Ahmad170412/spyglass-lite/issues)

</div>

---

## Why spyglass-lite?

- **Importable:** Stop shelling out to subprocesses. Integrate recon directly into your Python apps.
- **Precision First:** Unlike other tools, `lite` employs a rigorous verification layer to eliminate false positives from bot walls and generic landing pages.
- **Offline & Safe:** No external binary dependencies. No OS-level CLI installations required.
- **Transparent:** Results are clearly categorized into `found`, `absent`, and `unknown` (with reasons).

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Repository Structure](#repository-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

```python
import spyglass_lite as sg

# Quick check: stop after 20 seconds, keep whatever was decided by then
result = sg.username("johndoe", deadline=20)
for profile in result.found:
    print(f"Found on {profile.platform}: {profile.url} ({profile.confidence})")
```

A full scan of all 2,285 sites takes a couple of minutes. For a first look,
pass `deadline=`; for a narrower look, pass `sites=`. Both return real
results, not an error:

```python
result = sg.username("johndoe", sites=["github.com", "x.com", "reddit.com"])
print(result)          # <UsernameResult 'johndoe': 2 found, 1 unknown>
print(result.partial)  # True if a deadline cut the scan short
```

**Fewer hits than expected?** Read `result.unknown`. A site that blocks bots
(403), shows a challenge page, or serves the same shell to every handle is
reported there with the reason — it is not silently counted as "no account".
`unknown` is the honest middle state, and it is usually the bigger list. A
site that is merely slow shows up as a `request failed (…Timeout…)`: the
default per-request timeout is 6 seconds, so raise it for a slow network
(`sg.lite(timeout=10)`) rather than reading the absence as a fact.

---

## Architecture

`spyglass-lite` is the importable core of Spyglass OSINT, rewritten for in-process execution. It avoids the orchestration of external CLI tools (Sherlock, Maigret, etc.) by embedding the site rules and engines directly, ensuring consistent results and removing environmental fragility.

---

## Features

| Module | Returns | Needs |
| --- | --- | --- |
| `username()` | Platforms where a handle exists | 2,285 bundled site rules |
| `email()` | Validation, MX/provider, SPF/DMARC, Gravatar, breach hits | HTTP + DNS |
| `ip()` | Geolocation, reverse DNS, WHOIS, passive ports | HTTP + WHOIS/43 |
| `asn()` | Covering prefix, origin AS, RPKI state | RIPEStat |
| `phone()` | Carrier, region, line type, formats | `[phone]` extra |

---

## Installation

```bash
pip install spyglass-lite
pip install "spyglass-lite[phone]"    # optional: phonenumbers
```

Python 3.10+. Two core dependencies: `httpx` and `dnspython`.

---

## Configuration

```python
import spyglass_lite as sg

# Configure a custom client
client = sg.lite(
    timeout=8,          # per request, seconds (default 6)
    concurrency=100,    # global in-flight cap (default 50)
    per_host=2,         # cap per hostname
    retries=1,          # transient HTTP statuses only
    proxy="socks5://127.0.0.1:9050",   # needs spyglass-lite[socks]
)

# Use your custom client
client.username("johndoe", limit=500)
```

---

## Usage

### Username Enumeration

```python
# Stop after 30 seconds; take what has been decided by then
r = sg.username("johndoe", deadline=30)
if r.partial:
    print("the clock cut the scan short")

# Specific sites only — display names, domains, or full URLs
r = sg.username("johndoe", sites=["github.com", "https://x.com/someone"])

# A full scan of every bundled site (no deadline). ``limit`` keeps the N most
# popular sites, which are often the bot-walled ones — pair it with deadline=
# rather than expecting it to be quick.
r = sg.username("johndoe", limit=300, deadline=20)

# Raw mode: the dataset rule only, no verification layer and no
# catch-all probe. Used to compare against Sherlock/Maigret output.
r = sg.username("johndoe", judge=False)

# High-confidence results only
for profile in r.high_confidence:
    print(profile.url)

# Audit unknown results — this is why the found list is short
for u in r.unknown:
    print(f"{u.domain} could not be decided: {u.reason}")
```

By default every hit passes the verification layer: challenge and
registration pages, empty app shells, search/listing URLs, and sites that
serve the same page for any handle are reported as `unknown` with the
reason, not as accounts.

### Email Intelligence

**Tier A** (passive) is default. **Tier B** (active account existence) is opt-in:

```python
sg.email("me@example.com", registrations=True, recipes_path="my-recipes.json")

# Or pass recipes inline / pick bundled ones by domain — see docs/RECIPES.md
sg.email("me@example.com", sites=[{"name": "Example", "url": "https://…", "exists_when": {...}}])
```

---

## Testing

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,phone]"

pytest -q                 # offline: every HTTP and DNS call is mocked
ruff check src tests bench
mypy
python -m build
```

---

## Repository Structure

```text
.
├── bench/                # Benchmarking harness vs Sherlock/Maigret
├── docs/                 # Documentation (RECIPES.md)
├── scripts/              # Dataset generation tools
├── src/spyglass_lite/    # Core package source
└── tests/                # 150+ mocked offline tests
```

---

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Run `pytest` and `ruff`.
4. Submit a Pull Request.

---

## License

MIT. Derived from Spyglass OSINT (MIT, © Atheer), and includes site rules from Sherlock (MIT) and Maigret (MIT). See [NOTICE](NOTICE).

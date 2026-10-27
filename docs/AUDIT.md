# Security and reliability audit — `spyglass-lite` 0.9.0b0

| | |
|---|---|
| **Date** | 2026-10-27 |
| **Version** | `0.9.0b0` (pre-release) |
| **Commit** | `1cc2ad6` on top of `397d9f4` |
| **Scope** | `src/spyglass_lite/`, `tests/`, `bench/`, `scripts/`, packaging and CI |
| **Method** | Manual review of every module and helper in the package; static pattern search for dangerous APIs; dependency advisory review; live execution of every public verb; wheel and sdist inspection |
| **Status** | 220 tests passing · mypy clean · ruff clean (one pre-existing finding intentionally left) |

## 1. Summary

Fourteen findings. Two are worth acting on before anything is exposed publicly: the
response-body buffering issue (F-01) and the trust boundary around `email(sites=...)`
(F-02). Neither is remotely exploitable in the library's normal use; both matter the
moment a scan is driven by a stranger's input.

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-01 | Medium | Whole response decoded before truncation → memory exhaustion | **Fixed** |
| F-02 | Medium | `email(sites=...)` fetches caller-supplied URLs (SSRF) | **Mitigated**, residual |
| F-03 | Medium | WHOIS read unbounded; CRLF in query allowed command injection | **Fixed** |
| F-04 | Medium | `asn()` on a prefix returned no origin AS (correctness) | **Fixed** |
| F-05 | Low | `_dns.reverse()` had no timeout; OS resolver set the ceiling | **Fixed** |
| F-06 | Low | Catch-all control cache crossed proxy/UA boundaries | **Fixed** |
| F-07 | Low | Title regex was quadratic on malformed input | **Fixed** |
| F-08 | Low | Hardcoded macOS path broke the benchmark off one machine | **Fixed** |
| F-09 | Low | Geolocation fallback used plaintext HTTP | **Open** — decision needed |
| F-10 | Low | `email()` discloses the address to third parties by default | **Documented**, decision needed |
| F-11 | Info | `recipes_path=` reads an arbitrary file | By design; documented |
| F-12 | Low | Declared `dnspython` floor allowed a vulnerable version | **Fixed** for 3.11+, gap on 3.10 |
| F-13 | Info | Brotli decoder inherited from the host environment (CVE-2026-111497) | Environmental |
| F-14 | Info | Dead code, stale docstrings, wrong package URLs, dead ignore rule | **Fixed** |

## 2. Findings

### F-01 — Response bodies were fully buffered before truncation

**Severity:** Medium (availability) · **CWE-400** · **Fixed**

`fetch()` called `response.text[:MAX_BODY]`. `response.text` decodes the *entire*
body into memory; the 200 KB cap only applied to the string that was kept. A site
returning a multi-gigabyte response — accidentally or deliberately — would be read
in full, and a scan runs up to fifty requests at once.

**Evidence:** `_http.py`, previous line `text=response.text[:MAX_BODY]`.

**Fix:** the body is now read through `client.stream()` and the loop stops at
`MAX_BODY`. Oversized responses cost a bounded amount of memory and a closed
connection instead of an OOM.

**Residual:** truncation can split a UTF-8 sequence at the boundary; the decoder
uses `errors="replace"`, so the last character may be `�`. Irrelevant to verdicts.

---

### F-02 — `email(sites=...)` fetches caller-supplied URLs

**Severity:** Medium (trust boundary) · **CWE-918** · **Mitigated, residual**

`resolve_sites()` accepts inline recipe dicts, and `_run_recipe()` fetches whatever
`url` they contain. Before this audit, `{"url": "http://169.254.169.254/latest/meta-data/"}`
was fetched verbatim, as was `http://127.0.0.1:…`. In a library this is the caller's
own input; in an API that forwards user input to `sites=`, it is server-side request
forgery.

**Fix:** `fetch()` now refuses literal private, loopback, link-local, reserved and
internal hosts, plus the names `localhost`, `*.localhost` and `*.internal`.
Verified live:

```
http://169.254.169.254/latest/meta-data/  → blocked host (private, loopback or internal address)
http://127.0.0.1:8000/                    → blocked host (private, loopback or internal address)
http://[::1]/                              → blocked host (private, loopback or internal address)
```

**Residual — documented, not fixed:**

- a **hostname that resolves** to a private address is not caught (no DNS check);
- a public URL that **redirects** to a private address is not caught;
- DNS rebinding defeats any pre-flight check of this kind.

A complete fix needs connection-level peer-address validation (a custom httpx
transport) plus `follow_redirects` re-validation on every hop. That is a larger
change than this pass; the standing rule for any deployment is **do not expose
`email()` with a caller-controlled `sites=`**. For the preview API, expose
`username()` only.

---

### F-03 — WHOIS: unbounded read and CRLF injection

**Severity:** Medium · **CWE-400 / CWE-93** · **Fixed**

Two defects in `_query()`:

1. The read loop accumulated chunks until the server closed the socket, with the
   timeout **reset per chunk**. A server sending one byte every eleven seconds kept
   the connection open indefinitely and grew the buffer without limit.
2. The query was written as `payload + b"\r\n"` with no sanitisation. A payload
   containing `\r\n` is a second WHOIS command, not part of a name.

**Fix:** 256 KB cap, an overall deadline of `2 × timeout` across the whole read,
and `\r`/`\n` stripped from the payload. Partial output is kept when the deadline
fires, because a truncated registry record is still evidence.

---

### F-04 — `asn()` returned no origin for a prefix

**Severity:** Medium (correctness, not security) · **Fixed**

`asn()` accepts three input forms: address, prefix, AS number. For a prefix it
returned `query_type="prefix"`, the prefix itself, and **no origin AS, no holder,
no RPKI**. RIPEStat answers a prefix query with top-level `resource`/`asns`, while
an address query returns a `prefixes` list; only the address shape was parsed.

**Why the tests missed it:** the shared fixture mocked the address-shaped response
for every resource, including the prefix test — which asserted only `prefix` and
`query_type`, never `origin_asn`. The mock was wrong in the same direction as the
code.

**Evidence:** live, before and after:

```
before  sg.asn("1.1.1.0/24") → prefix=1.1.1.0/24  origin=  rpki=unknown
after   sg.asn("1.1.1.0/24") → prefix=1.1.1.0/24  origin=AS13335  holder=CLOUDFLARENET  rpki=valid
```

**Fix:** both response shapes handled; a regression test mocks the real prefix
shape and asserts the origin.

---

### F-05 — Reverse DNS had no timeout

**Severity:** Low · **CWE-400 / portability** · **Fixed**

`_dns.reverse()` ran `socket.gethostbyaddr` in a worker thread with no bound.
That call inherits the OS resolver's patience, which is not the library's
`timeout=`: on Windows it can block for tens of seconds. A single slow PTR lookup
could hold an `ip()` scan open far past its configured budget.

**Fix:** wrapped in `asyncio.wait_for(..., timeout=timeout)`. The worker thread is
not killed (Python cannot kill threads), but the caller is no longer blocked by it.

---

### F-06 — Control cache crossed transport boundaries

**Severity:** Low (correctness) · **Fixed**

The catch-all control cache is process-wide and was keyed by `method|url|payload`
only. A control probe run through a SOCKS proxy, or with a custom `user_agent`,
was reused for a direct client — and the catch-all page a site serves can depend on
exactly those things. The cached verdict could therefore be wrong for the scan that
consumed it.

**Fix:** the key now includes proxy, user agent and TLS verification setting.

---

### F-07 — Quadratic title regex

**Severity:** Low · **CWE-1333** · **Fixed**

`<title[^>]*>(.*?)</title>` with `re.DOTALL` backtracks across the whole document
for every `<title` occurrence when no closing tag follows. A 200 KB body containing
thousands of unterminated `<title>` fragments could burn seconds of CPU per site.

**Fix:** `[^<]*` instead of a lazy DOTALL group (linear, cannot cross `<`), plus a
32 KB scan window. Titles in real pages live in `<head>`.

---

### F-08 — Hardcoded macOS path in the benchmark

**Severity:** Low (portability) · **Fixed**

`bench/tools.py` contained:

```python
UPSTREAM = Path("/private/var/folders/r2/r2_…/T/opencode/spyglass-src")
```

A private temp directory from one machine, committed to the repository. The
benchmark could not run anywhere else, on any OS — and the directory no longer
exists, so it was already broken here.

**Fix:** `SPYGLASS_UPSTREAM` environment variable, falling back to `.upstream/`
beside `pyproject.toml`. Both are documented in `bench/README.md` and the directory
is git-ignored.

---

### F-09 — Plaintext HTTP geolocation fallback

**Severity:** Low · **CWE-319** · **Open**

`ip._geo()` falls back to `http://ip-api.com/json/…` when the primary provider
(`https://ipwho.is`) fails. The address being investigated travels in cleartext, and
a network attacker can alter the returned city/ISP/ASN — the fallback is labelled
in the result, but a tampered answer is still a wrong answer.

ip-api's free tier does not offer HTTPS, so fixing this means changing provider, not
changing a scheme.

**Options:** (a) drop the fallback — geo is unavailable rather than silently
downgraded; (b) move to a keyless HTTPS provider (`ipapi.co`, `ipinfo.io`) and remap
the fields. Recommendation: (a), with (b) as a follow-up.

---

### F-10 — `email()` discloses the address to third parties by default

**Severity:** Low · **CWE-359** (privacy) · **Documented, Open**

Tier A sends data off-host by default:

| Check | What leaves the machine | Destination |
|---|---|---|
| Gravatar | MD5 hash; the **plain address** in the profile lookup | `gravatar.com`, `en.gravatar.com` |
| Breaches | the **plain address** | `leakcheck.io`, `scylla.so` |
| MX/SPF/DMARC | the domain only | DNS resolver |

This is inherent to the features, but it was undocumented. `README.md` now states it
and points at `gravatar=False, breaches=False` for a DNS-only lookup.

**Decision needed:** keep both on by default (current), or make breach lookups
opt-in. For a public preview, `email()` should not be exposed at all.

---

### F-11 — `recipes_path=` reads an arbitrary file

**Severity:** Info · **By design**

`load_recipes(path)` opens whatever path it is given and parses it as JSON. Correct
for a library (the caller is the trust boundary), a local-file-disclosure primitive
in any API that forwards the argument. Documented; must not be exposed.

---

### F-12 — Declared `dnspython` floor allowed a vulnerable version

**Severity:** Low · **CVE-2026-114605 / GHSA-45c3-73f7-pv4m** (CVSS 7.5) · **Fixed for 3.11+**

`dns.name.from_wire_parser()` follows attacker-controlled compression pointers
without a hop limit, so a crafted DNS message can exhaust CPU. Fixed in
**dnspython 2.9.0**, which requires **Python 3.11**.

`pyproject.toml` declared `dnspython>=2.6`, which permits 2.6–2.8. It now declares:

```toml
"dnspython>=2.9.0; python_version >= '3.11'",
"dnspython>=2.6,<2.9; python_version < '3.11'",
```

**Residual:** Python 3.10 users (the version reached end of life this month) still
resolve to 2.8.x and cannot be patched. **Decision needed:** drop 3.10 and require
3.11, or keep the split.

**Exposure here:** the library is a stub resolver — it parses responses from the
configured recursive resolver. Exploitation requires an on-path attacker or a
malicious resolver, so the practical risk is low, but the floor should not ship
vulnerable.

---

### F-13 — Brotli decoder inherited from the environment

**Severity:** Info · **CVE-2026-111497** ("HTTP2Shell") · **Environmental**

httpx decompresses Brotli automatically **if** `Brotli` or `brotlicffi` is importable
in the environment. Brotli 1.0.3–1.0.9/1.1.0/1.2.0 carry a memory-corruption flaw
patched on 2026-10-23. Neither package is a dependency of `spyglass-lite`, and
neither is installed in the audit environment — but an application that installs one
inherits the risk on every fetched page.

**Mitigation:** keep `Brotli`/`brotlicffi` at the patched release in any deployment.
Not changed in code: forcing `Accept-Encoding: gzip, deflate` would not stop a
malicious server from replying with `br` anyway.

---

### F-14 — Dead code and stale metadata

**Severity:** Info · **Fixed**

- `_whois.domain()` — unreachable; the only domain-WHOIS path, never wired to a verb.
- `_dns.gather_limited()` — unused helper.
- `_whois._REPEATABLE` — unused constant.
- `NetworkError` documented a `raise_on_error=True` option that does not exist.
- `pyproject.toml` Homepage/Source pointed at `Spyglass-OSINT`, not `spyglass-lite`.
- `.gitignore` had a `!build/cache/.gitkeep` negation under an excluded parent — a
  rule Git cannot honour.
- `scripts/compare.py` (formerly `compare.py`) leaked file handles and resolved its
  report path from the working directory; two ruff findings in `scripts/` were
  invisible because CI did not lint that directory.

## 3. Dependency review

Resolved in the audit environment (`.venv`, CPython 3.11.15):

| Package | Installed | Advisories |
|---|---|---|
| `httpx` | 0.28.1 | None affecting this version (Snyk: 0 known) |
| `httpcore` | 1.0.9 | None known |
| `h11` | 0.16.0 | Current; includes the 2025 request-smuggling fix |
| `dnspython` | 2.9.0 | Includes the fix for CVE-2026-114605 |
| `idna` | 3.20 | Current |
| `certifi` | 2026.10.23 | Current bundle |
| `anyio` | 4.15.1 | None known |

`pip-audit` is not installed in the environment and was not run; the table is from
version inspection plus advisory lookups, not an automated scan. **Follow-up:** add
`pip-audit` to the CI job so this is mechanical rather than manual.

## 4. Cross-OS review

`src/spyglass_lite/` contains **no** platform-specific imports: no `signal`,
`resource`, `fcntl`, `termios`, `pwd`, `grp`, `msvcrt`, `winreg`, no `os.fork`, no
`SIGALRM`, no `uvloop`.

| Area | Implementation | Status |
|---|---|---|
| File paths | `pathlib` throughout; no hardcoded separators | Verified by search; the one violation (F-08) removed |
| Text I/O | every `open()` passes `encoding="utf-8"` | Verified by search |
| Subprocess | none in the package; enforced by `tests/test_no_subprocess.py` | Enforced in CI |
| Signals / timers | none; deadlines use `asyncio.wait` and `wait_for` | Verified by search |
| Sockets | `httpx`, `dnspython`, `asyncio.open_connection` (TCP/43) | Live on macOS; Windows exercised only in CI |
| Event loop | `asyncio.run`; Proactor loop on Windows supports TCP | No selector-only API used |
| Host normalisation | hosts/domains lowercased before comparison | Case-insensitive by construction |
| Bench paths | temp dirs via `tempfile`; upstream checkout configurable | Fixed (F-08) |
| CI matrix | Linux 3.10–3.13, macOS 3.11, **Windows 3.10 and 3.13** | Added; not yet executed |

**Honest limitation:** Windows was never tested before this audit, and it has not
been executed on Windows by the author either — the runner was added and the source
was reviewed for Unix-only APIs, but the first CI run is the actual proof. The single
known platform-sensitive call (F-05) is now bounded.

## 5. Verification evidence

```
pytest -q                       220 passed in 2.34s
mypy                            Success: no issues found in 14 source files
ruff check src tests bench scripts
                                tests/test_bench.py:8:1 I001 (pre-existing, left by request)
ruff format --check             same single file
python -m build                 wheel + sdist built
wheel inspection                24 entries; data/ + py.typed present; no .pyc
```

Live smoke test, all five public verbs, one network:

| Verb | Result |
|---|---|
| `username("torvalds", only=["github.com","gitlab.com","codeberg.org"])` | 2 found, 0 unknown, 726 ms |
| `email("torvalds@linux-foundation.org", gravatar=False, breaches=False)` | valid, Google Workspace, 5 MX, SPF true |
| `ip("1.1.1.1")` | `one.one.one.one`, geo, 5 ports, WHOIS fields |
| `asn("1.1.1.1")` / `asn("1.1.1.0/24")` | AS13335 / CLOUDFLARENET, RPKI valid |
| `phone("+14155552671")` | valid, US, fixed-line-or-mobile |

## 6. Not covered

- **No fuzzing.** Input handling was reviewed and tested, not fuzzed.
- **No live Windows run.** See §4.
- **No audit of the 2,285 bundled site rules.** They are data from Sherlock and
  Maigret; a hostile entry could point at an internal URL, which F-02's host check
  now blocks at fetch time, but the rules themselves were not reviewed line by line.
- **No legal/privacy review** of the breach and Gravatar lookups (F-10).
- **No threat model for the planned preview API** — that is a separate document and
  the reason F-02 matters.
- **`pip-audit` not run** (§3).

## 7. Open decisions

1. **F-09** — drop the plaintext geolocation fallback, or replace the provider?
2. **F-10** — keep Gravatar/breach lookups on by default, or make them opt-in?
3. **F-12** — keep Python 3.10 with an unpatched resolver, or require 3.11?
4. **`tests/test_bench.py`** — fix the last ruff finding (I001), or keep it as-is?

## 8. Rules for any public deployment

Derived from the findings above, and the basis for the preview plan:

- expose `username()` only; never `email(sites=...)` or `recipes_path=`;
- clamp `limit`, `deadline` and `concurrency` server-side — the library accepts any
  value;
- return `include_unknown=False` by default (the unknown list is ~700 entries);
- cap response size and require a bearer token per invitee;
- run behind a tunnel with an access gate, not a public port.

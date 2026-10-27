# Benchmark

Two questions, two harnesses.

| harness | question | command |
| --- | --- | --- |
| `bench.run` | Who finds more real accounts, with fewer false positives? | `python -m bench.run` |
| `bench.fields` | Do the modules that both projects ship agree on the facts? | `python -m bench.fields` |

Results land in `bench/results/`. Raw runs and oracle probes are cached in
`bench/.cache/`, which is git-ignored; `--refresh` re-measures everything.

`bench.fields` and the `spyglass` rows of `bench.run` need a local checkout of
upstream Spyglass. Point at it with `SPYGLASS_UPSTREAM=/path/to/Spyglass-OSINT`,
or place it at `.upstream/` beside `pyproject.toml` (git-ignored). There is no
hardcoded path: the harness is expected to run on any machine and any OS.

## Why an oracle, not a diff

Comparing lite's output to Sherlock's output tells you where they disagree,
not who is right. Both tools claim a URL; neither can prove the account
exists. So the benchmark asks a third party instead: a first-party API that
answers "does this handle have an account here?" with an account record or a
404. `bench/oracles.py` lists all of them.

Eighteen services qualify. Each one offers a keyless, documented endpoint:

GitHub, GitLab, Bitbucket, Codeberg, Gitee, Hugging Face, Docker Hub, npm,
DEV, Keybase, Mastodon, Hacker News, Chess.com, Lichess, Wikipedia, sourcehut,
itch.io and Last.fm.

Services that only expose a rendered profile page are *not* oracles, because
the page being absent is exactly the thing under test. Reddit, npm's web UI
and Wikimedia's HTML endpoint were dropped for returning 403 to this host —
an oracle that guesses is worse than none. `None` cells (timeout, rate limit,
WAF) are excluded from scoring rather than counted as "absent".

## What is scored

For every tool × handle, on oracle domains only:

- **TP** — claimed and the oracle confirms the account.
- **FP** — claimed and the oracle says there is no account.
- **FN** — the oracle confirms an account the tool did not claim.
- **unknown\*** — the oracle confirms an account that lite explicitly
  reported as unreachable. Sherlock and Maigret have no equivalent state, so
  this column is lite-only by construction; it is there so an honest "blocked"
  is not silently counted as a miss without a trace.
- **unscored** — claims outside the oracle set. Real sites, but not
  independently verified here. The report lists lite's unscored claims and
  how many of them another engine also found, so they can be audited.

Precision and recall are computed from those counts. Recall is bounded by
each engine's own database; the report prints how many oracle domains each
database covers, because a tool cannot find an account on a site it never
checks.

## Fairness settings

- Every engine gets a 15 s per-request timeout.
- Maigret runs `--top-sites 1000`, matching upstream Spyglass's own default,
  with recursion and extraction disabled so it behaves as a username checker.
- Sherlock runs its bundled list.
- lite runs all 2,285 bundled sites with the verification layer on (`lite`)
  and with it off (`lite-raw`). `lite-raw` is the apples-to-apples comparison
  with the other engines' raw rule evaluation.
- Upstream Spyglass runs `spyglass.username.username()` unmodified, which
  fans out to user-scanner, Sherlock, Maigret and Blackbird. On machines
  without Blackbird it degrades exactly as it does for a normal user.

Handles include four real accounts and two gibberish controls
(`zq9x7v3k2m1p`, `n0trealuser8x7q`). The controls are the precision test: a
tool that reports profiles for them is pattern-matching on its own URL
template.

## Known limits

- **The network is the instrument.** A Cloudflare wall seen by lite is also
  seen by Sherlock; a site that blocks this host will depress every tool's
  numbers. Re-run on a different network before drawing conclusions from a
  two-point difference.
- **Oracles lag.** Chess.com and Lichess can have a real account for a handle
  that belongs to somebody else entirely. The question here is existence, not
  identity.
- **A user agent is not a fingerprint.** Codeberg rejects an old Chrome major
  outright; so does a real browser profile. lite's UA is versioned, and
  `bench.run` will show coverage drift when it goes stale.
- **Rate limits.** Running the full matrix takes roughly 45–60 minutes and
  makes thousands of requests. It is a maintainer tool, not CI.

## Reading the output

`bench/results/report.md` has four tables worth looking at in order:

1. **Aggregate** — precision/recall/F1 per tool across all handles.
2. **Oracle-domain coverage** — whether a recall gap is a bug or a missing
   rule.
3. **False positives vs oracle** — the domains each tool got wrong.
4. **Claims only lite makes** — the manual-audit queue, with the oracle's
   verdict where one exists.

`bench/results/fields.md` compares IP, ASN, phone and email/Gravatar fields
against upstream Spyglass module by module, and lists what lite reports that
upstream does not.

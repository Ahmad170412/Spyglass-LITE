# spyglass-lite benchmark

Generated 2026-10-26T04:42:17Z · 1 handle(s) · 18 oracles

`unknown*` counts oracle-confirmed accounts the tool reported as unreachable rather than absent. `unscored` counts claims outside the oracle set (real sites, but not independently verified here).

## Aggregate

| tool | handle | TP | FP | FN | precision | recall | F1 | unknown* | unscored | seconds |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| spyglass | all | 8 | 1 | 4 | 89% | 67% | 0.76 | 0 | 55 | 158s |

## Per handle

| tool | handle | TP | FP | FN | precision | recall | F1 | unknown* | unscored | seconds |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| spyglass | torvalds | 8 | 1 | 4 | 89% | 67% | 0.76 | 0 | 55 | 158s |

## Oracle-domain coverage

| engine | oracle domains in its database |
|---|---:|
| lite | 18/18 |
| sherlock | 15/18 |
| maigret | 16/18 |
| spyglass | 16/18 |

## False positives vs oracle

- **spyglass / torvalds**: `news.ycombinator.com`

## Oracle-confirmed accounts missed

- **spyglass**:
  - torvalds: `codeberg.org`, `lichess.org`, `mastodon.social`, `npmjs.com`

## Claims only lite makes

No lite runs.

None — every lite claim was corroborated by another engine.

Wall clock for this invocation: 158s.

Oracle probes are cached in `bench/.cache/`; tool runs are cached too. Pass `--refresh` to re-measure.

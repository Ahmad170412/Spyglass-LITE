"""Score a tool run against the oracle matrix."""

from __future__ import annotations

from dataclasses import dataclass

from .oracles import BY_DOMAIN
from .tools import ToolRun


@dataclass
class Score:
    tool: str
    handle: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    unknown_present: int = 0
    unscored_claims: int = 0
    oracle_absent: int = 0
    oracle_present: int = 0
    seconds: float = 0.0
    error: str = ""

    @property
    def claims(self) -> int:
        return self.tp + self.fp

    @property
    def precision(self) -> float:
        return self.tp / self.claims if self.claims else 1.0

    @property
    def recall(self) -> float:
        return self.tp / self.oracle_present if self.oracle_present else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def merge(self, other: Score) -> Score:
        return Score(
            tool=self.tool,
            handle="all",
            tp=self.tp + other.tp,
            fp=self.fp + other.fp,
            fn=self.fn + other.fn,
            unknown_present=self.unknown_present + other.unknown_present,
            unscored_claims=self.unscored_claims + other.unscored_claims,
            oracle_absent=self.oracle_absent + other.oracle_absent,
            oracle_present=self.oracle_present + other.oracle_present,
            seconds=self.seconds + other.seconds,
            error=self.error or other.error,
        )


def score_run(run: ToolRun, oracle: dict[str, bool | None]) -> Score:
    result = Score(
        tool=run.tool,
        handle=run.handle,
        seconds=run.seconds,
        error=run.error,
    )

    for domain, exists in oracle.items():
        if exists is None:
            continue
        if exists:
            result.oracle_present += 1
        else:
            result.oracle_absent += 1

        claimed = domain in run.found
        if claimed:
            if exists:
                result.tp += 1
            else:
                result.fp += 1
        else:
            if exists:
                result.fn += 1
                if domain in run.unknown:
                    result.unknown_present += 1

    result.unscored_claims = sum(1 for domain in run.found if domain not in oracle)
    return result


def false_positives(run: ToolRun, oracle: dict[str, bool | None]) -> list[tuple[str, str]]:
    return [
        (domain, url) for domain, url in sorted(run.found.items()) if oracle.get(domain) is False
    ]


def misses(run: ToolRun, oracle: dict[str, bool | None]) -> list[str]:
    return [
        domain
        for domain, exists in sorted(oracle.items())
        if exists and domain not in run.found and domain in BY_DOMAIN
    ]


def table(rows: list[Score]) -> str:
    header = (
        "| tool | handle | TP | FP | FN | precision | recall | F1 | unknown* | unscored | seconds |\n"
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )
    lines = [header]
    for row in rows:
        lines.append(
            f"| {row.tool} | {row.handle} | {row.tp} | {row.fp} | {row.fn} | "
            f"{row.precision:.0%} | {row.recall:.0%} | {row.f1:.2f} | "
            f"{row.unknown_present} | {row.unscored_claims} | {row.seconds:.0f}s |"
        )
    return "\n".join(lines)

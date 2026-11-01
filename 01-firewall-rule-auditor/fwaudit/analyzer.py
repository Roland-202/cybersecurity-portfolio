"""Runs every check and turns findings into a scored report."""
from __future__ import annotations

from dataclasses import dataclass, field

from .checks import ALL_CHECKS
from .models import Finding, ParsedConfig, Severity

PENALTY = {Severity.CRITICAL: 30, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0}


@dataclass
class AuditResult:
    config: ParsedConfig
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(PENALTY[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"

    @property
    def counts(self) -> dict[str, int]:
        out = {sev.label: 0 for sev in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


def analyze(cfg: ParsedConfig) -> AuditResult:
    findings = [f for check in ALL_CHECKS for f in check(cfg)]
    findings.sort(key=lambda f: (-int(f.severity), f.container if not f.rule else f.rule.container,
                                 f.rule.index if f.rule else 0, f.check_id))
    return AuditResult(config=cfg, findings=findings)

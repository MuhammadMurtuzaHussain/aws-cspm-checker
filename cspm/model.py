"""Data model shared by checks and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    service: str
    severity: str  # default / worst-case severity for the check
    description: str
    remediation: str
    cis: Tuple[str, ...] = ()
    iso27001: Tuple[str, ...] = ()
    nis2: Tuple[str, ...] = ()


@dataclass
class Finding:
    check_id: str
    severity: str
    resource: str
    region: str
    message: str


@dataclass
class Outcome:
    """Collector handed to each check function."""

    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    evaluated: int = 0
    _check_id: str = ""

    def add(self, severity: str, resource: str, message: str, region: str = "global") -> None:
        self.findings.append(Finding(self._check_id, severity, resource, region, message))

    def error(self, message: str) -> None:
        self.errors.append(message)


@dataclass
class CheckResult:
    meta: CheckMeta
    findings: List[Finding]
    evaluated: int
    errors: List[str]

    @property
    def status(self) -> str:
        if self.findings:
            return "FAIL"
        if self.errors:
            return "ERROR"
        return "PASS"

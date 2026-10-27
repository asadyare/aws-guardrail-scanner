"""Findings, errors, and the scan report."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from aws_guardrail_scanner import __version__


class Severity(StrEnum):
    """Finding severity, from informational to critical."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """One misconfiguration on one resource."""

    check_id: str
    title: str
    severity: Severity
    resource_id: str
    region: str
    description: str
    remediation: str
    reference: str

    def to_dict(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_id": self.resource_id,
            "region": self.region,
            "description": self.description,
            "remediation": self.remediation,
            "reference": self.reference,
        }


@dataclass(frozen=True, slots=True)
class ScanError:
    """A read that failed. This is not itself a misconfiguration."""

    check_id: str
    message: str
    resource_id: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "check_id": self.check_id,
            "message": self.message,
            "resource_id": self.resource_id,
        }


@dataclass(slots=True)
class ScanReport:
    """Result of one account scan."""

    account_id: str
    regions: list[str]
    checks: list[str]
    findings: list[Finding]
    errors: list[ScanError]

    def summary(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def breached(self, threshold: Severity | None) -> bool:
        """Return whether any finding is at or above ``threshold``."""
        if threshold is None:
            return False
        minimum = SEVERITY_RANK[threshold]
        return any(SEVERITY_RANK[finding.severity] >= minimum for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "aws-guardrail-scanner",
            "version": __version__,
            "report_version": 1,
            "account_id": self.account_id,
            "regions": list(self.regions),
            "checks": list(self.checks),
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [error.to_dict() for error in self.errors],
            "summary": self.summary(),
        }

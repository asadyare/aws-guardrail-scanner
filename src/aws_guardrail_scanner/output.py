"""Table, JSON, and SARIF renderers."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from aws_guardrail_scanner import __version__
from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.models import SEVERITY_RANK, Finding, ScanReport, Severity

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.1",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}
INFORMATION_URI = "https://github.com/asadyare/aws-guardrail-scanner"


def render(report: ScanReport, fmt: str, checks: list[Check] | None = None) -> str:
    """Render a report as ``table``, ``json``, or ``sarif``."""
    if fmt == "json":
        return to_json(report)
    if fmt == "sarif":
        return to_sarif(report, checks or [])
    if fmt == "table":
        return to_table(report)
    raise ValueError(f"Unsupported output format: {fmt}")


def to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2) + "\n"


def to_table(report: ScanReport) -> str:
    lines = [
        f"Account: {report.account_id}",
        f"Regions: {', '.join(report.regions)}",
        f"Checks:  {', '.join(report.checks)}",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
        lines.append("")
    else:
        headers = ("SEVERITY", "CHECK", "REGION", "RESOURCE")
        rows = [
            (finding.severity.value, finding.check_id, finding.region, finding.resource_id)
            for finding in report.findings
        ]
        widths = [len(header) for header in headers]
        for row in rows:
            for index, cell in enumerate(row):
                widths[index] = max(widths[index], len(cell))

        def format_row(row: tuple[str, ...]) -> str:
            return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))

        lines.append(format_row(headers))
        lines.append(format_row(tuple("-" * width for width in widths)))
        for row in rows:
            lines.append(format_row(row))
        lines.append("")
        for finding in report.findings:
            lines.extend(_finding_block(finding))
    summary = report.summary()
    parts = [f"{name}={summary[name]}" for name in ("critical", "high", "medium", "low", "info")]
    lines.append("Summary: " + ", ".join(parts))
    if report.errors:
        lines.append(f"Errors: {len(report.errors)} (details on stderr)")
    return "\n".join(lines) + "\n"


def render_catalogue(checks: list[Check]) -> str:
    """Render the check catalogue for ``--list-checks``."""
    headers = ("ID", "SEVERITY", "TITLE")
    rows = [(check.id, check.severity, check.title) for check in checks]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def format_row(row: tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))

    lines = [format_row(headers), format_row(tuple("-" * width for width in widths))]
    lines.extend(format_row(row) for row in rows)
    lines.append("")
    for check in checks:
        lines.append(f"{check.id}: {check.description}")
        lines.append("")
    return "\n".join(lines)


def to_sarif(report: ScanReport, checks: list[Check]) -> str:
    """Render SARIF 2.1.0 for GitHub code scanning.

    Locations are logical plus a relative artefact URI. They do not point at
    source files, because the findings are cloud resources.
    """
    rules = [_rule(check, report.findings) for check in checks]
    results = [_result(report.account_id, finding) for finding in report.findings]
    notifications = [
        {
            "descriptor": {"id": "scan-error"},
            "message": {
                "text": (
                    f"{error.check_id}: {error.message}"
                    if error.resource_id is None
                    else f"{error.check_id} ({error.resource_id}): {error.message}"
                )
            },
            "level": "error",
        }
        for error in report.errors
    ]
    document: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aws-guardrail-scanner",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not report.errors,
                        "toolExecutionNotifications": notifications,
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _finding_block(finding: Finding) -> list[str]:
    return [
        f"[{finding.severity.value}] {finding.title}",
        f"  Resource:    {finding.resource_id}",
        f"  Region:      {finding.region}",
        f"  Description: {finding.description}",
        f"  Remediation: {finding.remediation}",
        f"  Reference:   {finding.reference}",
        "",
    ]


def _rule(check: Check, findings: list[Finding]) -> dict[str, Any]:
    severities = [finding.severity for finding in findings if finding.check_id == check.id]
    highest = max(severities, key=lambda item: SEVERITY_RANK[item], default=Severity.MEDIUM)
    return {
        "id": check.id,
        "name": check.title,
        "shortDescription": {"text": check.title},
        "fullDescription": {"text": check.description},
        "help": {
            "text": check.description,
            "markdown": f"**{check.title}**\n\n{check.description}",
        },
        "defaultConfiguration": {"level": SARIF_LEVEL[highest]},
        "properties": {
            "security-severity": SECURITY_SEVERITY[highest],
            "tags": ["security", "aws"],
        },
    }


def _result(account_id: str, finding: Finding) -> dict[str, Any]:
    uri = sarif_uri(finding.resource_id)
    fingerprint = hashlib.sha256(
        f"{account_id}|{finding.check_id}|{finding.region}|{finding.resource_id}".encode()
    ).hexdigest()
    return {
        "ruleId": finding.check_id,
        "level": SARIF_LEVEL[finding.severity],
        "message": {
            "text": (
                f"{finding.title}. {finding.description} Remediation: {finding.remediation} "
                f"Reference: {finding.reference}"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1, "startColumn": 1},
                },
                "logicalLocations": [
                    {
                        "name": finding.resource_id,
                        "fullyQualifiedName": finding.resource_id,
                        "kind": "resource",
                    }
                ],
            }
        ],
        "properties": {
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "severity": finding.severity.value,
            "region": finding.region,
            "resourceId": finding.resource_id,
        },
        "partialFingerprints": {"awsResource/v1": fingerprint},
    }


def sarif_uri(resource_id: str) -> str:
    """Turn an ARN into a relative URI GitHub code scanning will accept."""
    text = resource_id.replace("arn:aws:", "aws/")
    text = text.replace(":::", "/").replace(":", "/").replace(" ", "_")
    while "//" in text:
        text = text.replace("//", "/")
    return text

"""Run a selected set of checks."""

from __future__ import annotations

import logging

from botocore.exceptions import BotoCoreError, ClientError

from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import SEVERITY_RANK, Finding, ScanReport

logger = logging.getLogger(__name__)


def run_scan(ctx: ScanContext, checks: list[Check]) -> ScanReport:
    """Run each check. A failed AWS read is recorded and the scan continues."""
    findings: list[Finding] = []
    for check in checks:
        logger.info("Running %s", check.id)
        try:
            found = check.run(ctx)
        except (ClientError, BotoCoreError) as exc:
            ctx.add_error(check.id, str(exc))
            logger.info("%s failed: %s", check.id, exc)
            continue
        findings.extend(found)
        logger.info("%s produced %d finding(s)", check.id, len(found))

    findings.sort(
        key=lambda finding: (
            -SEVERITY_RANK[finding.severity],
            finding.check_id,
            finding.region,
            finding.resource_id,
        )
    )
    return ScanReport(
        account_id=ctx.account_id,
        regions=list(ctx.regions),
        checks=[check.id for check in checks],
        findings=findings,
        errors=list(ctx.errors),
    )

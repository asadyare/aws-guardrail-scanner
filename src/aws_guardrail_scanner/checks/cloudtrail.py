"""CloudTrail multi-Region logging check."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_guardrail_scanner.awsutil import session_client
from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Finding, Severity

CLOUDTRAIL_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 control 3.1; "
    "AWS Foundational Security Best Practices CloudTrail.1. "
    "Log file validation (CIS 3.2) and the access logging of the log bucket "
    "(CIS 3.4) are not checked"
)


def _equals(field: Mapping[str, Any]) -> set[str]:
    raw = field.get("Equals", [])
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {item for item in raw if isinstance(item, str)}
    return set()


def includes_read_write_management(selectors: Mapping[str, Any]) -> bool:
    """Return whether selectors record both read and write management events.

    Empty selectors do not pass. A trail's API response includes the defaults
    AWS applied, so an empty body means this scanner could not confirm them.
    """
    basic = selectors.get("EventSelectors")
    if isinstance(basic, list):
        for selector in basic:
            if not isinstance(selector, Mapping):
                continue
            read_write = selector.get("ReadWriteType", "All")
            if selector.get("IncludeManagementEvents") and read_write == "All":
                return True

    advanced = selectors.get("AdvancedEventSelectors")
    if isinstance(advanced, list):
        for selector in advanced:
            if not isinstance(selector, Mapping):
                continue
            fields = selector.get("FieldSelectors")
            if not isinstance(fields, list):
                continue
            categories: set[str] = set()
            read_only: set[str] | None = None
            for field in fields:
                if not isinstance(field, Mapping):
                    continue
                if field.get("Field") == "eventCategory":
                    categories.update(_equals(field))
                elif field.get("Field") == "readOnly":
                    read_only = {value.lower() for value in _equals(field)}
            if "Management" not in categories:
                continue
            if read_only is None or read_only == {"true", "false"} or read_only == set():
                return True
    return False


def trail_gaps(
    trail: Mapping[str, Any],
    status: Mapping[str, Any],
    selectors: Mapping[str, Any],
) -> list[str]:
    """Return why a trail does not satisfy the multi-Region logging control.

    An empty list means the trail passes.
    """
    gaps: list[str] = []
    if not trail.get("IsMultiRegionTrail"):
        gaps.append("is not multi-Region")
    if not status.get("IsLogging"):
        gaps.append("is not logging")
    if trail.get("IncludeGlobalServiceEvents") is False:
        gaps.append("does not include global service events")
    if not includes_read_write_management(selectors):
        gaps.append("does not record read and write management events")
    return gaps


class CloudTrailMultiRegionCheck(Check):
    id = "cloudtrail-multi-region"
    title = "CloudTrail is not logging as a multi-Region trail"
    description = (
        "The account should have at least one multi-Region trail that is logging, "
        "includes global service events, and records read and write management events. "
        "Shadow trails are visible from the first requested Region, so the check runs once."
    )
    severity = "high"

    def run(self, ctx: ScanContext) -> list[Finding]:
        region = ctx.regions[0]
        client = session_client(ctx.session, "cloudtrail", region)
        try:
            response = client.describe_trails()
        except (ClientError, BotoCoreError) as exc:
            ctx.add_error(self.id, f"Could not describe trails: {exc}")
            return []
        raw = response.get("trailList", [])
        trails = (
            [trail for trail in raw if isinstance(trail, dict)] if isinstance(raw, list) else []
        )
        if not trails:
            return [_finding(ctx, "No CloudTrail trails were returned.")]

        reasons: list[str] = []
        for trail in trails:
            raw_name = trail.get("Name")
            name = raw_name if isinstance(raw_name, str) else "unnamed"
            raw_arn = trail.get("TrailARN")
            arn = raw_arn if isinstance(raw_arn, str) else name
            raw_home = trail.get("HomeRegion")
            home = raw_home if isinstance(raw_home, str) else region
            status, selectors = _trail_details(ctx, home, arn)
            if status is None or selectors is None:
                reasons.append(f"{name}: details could not be read")
                continue
            gaps = trail_gaps(trail, status, selectors)
            if not gaps:
                return []
            reasons.append(f"{name}: " + ", ".join(gaps))

        shown = reasons[:10]
        extra = len(reasons) - len(shown)
        detail = " ".join(shown)
        if extra > 0:
            detail = f"{detail} and {extra} more trail(s)."
        description = (
            "No trail is multi-Region, logging, including global service events, and "
            f"recording read and write management events. {detail}"
        )
        return [_finding(ctx, description)]


def _trail_details(
    ctx: ScanContext,
    home_region: str,
    trail_arn: str,
) -> tuple[Mapping[str, Any] | None, Mapping[str, Any] | None]:
    client = session_client(ctx.session, "cloudtrail", home_region)
    try:
        status = client.get_trail_status(Name=trail_arn)
    except (ClientError, BotoCoreError) as exc:
        ctx.add_error(
            CloudTrailMultiRegionCheck.id,
            f"Could not read trail status: {exc}",
            trail_arn,
        )
        return None, None
    try:
        selectors = client.get_event_selectors(TrailName=trail_arn)
    except (ClientError, BotoCoreError) as exc:
        ctx.add_error(
            CloudTrailMultiRegionCheck.id,
            f"Could not read event selectors: {exc}",
            trail_arn,
        )
        return status, None
    return status, selectors


def _finding(ctx: ScanContext, description: str) -> Finding:
    return Finding(
        check_id=CloudTrailMultiRegionCheck.id,
        title=CloudTrailMultiRegionCheck.title,
        severity=Severity.HIGH,
        resource_id=f"arn:aws:cloudtrail::{ctx.account_id}:account",
        region="global",
        description=description,
        remediation=(
            "Create one multi-Region trail, or convert an existing trail, and start "
            "logging. Include global service events and both read and write management "
            "events. Send the logs to a dedicated bucket that this account cannot "
            "rewrite, in a separate log-archive account where you have one."
        ),
        reference=CLOUDTRAIL_REFERENCE,
    )

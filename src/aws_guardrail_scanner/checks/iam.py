"""IAM credential checks: MFA, root keys, and access key age."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_guardrail_scanner.awsutil import aws_error_code, session_client
from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Finding, Severity

ACCESS_KEY_MAX_AGE = timedelta(days=90)
NO_SUCH_ENTITY = "NoSuchEntity"

IAM_USER_MFA_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 control 1.10; "
    "AWS Foundational Security Best Practices IAM.5"
)
IAM_ROOT_KEYS_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 control 1.4; "
    "AWS Foundational Security Best Practices IAM.4"
)
IAM_ROOT_MFA_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 control 1.5; "
    "AWS Foundational Security Best Practices IAM.9. "
    "This check does not evaluate IAM.6 (hardware MFA for root): "
    "GetAccountSummary only reports whether any MFA device is present"
)
IAM_KEY_AGE_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 control 1.14; "
    "AWS Foundational Security Best Practices IAM.3. "
    "Age is measured from CreateDate, which is what those controls use"
)


def access_key_severity(status: str, create_date: datetime, now: datetime) -> Severity | None:
    """Return a severity when a key is older than 90 days, else ``None``.

    A key that is exactly 90 days old still meets "rotated every 90 days or less".
    """
    created = create_date if create_date.tzinfo is not None else create_date.replace(tzinfo=UTC)
    current = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
    if current - created <= ACCESS_KEY_MAX_AGE:
        return None
    if status == "Inactive":
        return Severity.LOW
    return Severity.MEDIUM


def root_access_key_finding(summary: Mapping[str, int], account_id: str) -> Finding | None:
    """Return a finding when the account summary says root has access keys."""
    present = summary.get("AccountAccessKeysPresent")
    if present is None or present <= 0:
        return None
    return Finding(
        check_id=IamRootAccessKeysCheck.id,
        title=IamRootAccessKeysCheck.title,
        severity=Severity.CRITICAL,
        resource_id=f"arn:aws:iam::{account_id}:root",
        region="global",
        description=(
            "GetAccountSummary reports AccountAccessKeysPresent greater than zero. "
            "Root access keys bypass IAM, cannot be scoped, and are a common persistence path."
        ),
        remediation=(
            "Sign in as root, delete the access keys, and confirm AccountAccessKeysPresent "
            "returns to zero. Use an IAM role with short-lived credentials for administration. "
            "There is no safe reason to keep a root key for automation."
        ),
        reference=IAM_ROOT_KEYS_REFERENCE,
    )


def root_mfa_finding(summary: Mapping[str, int], account_id: str) -> Finding | None:
    """Return a finding when the account summary says root MFA is off."""
    enabled = summary.get("AccountMFAEnabled")
    if enabled is None or enabled > 0:
        return None
    return Finding(
        check_id=IamRootMfaCheck.id,
        title=IamRootMfaCheck.title,
        severity=Severity.CRITICAL,
        resource_id=f"arn:aws:iam::{account_id}:root",
        region="global",
        description=(
            "GetAccountSummary reports AccountMFAEnabled as zero. Root has no MFA device. "
            "The summary does not say whether a device is virtual or hardware, so this "
            "matches CIS 1.5 and FSBP IAM.9, not the hardware-only IAM.6 control."
        ),
        remediation=(
            "Sign in as root and register an MFA device. A hardware key is the stronger "
            "choice (CIS 1.6 / FSBP IAM.6) but any MFA is an immediate improvement. "
            "Store the root password in a break-glass vault, not in a pipeline."
        ),
        reference=IAM_ROOT_MFA_REFERENCE,
    )


def _summary(ctx: ScanContext) -> dict[str, int] | None:
    def load() -> dict[str, int] | None:
        client = session_client(ctx.session, "iam", "us-east-1")
        try:
            response = client.get_account_summary()
        except (ClientError, BotoCoreError) as exc:
            ctx.add_error("iam-account-summary", f"Could not read the IAM account summary: {exc}")
            return None
        raw = response.get("SummaryMap", {})
        if not isinstance(raw, Mapping):
            return {}
        parsed: dict[str, int] = {}
        for key, value in raw.items():
            if isinstance(key, str) and isinstance(value, int):
                parsed[key] = value
        return parsed

    return ctx.remember("iam-account-summary", load)


def _iam_client(ctx: ScanContext) -> Any:
    return session_client(ctx.session, "iam", "us-east-1")


def _paginate(client: Any, method: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
    paginator = client.get_paginator(method)
    items: list[dict[str, Any]] = []
    for page in paginator.paginate(**kwargs):
        raw = page.get(result_key, [])
        if isinstance(raw, list):
            items.extend(item for item in raw if isinstance(item, dict))
    return items


class IamUserMfaCheck(Check):
    id = "iam-user-mfa"
    title = "IAM user with a console password has no MFA"
    description = (
        "IAM users who can sign in to the console should have at least one MFA device. "
        "Users without a login profile are not reported; they have no console password."
    )
    severity = "high"

    def run(self, ctx: ScanContext) -> list[Finding]:
        client = _iam_client(ctx)
        try:
            users = _paginate(client, "list_users", "Users")
        except (ClientError, BotoCoreError) as exc:
            ctx.add_error(self.id, f"Could not list IAM users: {exc}")
            return []
        findings: list[Finding] = []
        for user in users:
            user_name = user.get("UserName")
            user_arn = user.get("Arn")
            if not isinstance(user_name, str) or not isinstance(user_arn, str):
                continue
            if not _has_console_password(ctx, client, user_name, user_arn):
                continue
            if _has_mfa(ctx, client, user_name, user_arn) is not False:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.HIGH,
                    resource_id=user_arn,
                    region="global",
                    description=(
                        f"{user_name} has a console password and no MFA device. "
                        "A phished or reused password is then enough to open the console."
                    ),
                    remediation=(
                        "Register a virtual or hardware MFA device for this user before the "
                        "next console sign-in. If the user does not need the console, delete "
                        "the login profile instead of adding MFA to an unused password."
                    ),
                    reference=IAM_USER_MFA_REFERENCE,
                )
            )
        return findings


def _has_console_password(ctx: ScanContext, client: Any, user_name: str, user_arn: str) -> bool:
    try:
        client.get_login_profile(UserName=user_name)
    except ClientError as exc:
        if aws_error_code(exc) == NO_SUCH_ENTITY:
            return False
        ctx.add_error(IamUserMfaCheck.id, f"Could not read the login profile: {exc}", user_arn)
        return False
    except BotoCoreError as exc:
        ctx.add_error(IamUserMfaCheck.id, f"Could not read the login profile: {exc}", user_arn)
        return False
    return True


def _has_mfa(ctx: ScanContext, client: Any, user_name: str, user_arn: str) -> bool | None:
    """Return True/False, or None when the read failed."""
    try:
        devices = _paginate(client, "list_mfa_devices", "MFADevices", UserName=user_name)
    except (ClientError, BotoCoreError) as exc:
        ctx.add_error(IamUserMfaCheck.id, f"Could not list MFA devices: {exc}", user_arn)
        return None
    return len(devices) > 0


class IamRootAccessKeysCheck(Check):
    id = "iam-root-access-keys"
    title = "Root account has access keys"
    description = "The root user should not have access keys."
    severity = "critical"

    def run(self, ctx: ScanContext) -> list[Finding]:
        summary = _summary(ctx)
        if summary is None:
            return []
        if "AccountAccessKeysPresent" not in summary:
            ctx.add_error(self.id, "Account summary did not include AccountAccessKeysPresent.")
            return []
        finding = root_access_key_finding(summary, ctx.account_id)
        return [finding] if finding else []


class IamRootMfaCheck(Check):
    id = "iam-root-mfa"
    title = "Root account has no MFA"
    description = (
        "The root user should have MFA enabled. Hardware versus virtual MFA is not "
        "distinguished, because the account summary does not include the device type."
    )
    severity = "critical"

    def run(self, ctx: ScanContext) -> list[Finding]:
        summary = _summary(ctx)
        if summary is None:
            return []
        if "AccountMFAEnabled" not in summary:
            ctx.add_error(self.id, "Account summary did not include AccountMFAEnabled.")
            return []
        finding = root_mfa_finding(summary, ctx.account_id)
        return [finding] if finding else []


class IamAccessKeyAgeCheck(Check):
    id = "iam-access-key-age"
    title = "IAM access key is older than 90 days"
    description = (
        "Active access keys should be rotated at least every 90 days. Inactive keys "
        "older than that are rated low: they cannot be used, but they should be deleted."
    )
    severity = "medium"

    def run(self, ctx: ScanContext) -> list[Finding]:
        client = _iam_client(ctx)
        try:
            users = _paginate(client, "list_users", "Users")
        except (ClientError, BotoCoreError) as exc:
            ctx.add_error(self.id, f"Could not list IAM users: {exc}")
            return []
        findings: list[Finding] = []
        for user in users:
            user_name = user.get("UserName")
            user_arn = user.get("Arn")
            if not isinstance(user_name, str) or not isinstance(user_arn, str):
                continue
            try:
                keys = _paginate(
                    client, "list_access_keys", "AccessKeyMetadata", UserName=user_name
                )
            except (ClientError, BotoCoreError) as exc:
                ctx.add_error(self.id, f"Could not list access keys: {exc}", user_arn)
                continue
            for key in keys:
                finding = _key_finding(ctx, user_name, user_arn, key)
                if finding is not None:
                    findings.append(finding)
        return findings


def _key_finding(
    ctx: ScanContext,
    user_name: str,
    user_arn: str,
    key: Mapping[str, Any],
) -> Finding | None:
    key_id = key.get("AccessKeyId")
    status = key.get("Status")
    created = key.get("CreateDate")
    if (
        not isinstance(key_id, str)
        or not isinstance(status, str)
        or not isinstance(created, datetime)
    ):
        ctx.add_error(
            IamAccessKeyAgeCheck.id,
            "Access key metadata was missing an id, status, or creation time.",
            user_arn,
        )
        return None
    severity = access_key_severity(status, created, ctx.now)
    if severity is None:
        return None
    created_utc = created if created.tzinfo is not None else created.replace(tzinfo=UTC)
    current = ctx.now if ctx.now.tzinfo is not None else ctx.now.replace(tzinfo=UTC)
    age_days = (current - created_utc).days
    if severity is Severity.LOW:
        action = "The key is inactive. Delete it so an old credential is not left in the account."
    else:
        action = (
            "The key is active. Create a new key, update the workload, then disable and "
            "delete this one."
        )
    return Finding(
        check_id=IamAccessKeyAgeCheck.id,
        title=IamAccessKeyAgeCheck.title,
        severity=severity,
        resource_id=f"{user_arn}/access-key/{key_id}",
        region="global",
        description=(
            f"Access key {key_id} for {user_name} was created on "
            f"{created_utc.date().isoformat()} ({age_days} days ago) and is {status.lower()}."
        ),
        remediation=action,
        reference=IAM_KEY_AGE_REFERENCE,
    )

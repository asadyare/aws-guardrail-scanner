"""IAM checks against moto, plus a patched account summary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.client import BaseClient

from aws_guardrail_scanner.checks.iam import (
    IamAccessKeyAgeCheck,
    IamRootAccessKeysCheck,
    IamRootMfaCheck,
    IamUserMfaCheck,
)
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Severity


def test_console_user_without_mfa_is_reported_and_others_are_not(ctx: ScanContext) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="console")
    iam.create_login_profile(UserName="console", Password="Not-a-real-password-1")
    iam.create_user(UserName="service")
    iam.create_access_key(UserName="service")
    iam.create_user(UserName="protected")
    iam.create_login_profile(UserName="protected", Password="Not-a-real-password-2")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="phone")["VirtualMFADevice"][
        "SerialNumber"
    ]
    iam.enable_mfa_device(
        UserName="protected",
        SerialNumber=serial,
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    findings = IamUserMfaCheck().run(ctx)
    assert [finding.resource_id for finding in findings] == [
        f"arn:aws:iam::{ctx.account_id}:user/console"
    ]
    assert findings[0].severity is Severity.HIGH
    assert "1.10" in findings[0].reference


def test_access_key_age_uses_the_injected_clock(ctx: ScanContext) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    active = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    iam.create_user(UserName="bob")
    inactive = iam.create_access_key(UserName="bob")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="bob", AccessKeyId=inactive, Status="Inactive")

    assert IamAccessKeyAgeCheck().run(ctx) == []

    ctx.now = datetime.now(UTC) + timedelta(days=120)
    findings = {finding.resource_id: finding for finding in IamAccessKeyAgeCheck().run(ctx)}
    assert (
        findings[f"arn:aws:iam::{ctx.account_id}:user/alice/access-key/{active}"].severity
        is Severity.MEDIUM
    )
    assert (
        findings[f"arn:aws:iam::{ctx.account_id}:user/bob/access-key/{inactive}"].severity
        is Severity.LOW
    )
    assert (
        "1.14"
        in findings[f"arn:aws:iam::{ctx.account_id}:user/alice/access-key/{active}"].reference
    )


def test_root_checks_follow_the_account_summary(
    ctx: ScanContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = BaseClient._make_api_call

    def fake(self: BaseClient, operation_name: str, api_params: dict[str, object]) -> object:
        result = real(self, operation_name, api_params)
        if operation_name == "GetAccountSummary" and isinstance(result, dict):
            summary = dict(result.get("SummaryMap", {}))
            summary["AccountAccessKeysPresent"] = 2
            summary["AccountMFAEnabled"] = 0
            result = dict(result)
            result["SummaryMap"] = summary
        return result

    monkeypatch.setattr(BaseClient, "_make_api_call", fake)
    keys = IamRootAccessKeysCheck().run(ctx)
    mfa = IamRootMfaCheck().run(ctx)
    assert len(keys) == 1
    assert keys[0].severity is Severity.CRITICAL
    assert "IAM.4" in keys[0].reference
    assert len(mfa) == 1
    assert mfa[0].resource_id == f"arn:aws:iam::{ctx.account_id}:root"


def test_fresh_account_has_root_mfa_gap_and_no_root_keys(ctx: ScanContext) -> None:
    assert IamRootAccessKeysCheck().run(ctx) == []
    mfa = IamRootMfaCheck().run(ctx)
    assert len(mfa) == 1
    assert mfa[0].severity is Severity.CRITICAL

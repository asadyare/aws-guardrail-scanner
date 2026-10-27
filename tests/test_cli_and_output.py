"""CLI, report rendering, and the runner."""

from __future__ import annotations

import json

import boto3
import pytest
from botocore.exceptions import ClientError, ProfileNotFound

from aws_guardrail_scanner import __version__
from aws_guardrail_scanner.checks import UnknownCheckError, all_checks, select_checks
from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.checks.ebs import EbsDefaultEncryptionCheck
from aws_guardrail_scanner.cli import collect_regions, main
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Severity
from aws_guardrail_scanner.output import render, sarif_uri, to_sarif, to_table
from aws_guardrail_scanner.runner import run_scan


def test_catalogue_prefixes_and_duplicates() -> None:
    assert len(select_checks([])) == len(all_checks())
    s3 = {check.id for check in select_checks(["s3"])}
    assert s3 == {check.id for check in all_checks() if check.id.startswith("s3-")}
    assert {check.id for check in select_checks(["ec2-sg"])} == {
        "ec2-sg-ssh-open",
        "ec2-sg-rdp-open",
        "ec2-sg-all-ports-open",
    }
    assert [check.id for check in select_checks(["s3-public-acl", "s3-public-acl"])] == [
        "s3-public-acl"
    ]
    with pytest.raises(UnknownCheckError):
        select_checks(["not-a-check"])
    ids = [check.id for check in all_checks()]
    assert len(ids) == len(set(ids))
    assert all(check.title and check.description and check.severity for check in all_checks())


def test_region_collection() -> None:
    assert collect_regions(["eu-west-1", "eu-west-1,eu-west-2"], "eu-west-2,us-east-1") == [
        "eu-west-1",
        "eu-west-2",
        "us-east-1",
    ]
    with pytest.raises(ValueError):
        collect_regions(["eu-west-1,"], None)


def test_list_checks_does_not_need_aws(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-checks"]) == 0
    output = capsys.readouterr().out
    for check in all_checks():
        assert check.id in output


def test_help_and_bad_input(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0
    assert main(["--region", "eu-west-1", "--checks", "nope"]) == 2
    assert "Unknown check" in capsys.readouterr().err
    assert main(["--region", ","]) == 2


def test_profile_not_found(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(**_kwargs: object) -> object:
        raise ProfileNotFound(profile="nope")

    monkeypatch.setattr("aws_guardrail_scanner.cli.boto3.Session", boom)
    assert main(["--profile", "nope", "--region", "eu-west-1"]) == 2
    assert "profile" in capsys.readouterr().err.lower()


def test_default_region_is_used_when_the_session_has_one(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class SessionWithRegion:
        def __init__(self, **_kwargs: object) -> None:
            self.region_name = "eu-west-2"

        def client(self, *_args: object, **_kwargs: object) -> object:
            raise ClientError(
                {"Error": {"Code": "ExpiredToken", "Message": "expired"}},
                "GetCallerIdentity",
            )

    monkeypatch.setattr("aws_guardrail_scanner.cli.boto3.Session", SessionWithRegion)
    assert main([]) == 2
    assert "could not determine the AWS account" in capsys.readouterr().err


def test_missing_region_and_profile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class EmptySession:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs
            self.region_name = None

        def client(self, *_args: object, **_kwargs: object) -> object:
            raise ClientError(
                {"Error": {"Code": "ExpiredToken", "Message": "expired"}},
                "GetCallerIdentity",
            )

    monkeypatch.setattr("aws_guardrail_scanner.cli.boto3.Session", EmptySession)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    assert main([]) == 2
    assert "No Region configured" in capsys.readouterr().err

    seen: dict[str, object] = {}

    class RecordingSession(EmptySession):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)
            seen.update(kwargs)
            self.region_name = "eu-west-1"

    monkeypatch.setattr("aws_guardrail_scanner.cli.boto3.Session", RecordingSession)
    assert main(["--profile", "dev", "--region", "eu-west-1"]) == 2
    assert seen["profile_name"] == "dev"
    assert "could not determine the AWS account" in capsys.readouterr().err


def test_cli_json_sarif_and_fail_on(ctx: ScanContext, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "--region",
            "us-east-1",
            "--checks",
            "ec2-ebs-default-encryption",
            "--output",
            "json",
            "--fail-on",
            "medium",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 1
    assert payload["version"] == __version__
    assert payload["findings"][0]["check_id"] == "ec2-ebs-default-encryption"
    assert "finding(s)" in captured.err

    boto3.client("ec2", region_name="us-east-1").enable_ebs_encryption_by_default()
    assert (
        main(
            [
                "--region",
                "us-east-1",
                "--checks",
                "ec2-ebs-default-encryption",
                "--output",
                "table",
                "--fail-on",
                "high",
            ]
        )
        == 0
    )
    assert "No findings." in capsys.readouterr().out

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="hygiene")
    low = main(
        [
            "--region",
            "us-east-1",
            "--regions",
            "us-east-1",
            "--checks",
            "s3-default-encryption",
            "--output",
            "sarif",
            "--fail-on",
            "high",
        ]
    )
    sarif_out = capsys.readouterr().out
    assert low == 0
    document = json.loads(sarif_out)
    assert document["version"] == "2.1.0"
    result = document["runs"][0]["results"][0]
    assert result["ruleId"] == "s3-default-encryption"
    assert result["level"] == "note"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert not result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "arn:"
    )
    assert result["properties"]["security-severity"] == "2.0"
    rule_ids = {rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]}
    assert "s3-default-encryption" in rule_ids


def test_table_orders_critical_before_low(ctx: ScanContext) -> None:
    report = run_scan(
        ctx,
        [
            check
            for check in all_checks()
            if check.id in {"iam-root-mfa", "ec2-ebs-default-encryption"}
        ],
    )
    assert [finding.severity for finding in report.findings] == [Severity.CRITICAL, Severity.MEDIUM]
    text = to_table(report)
    assert text.index("iam-root-mfa") < text.index("ec2-ebs-default-encryption")
    rendered = render(report, "json")
    assert json.loads(rendered)["summary"]["critical"] == 1


def test_sarif_uri_and_runner_records_client_errors(ctx: ScanContext) -> None:
    assert sarif_uri("arn:aws:s3:::my bucket") == "aws/s3/my_bucket"
    assert sarif_uri("arn:aws:iam::123:user/alice") == "aws/iam/123/user/alice"

    class Boom(Check):
        id = "boom"
        title = "Boom"
        description = "Always fails the AWS call."
        severity = "high"

        def run(self, _ctx: ScanContext) -> list[object]:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no"}}, "DescribeTrails"
            )

    report = run_scan(ctx, [EbsDefaultEncryptionCheck(), Boom()])
    assert any(error.check_id == "boom" for error in report.errors)
    assert any(finding.check_id == "ec2-ebs-default-encryption" for finding in report.findings)
    assert report.breached(None) is False
    assert "Errors: 1" in to_table(report)
    sarif = json.loads(to_sarif(report, [EbsDefaultEncryptionCheck(), Boom()]))
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    with pytest.raises(ValueError):
        render(report, "xml")

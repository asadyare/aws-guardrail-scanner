"""S3 checks against moto."""

from __future__ import annotations

import json

import boto3

from aws_guardrail_scanner.checks.s3 import (
    S3AccountBlockPublicAccessCheck,
    S3BucketBlockPublicAccessCheck,
    S3DefaultEncryptionCheck,
    S3PublicAclCheck,
    S3PublicPolicyCheck,
)
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Severity

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _s3_client() -> boto3.client:
    return boto3.client("s3", region_name="us-east-1")


def test_fresh_account_has_no_bucket_findings_and_flags_account_block(ctx: ScanContext) -> None:
    assert S3BucketBlockPublicAccessCheck().run(ctx) == []
    assert S3PublicAclCheck().run(ctx) == []
    assert S3DefaultEncryptionCheck().run(ctx) == []
    account = S3AccountBlockPublicAccessCheck().run(ctx)
    assert len(account) == 1
    assert account[0].severity is Severity.MEDIUM
    assert "S3.1" in account[0].reference


def test_bucket_without_guardrails_is_high_and_encryption_is_low(ctx: ScanContext) -> None:
    _s3_client().create_bucket(Bucket="open-bucket")
    block = S3BucketBlockPublicAccessCheck().run(ctx)
    assert len(block) == 1
    assert block[0].severity is Severity.HIGH
    assert block[0].region == "us-east-1"
    assert block[0].resource_id == "arn:aws:s3:::open-bucket"

    encryption = S3DefaultEncryptionCheck().run(ctx)
    assert len(encryption) == 1
    assert encryption[0].severity is Severity.LOW
    assert "20 September 2023" in encryption[0].reference


def test_account_block_lowers_bucket_findings_and_secure_bucket_is_clean(ctx: ScanContext) -> None:
    s3 = _s3_client()
    s3.create_bucket(Bucket="latent")
    s3.put_bucket_acl(Bucket="latent", ACL="public-read")
    s3.create_bucket(Bucket="locked")
    s3.put_public_access_block(Bucket="locked", PublicAccessBlockConfiguration=FULL_BLOCK)
    s3.put_bucket_encryption(
        Bucket="locked",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        },
    )
    boto3.client("s3control", region_name="us-east-1").put_public_access_block(
        AccountId=ctx.account_id,
        PublicAccessBlockConfiguration=FULL_BLOCK,
    )

    assert S3AccountBlockPublicAccessCheck().run(ctx) == []
    bucket = S3BucketBlockPublicAccessCheck().run(ctx)
    assert [finding.resource_id for finding in bucket] == ["arn:aws:s3:::latent"]
    assert bucket[0].severity is Severity.LOW

    acl = S3PublicAclCheck().run(ctx)
    assert len(acl) == 1
    assert acl[0].severity is Severity.LOW
    assert "not currently effective" in acl[0].description

    encryption = S3DefaultEncryptionCheck().run(ctx)
    assert [finding.resource_id for finding in encryption] == ["arn:aws:s3:::latent"]


def test_public_acl_and_policy_are_critical_when_not_blocked(ctx: ScanContext) -> None:
    s3 = _s3_client()
    s3.create_bucket(Bucket="published")
    s3.put_bucket_acl(Bucket="published", ACL="public-read")
    s3.put_bucket_policy(
        Bucket="published",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::published/*",
                    }
                ],
            }
        ),
    )
    acl = S3PublicAclCheck().run(ctx)
    assert len(acl) == 1
    assert acl[0].severity is Severity.CRITICAL
    policy = S3PublicPolicyCheck().run(ctx)
    assert len(policy) == 1
    assert policy[0].severity is Severity.CRITICAL
    assert "S3.2" in policy[0].reference


def test_bucket_in_another_region_is_labelled_with_that_region(ctx: ScanContext) -> None:
    boto3.client("s3", region_name="eu-west-1").create_bucket(
        Bucket="eu-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
    )
    findings = S3DefaultEncryptionCheck().run(ctx)
    assert findings[0].region == "eu-west-1"
    assert findings[0].resource_id == "arn:aws:s3:::eu-bucket"


def test_restrict_public_buckets_lowers_a_public_policy(ctx: ScanContext) -> None:
    s3 = _s3_client()
    s3.create_bucket(Bucket="policy-only")
    s3.put_bucket_policy(
        Bucket="policy-only",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::policy-only/*",
                    }
                ],
            }
        ),
    )
    s3.put_public_access_block(
        Bucket="policy-only",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
    )
    policy = S3PublicPolicyCheck().run(ctx)
    assert len(policy) == 1
    assert policy[0].severity is Severity.LOW

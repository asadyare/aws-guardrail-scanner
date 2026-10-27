"""Decision helpers that do not need AWS."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aws_guardrail_scanner.awsutil import bucket_region_from_constraint
from aws_guardrail_scanner.checks.cloudtrail import includes_read_write_management, trail_gaps
from aws_guardrail_scanner.checks.iam import (
    access_key_severity,
    root_access_key_finding,
    root_mfa_finding,
)
from aws_guardrail_scanner.checks.s3 import (
    acl_severity,
    encryption_algorithm,
    missing_bpa_flags,
    policy_severity,
    public_acl_permissions,
)
from aws_guardrail_scanner.checks.security_groups import opens_all_ports, opens_port, world_cidrs
from aws_guardrail_scanner.models import Severity

NOW = datetime(2026, 10, 27, tzinfo=UTC)


def test_bucket_region_mapping() -> None:
    assert bucket_region_from_constraint(None) == "us-east-1"
    assert bucket_region_from_constraint("") == "us-east-1"
    assert bucket_region_from_constraint("EU") == "eu-west-1"
    assert bucket_region_from_constraint("eu-west-2") == "eu-west-2"
    assert bucket_region_from_constraint(12) == "us-east-1"


def test_block_public_access_flags() -> None:
    assert missing_bpa_flags(None) == [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ]
    assert missing_bpa_flags({"BlockPublicAcls": True, "IgnorePublicAcls": True}) == [
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ]
    assert (
        missing_bpa_flags(
            {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        )
        == []
    )


def test_public_acl_permissions_ignore_owner_grants() -> None:
    grants = [
        {"Grantee": {"Type": "CanonicalUser", "ID": "abc"}, "Permission": "FULL_CONTROL"},
        {
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
            "Permission": "READ",
        },
        {
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"},
            "Permission": "WRITE",
        },
        {"Grantee": "not-a-mapping", "Permission": "READ"},
    ]
    assert public_acl_permissions(grants) == ["READ", "WRITE"]


def test_acl_and_policy_severity() -> None:
    assert acl_severity({"READ"}, ignored=False) is Severity.CRITICAL
    assert acl_severity({"READ_ACP"}, ignored=False) is Severity.MEDIUM
    assert acl_severity({"READ"}, ignored=True) is Severity.LOW
    assert acl_severity({"UNKNOWN"}, ignored=False) is Severity.CRITICAL
    assert policy_severity(restricted=False) is Severity.CRITICAL
    assert policy_severity(restricted=True) is Severity.LOW


def test_encryption_algorithm() -> None:
    assert encryption_algorithm([]) is None
    assert (
        encryption_algorithm([{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}])
        == "AES256"
    )
    assert encryption_algorithm([{"BucketKeyEnabled": True}]) is None


def test_access_key_age_boundary() -> None:
    created = NOW - timedelta(days=90)
    assert access_key_severity("Active", created, NOW) is None
    just_over = NOW - timedelta(days=90, seconds=1)
    assert access_key_severity("Active", just_over, NOW) is Severity.MEDIUM
    assert access_key_severity("Inactive", just_over, NOW) is Severity.LOW
    assert access_key_severity("Active", created.replace(tzinfo=None), NOW) is None


def test_root_summary_decisions() -> None:
    assert root_access_key_finding({"AccountAccessKeysPresent": 0}, "123") is None
    assert root_access_key_finding({}, "123") is None
    keys = root_access_key_finding({"AccountAccessKeysPresent": 1}, "123")
    assert keys is not None
    assert keys.severity is Severity.CRITICAL
    assert keys.resource_id == "arn:aws:iam::123:root"

    assert root_mfa_finding({"AccountMFAEnabled": 1}, "123") is None
    assert root_mfa_finding({}, "123") is None
    mfa = root_mfa_finding({"AccountMFAEnabled": 0}, "123")
    assert mfa is not None
    assert "IAM.6" in mfa.reference


def test_world_cidrs_and_ports() -> None:
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 20,
        "ToPort": 25,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "10.0.0.0/8"}],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        "PrefixListIds": [{"PrefixListId": "pl-123"}],
    }
    assert world_cidrs(permission) == ["0.0.0.0/0", "::/0"]
    assert opens_port(permission, 22) is True
    assert opens_port(permission, 80) is False
    assert opens_port({"IpProtocol": "icmp", "FromPort": 22, "ToPort": 22}, 22) is False
    assert opens_all_ports({"IpProtocol": "-1"}) is True
    assert opens_all_ports({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535}) is True
    assert opens_port({"IpProtocol": "-1"}, 3389) is True
    assert world_cidrs({"IpRanges": "nope", "Ipv6Ranges": None}) == []


def test_cloudtrail_selectors_and_gaps() -> None:
    assert includes_read_write_management({}) is False
    assert includes_read_write_management(
        {"EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]}
    )
    assert not includes_read_write_management(
        {"EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "ReadOnly"}]}
    )
    assert includes_read_write_management(
        {
            "AdvancedEventSelectors": [
                {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}
            ]
        }
    )
    assert includes_read_write_management(
        {
            "AdvancedEventSelectors": [
                {
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": "Management"},
                        {"Field": "readOnly", "Equals": ["true", "false"]},
                    ]
                }
            ]
        }
    )
    assert not includes_read_write_management(
        {
            "AdvancedEventSelectors": [
                {
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Data"]},
                        {"Field": "readOnly", "Equals": ["true"]},
                    ]
                }
            ]
        }
    )
    assert not includes_read_write_management(
        {"AdvancedEventSelectors": [{"FieldSelectors": "bad"}]}
    )
    assert not includes_read_write_management({"EventSelectors": ["bad"]})

    compliant = trail_gaps(
        {"IsMultiRegionTrail": True, "IncludeGlobalServiceEvents": True},
        {"IsLogging": True},
        {"EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]},
    )
    assert compliant == []
    gaps = trail_gaps(
        {"IsMultiRegionTrail": False, "IncludeGlobalServiceEvents": False},
        {"IsLogging": False},
        {},
    )
    assert "is not multi-Region" in gaps
    assert "is not logging" in gaps
    assert "does not include global service events" in gaps
    assert "does not record read and write management events" in gaps

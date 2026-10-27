"""Security groups, CloudTrail, and EBS checks against moto."""

from __future__ import annotations

import boto3

from aws_guardrail_scanner.checks.cloudtrail import CloudTrailMultiRegionCheck
from aws_guardrail_scanner.checks.ebs import EbsDefaultEncryptionCheck
from aws_guardrail_scanner.checks.security_groups import (
    DefaultSecurityGroupCheck,
    SecurityGroupAllPortsCheck,
    SecurityGroupRdpCheck,
    SecurityGroupSshCheck,
)
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Severity


def _open_group(region: str, name: str, permission: dict[str, object]) -> str:
    ec2 = boto3.client("ec2", region_name=region)
    vpc_id = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
    group_id = ec2.create_security_group(GroupName=name, Description="test", VpcId=vpc_id)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[permission])
    return group_id


def test_ssh_rdp_and_all_ports(ctx: ScanContext) -> None:
    ssh_id = _open_group(
        "us-east-1",
        "ssh",
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        },
    )
    _open_group(
        "us-east-1",
        "rdp",
        {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        },
    )
    _open_group(
        "us-east-1",
        "wide",
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    )
    _open_group(
        "us-east-1",
        "web",
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        },
    )

    ssh = SecurityGroupSshCheck().run(ctx)
    ssh_ids = {finding.resource_id for finding in ssh}
    assert any(ssh_id in resource for resource in ssh_ids)
    assert all(finding.severity is Severity.HIGH for finding in ssh)
    assert any(
        "tcp port 22" in finding.description and "::/0" in finding.description for finding in ssh
    )
    assert "5.2" in ssh[0].reference

    rdp = SecurityGroupRdpCheck().run(ctx)
    assert any("(rdp)" in finding.description for finding in rdp)
    assert all("(web)" not in finding.description for finding in rdp)

    wide = SecurityGroupAllPortsCheck().run(ctx)
    assert len(wide) == 1
    assert wide[0].severity is Severity.CRITICAL
    assert "EC2.19" in wide[0].reference


def test_security_groups_are_limited_to_the_requested_region(ctx: ScanContext) -> None:
    _open_group(
        "eu-west-1",
        "remote-ssh",
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        },
    )
    findings = SecurityGroupSshCheck().run(ctx)
    assert all(finding.region == "us-east-1" for finding in findings)
    assert all("remote-ssh" not in finding.description for finding in findings)


def test_default_security_group_and_a_cleared_one(ctx: ScanContext) -> None:
    initial = DefaultSecurityGroupCheck().run(ctx)
    assert initial
    assert all(finding.severity is Severity.HIGH for finding in initial)
    assert "5.4" in initial[0].reference

    ec2 = boto3.client("ec2", region_name="us-east-1")
    for group in ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]:
        if group["IpPermissions"]:
            ec2.revoke_security_group_ingress(
                GroupId=group["GroupId"], IpPermissions=group["IpPermissions"]
            )
        if group["IpPermissionsEgress"]:
            ec2.revoke_security_group_egress(
                GroupId=group["GroupId"],
                IpPermissions=group["IpPermissionsEgress"],
            )
    ctx._cache.clear()
    assert DefaultSecurityGroupCheck().run(ctx) == []


def test_missing_cloudtrail_and_a_compliant_trail(ctx: ScanContext) -> None:
    missing = CloudTrailMultiRegionCheck().run(ctx)
    assert len(missing) == 1
    assert missing[0].severity is Severity.HIGH
    assert "No CloudTrail trails" in missing[0].description
    assert "3.1" in missing[0].reference

    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="trail-logs")
    cloudtrail = boto3.client("cloudtrail", region_name="us-east-1")
    created = cloudtrail.create_trail(
        Name="org",
        S3BucketName="trail-logs",
        IsMultiRegionTrail=True,
        IncludeGlobalServiceEvents=True,
    )
    cloudtrail.start_logging(Name="org")
    cloudtrail.put_event_selectors(
        TrailName=created["TrailARN"],
        EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}],
    )
    ctx._cache.clear()
    assert CloudTrailMultiRegionCheck().run(ctx) == []


def test_single_region_trail_does_not_pass(ctx: ScanContext) -> None:
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="local-logs")
    cloudtrail = boto3.client("cloudtrail", region_name="us-east-1")
    cloudtrail.create_trail(Name="local", S3BucketName="local-logs", IsMultiRegionTrail=False)
    cloudtrail.start_logging(Name="local")
    findings = CloudTrailMultiRegionCheck().run(ctx)
    assert len(findings) == 1
    assert "is not multi-Region" in findings[0].description


def test_ebs_encryption_is_per_region(ctx: ScanContext) -> None:
    assert len(EbsDefaultEncryptionCheck().run(ctx)) == 1
    boto3.client("ec2", region_name="us-east-1").enable_ebs_encryption_by_default()
    ctx._cache.clear()
    assert EbsDefaultEncryptionCheck().run(ctx) == []

    ctx.regions = ["us-east-1", "eu-west-1"]
    findings = EbsDefaultEncryptionCheck().run(ctx)
    assert [finding.region for finding in findings] == ["eu-west-1"]
    assert "2.2.1" in findings[0].reference
    assert findings[0].severity is Severity.MEDIUM

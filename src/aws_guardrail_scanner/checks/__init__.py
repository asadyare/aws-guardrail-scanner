"""Check catalogue."""

from __future__ import annotations

from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.checks.cloudtrail import CloudTrailMultiRegionCheck
from aws_guardrail_scanner.checks.ebs import EbsDefaultEncryptionCheck
from aws_guardrail_scanner.checks.iam import (
    IamAccessKeyAgeCheck,
    IamRootAccessKeysCheck,
    IamRootMfaCheck,
    IamUserMfaCheck,
)
from aws_guardrail_scanner.checks.s3 import (
    S3AccountBlockPublicAccessCheck,
    S3BucketBlockPublicAccessCheck,
    S3DefaultEncryptionCheck,
    S3PublicAclCheck,
    S3PublicPolicyCheck,
)
from aws_guardrail_scanner.checks.security_groups import (
    DefaultSecurityGroupCheck,
    SecurityGroupAllPortsCheck,
    SecurityGroupRdpCheck,
    SecurityGroupSshCheck,
)


class UnknownCheckError(ValueError):
    """Raised when ``--checks`` names nothing in the catalogue."""


def all_checks() -> list[Check]:
    """Return checks in catalogue order."""
    return [
        S3AccountBlockPublicAccessCheck(),
        S3BucketBlockPublicAccessCheck(),
        S3PublicAclCheck(),
        S3PublicPolicyCheck(),
        S3DefaultEncryptionCheck(),
        IamUserMfaCheck(),
        IamRootAccessKeysCheck(),
        IamRootMfaCheck(),
        IamAccessKeyAgeCheck(),
        SecurityGroupSshCheck(),
        SecurityGroupRdpCheck(),
        SecurityGroupAllPortsCheck(),
        DefaultSecurityGroupCheck(),
        CloudTrailMultiRegionCheck(),
        EbsDefaultEncryptionCheck(),
    ]


def select_checks(tokens: list[str]) -> list[Check]:
    """Resolve exact ids and prefixes such as ``s3`` or ``ec2-sg``.

    An empty token list selects the whole catalogue.
    """
    catalogue = all_checks()
    if not tokens:
        return catalogue

    by_id = {check.id: check for check in catalogue}
    selected: list[Check] = []
    seen: set[str] = set()
    unknown: list[str] = []

    for token in tokens:
        if token in by_id:
            matches = [by_id[token]]
        else:
            prefix = token[:-1] if token.endswith("-") else token
            matches = [check for check in catalogue if check.id.startswith(f"{prefix}-")]
        if not matches:
            unknown.append(token)
            continue
        for check in matches:
            if check.id not in seen:
                seen.add(check.id)
                selected.append(check)

    if unknown:
        known = ", ".join(check.id for check in catalogue)
        joined = ", ".join(unknown)
        raise UnknownCheckError(f"Unknown check: {joined}. Known checks: {known}")
    return selected

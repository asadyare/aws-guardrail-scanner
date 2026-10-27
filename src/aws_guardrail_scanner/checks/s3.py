"""S3 public access and default encryption checks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_guardrail_scanner.awsutil import (
    aws_error_code,
    bucket_region_from_constraint,
    session_client,
)
from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Finding, Severity

BPA_FLAGS: tuple[str, ...] = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
PUBLIC_ACL_URIS = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)
DATA_PERMISSIONS = frozenset({"READ", "WRITE", "FULL_CONTROL"})
ACCEPTED_SSE = frozenset({"AES256", "aws:kms", "aws:kms:dsse"})
MISSING_BPA_CODES = frozenset(
    {
        "NoSuchPublicAccessBlockConfiguration",
        "NoSuchPublicAccessBlock",
    }
)
MISSING_ENCRYPTION_CODES = frozenset(
    {
        "ServerSideEncryptionConfigurationNotFoundError",
        "ServerSideEncryptionConfigurationNotFound",
    }
)
MISSING_POLICY_CODES = frozenset({"NoSuchBucketPolicy"})

CIS_BPA = (
    "CIS AWS Foundations Benchmark v3.0.0 control 2.1.4; "
    "AWS Foundational Security Best Practices S3.1 (account) and S3.8 (bucket)"
)
FSBP_PUBLIC = (
    "AWS Foundational Security Best Practices S3.2 (public read) and S3.3 (public write). "
    "CIS AWS Foundations Benchmark v3.0.0 addresses this through control 2.1.4 "
    "(Block Public Access) rather than a separate ACL control"
)
ENCRYPTION_REFERENCE = (
    "No current CIS or AWS FSBP control. Security Hub retired FSBP S3.4 on "
    "20 September 2023 after Amazon S3 applied SSE-S3 by default. "
    "FSBP S3.17 still requires a KMS key, which is stricter than this check"
)


@dataclass(frozen=True, slots=True)
class PublicAccessBlock:
    """Account or bucket Block Public Access settings."""

    settings: dict[str, bool]
    configured: bool
    error: str | None = None


@dataclass(frozen=True, slots=True)
class BucketInventory:
    """Buckets visible to ``ListAllMyBuckets``."""

    buckets: tuple[dict[str, Any], ...]
    error: str | None = None


def missing_bpa_flags(settings: Mapping[str, Any] | None) -> list[str]:
    """Return Block Public Access flags that are not true."""
    if settings is None:
        return list(BPA_FLAGS)
    return [name for name in BPA_FLAGS if not settings.get(name)]


def bpa_enabled(settings: Mapping[str, Any] | None, name: str) -> bool:
    """Return whether one flag is explicitly true."""
    if settings is None:
        return False
    return bool(settings.get(name))


def effectively_on(
    account: Mapping[str, Any] | None,
    bucket: Mapping[str, Any] | None,
    name: str,
) -> bool:
    """Return whether account or bucket Block Public Access enables ``name``.

    Amazon S3 applies the more restrictive of the two.
    """
    return bpa_enabled(account, name) or bpa_enabled(bucket, name)


def public_acl_permissions(grants: list[Mapping[str, Any]]) -> list[str]:
    """Return permissions granted to All Users or Authenticated Users."""
    found: list[str] = []
    for grant in grants:
        grantee = grant.get("Grantee")
        if not isinstance(grantee, Mapping):
            continue
        if grantee.get("URI") not in PUBLIC_ACL_URIS:
            continue
        permission = grant.get("Permission")
        found.append(permission if isinstance(permission, str) else "UNKNOWN")
    return found


def acl_severity(permissions: set[str], *, ignored: bool) -> Severity:
    """Rate a public ACL, lowering it when Block Public Access ignores ACLs."""
    if ignored:
        return Severity.LOW
    if permissions & DATA_PERMISSIONS or "UNKNOWN" in permissions:
        return Severity.CRITICAL
    return Severity.MEDIUM


def policy_severity(*, restricted: bool) -> Severity:
    """Rate a public bucket policy."""
    if restricted:
        return Severity.LOW
    return Severity.CRITICAL


def encryption_algorithm(rules: list[Mapping[str, Any]]) -> str | None:
    """Return the first default SSE algorithm, if a rule declares one."""
    for rule in rules:
        default = rule.get("ApplyServerSideEncryptionByDefault")
        if not isinstance(default, Mapping):
            continue
        algorithm = default.get("SSEAlgorithm")
        if isinstance(algorithm, str) and algorithm:
            return algorithm
    return None


def _settings_from_config(config: Mapping[str, Any]) -> dict[str, bool]:
    return {name: bool(config.get(name)) for name in BPA_FLAGS}


def load_account_public_access(ctx: ScanContext) -> PublicAccessBlock:
    """Read account-level Block Public Access once per scan."""

    def load() -> PublicAccessBlock:
        client = session_client(ctx.session, "s3control", "us-east-1")
        try:
            response = client.get_public_access_block(AccountId=ctx.account_id)
        except ClientError as exc:
            if aws_error_code(exc) in MISSING_BPA_CODES:
                return PublicAccessBlock(settings={}, configured=False)
            ctx.add_error(
                S3AccountBlockPublicAccessCheck.id,
                f"Could not read account Block Public Access: {exc}",
            )
            return PublicAccessBlock(settings={}, configured=False, error=str(exc))
        except BotoCoreError as exc:
            ctx.add_error(
                S3AccountBlockPublicAccessCheck.id,
                f"Could not read account Block Public Access: {exc}",
            )
            return PublicAccessBlock(settings={}, configured=False, error=str(exc))
        config = response.get("PublicAccessBlockConfiguration", {})
        if not isinstance(config, Mapping):
            config = {}
        return PublicAccessBlock(settings=_settings_from_config(config), configured=True)

    return ctx.remember("s3-account-bpa", load)


def load_buckets(ctx: ScanContext) -> BucketInventory:
    """List general purpose buckets once per scan."""

    def load() -> BucketInventory:
        client = session_client(ctx.session, "s3", "us-east-1")
        try:
            response = client.list_buckets()
        except (ClientError, BotoCoreError) as exc:
            return BucketInventory(buckets=(), error=str(exc))
        raw = response.get("Buckets", [])
        if not isinstance(raw, list):
            return BucketInventory(buckets=())
        buckets = tuple(bucket for bucket in raw if isinstance(bucket, dict))
        return BucketInventory(buckets=buckets)

    return ctx.remember("s3-buckets", load)


def _bucket_name(bucket: Mapping[str, Any]) -> str | None:
    name = bucket.get("Name")
    if isinstance(name, str) and name:
        return name
    return None


def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


class _BucketCheck(Check):
    """Shared bucket loop for the S3 checks."""

    def _require_buckets(self, ctx: ScanContext) -> tuple[dict[str, Any], ...] | None:
        inventory = load_buckets(ctx)
        if inventory.error:
            ctx.add_error(self.id, f"Could not list buckets: {inventory.error}")
            return None
        return inventory.buckets

    def _region_and_client(self, ctx: ScanContext, name: str) -> tuple[str, Any]:
        locator = session_client(ctx.session, "s3", "us-east-1")
        try:
            response = locator.get_bucket_location(Bucket=name)
            region = bucket_region_from_constraint(response.get("LocationConstraint"))
        except (ClientError, BotoCoreError) as exc:
            ctx.add_error(self.id, f"Could not read bucket location: {exc}", _bucket_arn(name))
            region = "us-east-1"
        return region, session_client(ctx.session, "s3", region)

    def _bucket_bpa(self, ctx: ScanContext, client: Any, name: str) -> PublicAccessBlock:
        try:
            response = client.get_public_access_block(Bucket=name)
        except ClientError as exc:
            if aws_error_code(exc) in MISSING_BPA_CODES:
                return PublicAccessBlock(settings={}, configured=False)
            ctx.add_error(
                self.id,
                f"Could not read Block Public Access: {exc}",
                _bucket_arn(name),
            )
            return PublicAccessBlock(settings={}, configured=False, error=str(exc))
        except BotoCoreError as exc:
            ctx.add_error(
                self.id,
                f"Could not read Block Public Access: {exc}",
                _bucket_arn(name),
            )
            return PublicAccessBlock(settings={}, configured=False, error=str(exc))
        config = response.get("PublicAccessBlockConfiguration", {})
        if not isinstance(config, Mapping):
            config = {}
        return PublicAccessBlock(settings=_settings_from_config(config), configured=True)


class S3AccountBlockPublicAccessCheck(Check):
    id = "s3-account-block-public-access"
    title = "S3 Block Public Access is incomplete at account level"
    description = (
        "The account should enable all four Amazon S3 Block Public Access settings. "
        "That is the guardrail: buckets and objects stay private even if a policy or "
        "ACL is later made public."
    )
    severity = "medium"

    def run(self, ctx: ScanContext) -> list[Finding]:
        block = load_account_public_access(ctx)
        if block.error:
            return []
        missing = missing_bpa_flags(block.settings if block.configured else None)
        if not missing:
            return []
        state = "not configured" if not block.configured else f"missing {', '.join(missing)}"
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.MEDIUM,
                resource_id=f"arn:aws:s3:::{ctx.account_id}:account",
                region="global",
                description=(
                    f"Account-level S3 Block Public Access is {state}. "
                    "Without all four settings, a bucket policy or ACL can expose objects."
                ),
                remediation=(
                    "Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and "
                    "RestrictPublicBuckets on the account. Do this in the S3 console under "
                    "Block Public Access settings for this account, or with "
                    "s3control:PutPublicAccessBlock. Prefer the account setting over "
                    "per-bucket exceptions."
                ),
                reference=CIS_BPA,
            )
        ]


class S3BucketBlockPublicAccessCheck(_BucketCheck):
    id = "s3-bucket-block-public-access"
    title = "S3 bucket Block Public Access is incomplete"
    description = (
        "Each general purpose bucket should enable all four Block Public Access "
        "settings. When the account-level guardrail is already fully on, a bucket "
        "gap is latent and is rated low."
    )
    severity = "high"

    def run(self, ctx: ScanContext) -> list[Finding]:
        buckets = self._require_buckets(ctx)
        if buckets is None:
            return []
        account = load_account_public_access(ctx)
        account_settings = account.settings if account.configured and not account.error else None
        account_holds = not missing_bpa_flags(account_settings) and account_settings is not None
        findings: list[Finding] = []
        for bucket in buckets:
            name = _bucket_name(bucket)
            if name is None:
                continue
            region, client = self._region_and_client(ctx, name)
            block = self._bucket_bpa(ctx, client, name)
            if block.error:
                continue
            missing = missing_bpa_flags(block.settings if block.configured else None)
            if not missing:
                continue
            severity = Severity.LOW if account_holds else Severity.HIGH
            state = "not configured" if not block.configured else f"missing {', '.join(missing)}"
            contained = (
                " The account-level Block Public Access settings are fully on, so this "
                "bucket is not currently exposed. The bucket setting should still match, "
                "or the protection disappears if the account guardrail is relaxed."
                if account_holds
                else " The account-level guardrail does not cover this bucket."
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=severity,
                    resource_id=_bucket_arn(name),
                    region=region,
                    description=f"Block Public Access on {name} is {state}.{contained}",
                    remediation=(
                        "Enable all four Block Public Access settings on the bucket. "
                        "Keep the account-level settings enabled as well, so a new bucket "
                        "cannot be made public by mistake."
                    ),
                    reference=CIS_BPA,
                )
            )
        return findings


class S3PublicAclCheck(_BucketCheck):
    id = "s3-public-acl"
    title = "S3 bucket ACL grants public access"
    description = (
        "A bucket ACL should not grant All Users or Authenticated Users any permission. "
        "The severity drops when Block Public Access is ignoring public ACLs."
    )
    severity = "critical"

    def run(self, ctx: ScanContext) -> list[Finding]:
        buckets = self._require_buckets(ctx)
        if buckets is None:
            return []
        account = load_account_public_access(ctx)
        findings: list[Finding] = []
        for bucket in buckets:
            name = _bucket_name(bucket)
            if name is None:
                continue
            region, client = self._region_and_client(ctx, name)
            try:
                response = client.get_bucket_acl(Bucket=name)
            except (ClientError, BotoCoreError) as exc:
                ctx.add_error(self.id, f"Could not read bucket ACL: {exc}", _bucket_arn(name))
                continue
            raw_grants = response.get("Grants", [])
            grants = (
                [grant for grant in raw_grants if isinstance(grant, Mapping)]
                if isinstance(raw_grants, list)
                else []
            )
            permissions = public_acl_permissions(grants)
            if not permissions:
                continue
            bucket_bpa = self._bucket_bpa(ctx, client, name)
            account_settings = None if account.error or not account.configured else account.settings
            bucket_settings = None if bucket_bpa.error else bucket_bpa.settings
            ignored = effectively_on(account_settings, bucket_settings, "IgnorePublicAcls")
            severity = acl_severity(set(permissions), ignored=ignored)
            joined = ", ".join(sorted(set(permissions)))
            contained = (
                " Block Public Access is ignoring public ACLs, so this grant is not "
                "currently effective."
                if ignored
                else " Block Public Access is not ignoring public ACLs, so the grant is effective."
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=severity,
                    resource_id=_bucket_arn(name),
                    region=region,
                    description=(
                        f"The ACL on {name} grants {joined} to All Users or "
                        f"Authenticated Users.{contained}"
                    ),
                    remediation=(
                        "Remove the All Users and Authenticated Users grants. Prefer "
                        "Bucket owner enforced (ACLs disabled) and grant access with IAM. "
                        "Keep IgnorePublicAcls enabled at the account."
                    ),
                    reference=FSBP_PUBLIC,
                )
            )
        return findings


class S3PublicPolicyCheck(_BucketCheck):
    id = "s3-public-policy"
    title = "S3 bucket policy allows public access"
    description = (
        "GetBucketPolicyStatus reports whether a bucket policy allows public access. "
        "The severity drops when RestrictPublicBuckets is already in force."
    )
    severity = "critical"

    def run(self, ctx: ScanContext) -> list[Finding]:
        buckets = self._require_buckets(ctx)
        if buckets is None:
            return []
        account = load_account_public_access(ctx)
        findings: list[Finding] = []
        for bucket in buckets:
            name = _bucket_name(bucket)
            if name is None:
                continue
            region, client = self._region_and_client(ctx, name)
            try:
                response = client.get_bucket_policy_status(Bucket=name)
            except ClientError as exc:
                if aws_error_code(exc) in MISSING_POLICY_CODES:
                    continue
                ctx.add_error(
                    self.id, f"Could not read bucket policy status: {exc}", _bucket_arn(name)
                )
                continue
            except BotoCoreError as exc:
                ctx.add_error(
                    self.id, f"Could not read bucket policy status: {exc}", _bucket_arn(name)
                )
                continue
            status = response.get("PolicyStatus", {})
            is_public = isinstance(status, Mapping) and bool(status.get("IsPublic"))
            if not is_public:
                continue
            bucket_bpa = self._bucket_bpa(ctx, client, name)
            account_settings = None if account.error or not account.configured else account.settings
            bucket_settings = None if bucket_bpa.error else bucket_bpa.settings
            restricted = effectively_on(account_settings, bucket_settings, "RestrictPublicBuckets")
            severity = policy_severity(restricted=restricted)
            contained = (
                " RestrictPublicBuckets is on, so anonymous and cross-account public "
                "access is blocked. The policy is still a latent risk."
                if restricted
                else " RestrictPublicBuckets is off, so the public policy is effective."
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=severity,
                    resource_id=_bucket_arn(name),
                    region=region,
                    description=(
                        f"Amazon S3 reports that the bucket policy on {name} is public.{contained}"
                    ),
                    remediation=(
                        "Remove the public statement (Principal * or Principal AWS *) or add "
                        "a condition that limits it to a known account. Enable "
                        "RestrictPublicBuckets and BlockPublicPolicy at the account."
                    ),
                    reference=FSBP_PUBLIC,
                )
            )
        return findings


class S3DefaultEncryptionCheck(_BucketCheck):
    id = "s3-default-encryption"
    title = "S3 bucket has no explicit default encryption"
    description = (
        "Reports buckets without an explicit SSE-S3, SSE-KMS, or DSSE-KMS default. "
        "Since 5 January 2023 Amazon S3 encrypts new objects with SSE-S3 anyway, so "
        "this is configuration hygiene, rated low, not evidence that objects are plaintext."
    )
    severity = "low"

    def run(self, ctx: ScanContext) -> list[Finding]:
        buckets = self._require_buckets(ctx)
        if buckets is None:
            return []
        findings: list[Finding] = []
        for bucket in buckets:
            name = _bucket_name(bucket)
            if name is None:
                continue
            region, client = self._region_and_client(ctx, name)
            algorithm, failed = _read_encryption(ctx, self.id, client, name)
            if failed or algorithm in ACCEPTED_SSE:
                continue
            detail = (
                f"The bucket default names an unrecognised algorithm ({algorithm})."
                if algorithm
                else "The bucket has no default encryption configuration."
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.LOW,
                    resource_id=_bucket_arn(name),
                    region=region,
                    description=(
                        f"{detail} New uploads still receive SSE-S3 from the service default "
                        "unless a client requests something else. An explicit bucket setting "
                        "makes the choice visible and is where you would require a KMS key."
                    ),
                    remediation=(
                        "Set a bucket default of SSE-S3 (AES256) or SSE-KMS. Choose a customer "
                        "managed key where the data-protection policy requires one. This does "
                        "not re-encrypt objects that are already stored."
                    ),
                    reference=ENCRYPTION_REFERENCE,
                )
            )
        return findings


def _read_encryption(
    ctx: ScanContext,
    check_id: str,
    client: Any,
    name: str,
) -> tuple[str | None, bool]:
    """Return ``(algorithm, failed)``. A missing configuration is not a failure."""
    try:
        response = client.get_bucket_encryption(Bucket=name)
    except ClientError as exc:
        if aws_error_code(exc) in MISSING_ENCRYPTION_CODES:
            return None, False
        ctx.add_error(check_id, f"Could not read bucket encryption: {exc}", _bucket_arn(name))
        return None, True
    except BotoCoreError as exc:
        ctx.add_error(check_id, f"Could not read bucket encryption: {exc}", _bucket_arn(name))
        return None, True
    configuration = response.get("ServerSideEncryptionConfiguration", {})
    rules = configuration.get("Rules", []) if isinstance(configuration, Mapping) else []
    if not isinstance(rules, list):
        return None, False
    typed_rules = [rule for rule in rules if isinstance(rule, Mapping)]
    return encryption_algorithm(typed_rules), False

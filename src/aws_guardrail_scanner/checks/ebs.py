"""EBS encryption-by-default check."""

from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_guardrail_scanner.awsutil import session_client
from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Finding, Severity

EBS_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 control 2.2.1; "
    "AWS Foundational Security Best Practices EC2.7"
)


class EbsDefaultEncryptionCheck(Check):
    id = "ec2-ebs-default-encryption"
    title = "EBS encryption by default is off"
    description = (
        "Each Region should encrypt new EBS volumes by default. Volumes that already "
        "exist are not changed by turning the setting on."
    )
    severity = "medium"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for region in ctx.regions:
            client = session_client(ctx.session, "ec2", region)
            try:
                response = client.get_ebs_encryption_by_default()
            except (ClientError, BotoCoreError) as exc:
                ctx.add_error(self.id, f"Could not read EBS encryption by default: {exc}", region)
                continue
            if response.get("EbsEncryptionByDefault"):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    resource_id=f"arn:aws:ec2:{region}:{ctx.account_id}:ebs-encryption-by-default",
                    region=region,
                    description=(
                        f"EBS encryption by default is disabled in {region}. A volume created "
                        "without an explicit encryption flag will be unencrypted."
                    ),
                    remediation=(
                        "Turn on EBS encryption by default in this Region and set the default "
                        "KMS key if the platform key is not acceptable. This applies to new "
                        "volumes and to copies of unencrypted snapshots. It does not encrypt "
                        "volumes that are already attached."
                    ),
                    reference=EBS_REFERENCE,
                )
            )
        return findings

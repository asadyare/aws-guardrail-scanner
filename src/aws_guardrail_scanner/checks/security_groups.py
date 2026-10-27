"""Security group ingress and default-group checks."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_guardrail_scanner.awsutil import session_client
from aws_guardrail_scanner.checks.base import Check
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Finding, Severity

WORLD_V4 = "0.0.0.0/0"
WORLD_V6 = "::/0"
ADMIN_PROTOCOLS = frozenset({"tcp", "udp", "6", "17", "-1"})
SSH_PORT = 22
RDP_PORT = 3389

SSH_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 controls 5.2 (IPv4) and 5.3 (IPv6); "
    "AWS Foundational Security Best Practices EC2.13, EC2.53, and EC2.54"
)
RDP_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 controls 5.2 (IPv4) and 5.3 (IPv6); "
    "AWS Foundational Security Best Practices EC2.14, EC2.53, and EC2.54"
)
ALL_PORTS_REFERENCE = (
    "AWS Foundational Security Best Practices EC2.19. "
    "A rule that opens every port includes the high-risk ports that control lists. "
    "CIS AWS Foundations Benchmark v3.0.0 has no separate all-ports control; "
    "administration ports are covered by 5.2 and 5.3"
)
DEFAULT_SG_REFERENCE = (
    "CIS AWS Foundations Benchmark v3.0.0 control 5.4; "
    "AWS Foundational Security Best Practices EC2.2"
)


def world_cidrs(permission: Mapping[str, Any]) -> list[str]:
    """Return world-open CIDRs on one permission. Prefix lists are not expanded."""
    found: list[str] = []
    ipv4 = permission.get("IpRanges")
    if isinstance(ipv4, list):
        for entry in ipv4:
            if isinstance(entry, Mapping) and entry.get("CidrIp") == WORLD_V4:
                found.append(WORLD_V4)
    ipv6 = permission.get("Ipv6Ranges")
    if isinstance(ipv6, list):
        for entry in ipv6:
            if isinstance(entry, Mapping) and entry.get("CidrIpv6") == WORLD_V6:
                found.append(WORLD_V6)
    return found


def opens_all_ports(permission: Mapping[str, Any]) -> bool:
    """Return whether the permission opens every port."""
    protocol = str(permission.get("IpProtocol", ""))
    if protocol == "-1":
        return True
    return permission.get("FromPort") == 0 and permission.get("ToPort") == 65535


def opens_port(permission: Mapping[str, Any], port: int) -> bool:
    """Return whether TCP, UDP, or all protocols cover ``port``."""
    protocol = str(permission.get("IpProtocol", ""))
    if protocol == "-1":
        return True
    if protocol not in ADMIN_PROTOCOLS:
        return False
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if isinstance(from_port, int) and isinstance(to_port, int):
        return from_port <= port <= to_port
    return False


def _permissions(group: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    raw = group.get(key, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, Mapping)]


def load_security_groups(ctx: ScanContext) -> list[tuple[str, dict[str, Any]]]:
    """Describe security groups once per scan, in each requested Region."""

    def load() -> list[tuple[str, dict[str, Any]]]:
        groups: list[tuple[str, dict[str, Any]]] = []
        for region in ctx.regions:
            client = session_client(ctx.session, "ec2", region)
            try:
                paginator = client.get_paginator("describe_security_groups")
                for page in paginator.paginate():
                    raw = page.get("SecurityGroups", [])
                    if not isinstance(raw, list):
                        continue
                    for group in raw:
                        if isinstance(group, dict):
                            groups.append((region, group))
            except (ClientError, BotoCoreError) as exc:
                ctx.add_error(
                    "ec2-security-groups",
                    f"Could not describe security groups in {region}: {exc}",
                )
        return groups

    return ctx.remember("security-groups", load)


def _group_arn(region: str, group: Mapping[str, Any], account_id: str) -> str:
    owner = group.get("OwnerId")
    owner_id = owner if isinstance(owner, str) and owner else account_id
    group_id = group.get("GroupId")
    identifier = group_id if isinstance(group_id, str) else "unknown"
    return f"arn:aws:ec2:{region}:{owner_id}:security-group/{identifier}"


def _describe_rule(permission: Mapping[str, Any], cidrs: list[str]) -> str:
    protocol = str(permission.get("IpProtocol", "?"))
    sources = ", ".join(cidrs)
    if protocol == "-1":
        return f"all protocols and ports from {sources}"
    start = permission.get("FromPort")
    end = permission.get("ToPort")
    if start == 0 and end == 65535:
        ports = "all ports"
    elif start == end:
        ports = f"port {start}"
    else:
        ports = f"ports {start}-{end}"
    label = {"6": "tcp", "17": "udp"}.get(protocol, protocol)
    return f"{label} {ports} from {sources}"


class _WorldIngressCheck(Check):
    """Shared matcher for world-open ingress."""

    port: int | None = None
    match_all_ports: bool = False
    finding_severity: Severity = Severity.HIGH
    reference_text: str = ""

    def _matches(self, permission: Mapping[str, Any]) -> bool:
        if self.match_all_ports:
            return opens_all_ports(permission)
        if self.port is None:
            return False
        return opens_port(permission, self.port)

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for region, group in load_security_groups(ctx):
            matched: list[str] = []
            for permission in _permissions(group, "IpPermissions"):
                cidrs = world_cidrs(permission)
                if not cidrs or not self._matches(permission):
                    continue
                matched.append(_describe_rule(permission, cidrs))
            if not matched:
                continue
            group_id = group.get("GroupId", "unknown")
            group_name = group.get("GroupName", "unnamed")
            detail = "; ".join(matched)
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.finding_severity,
                    resource_id=_group_arn(region, group, ctx.account_id),
                    region=region,
                    description=(
                        f"Security group {group_id} ({group_name}) allows {detail}. "
                        "Managed prefix lists are not expanded, so a prefix list that "
                        "contains a world CIDR is not detected."
                    ),
                    remediation=(
                        "Delete the inbound rule or replace the source with a known CIDR, "
                        "a security group, or a prefix list that is not the whole internet. "
                        "Administration ports should be reached through a bastion, VPN, or "
                        "SSM Session Manager rather than a public listener."
                    ),
                    reference=self.reference_text,
                )
            )
        return findings


class SecurityGroupSshCheck(_WorldIngressCheck):
    id = "ec2-sg-ssh-open"
    title = "Security group allows SSH from the internet"
    description = "No security group should allow 0.0.0.0/0 or ::/0 onto port 22."
    severity = "high"
    port = SSH_PORT
    finding_severity = Severity.HIGH
    reference_text = SSH_REFERENCE


class SecurityGroupRdpCheck(_WorldIngressCheck):
    id = "ec2-sg-rdp-open"
    title = "Security group allows RDP from the internet"
    description = "No security group should allow 0.0.0.0/0 or ::/0 onto port 3389."
    severity = "high"
    port = RDP_PORT
    finding_severity = Severity.HIGH
    reference_text = RDP_REFERENCE


class SecurityGroupAllPortsCheck(_WorldIngressCheck):
    id = "ec2-sg-all-ports-open"
    title = "Security group allows all ports from the internet"
    description = (
        "No security group should allow 0.0.0.0/0 or ::/0 onto every port "
        "(protocol -1, or ports 0-65535)."
    )
    severity = "critical"
    match_all_ports = True
    finding_severity = Severity.CRITICAL
    reference_text = ALL_PORTS_REFERENCE


class DefaultSecurityGroupCheck(Check):
    id = "ec2-default-security-group"
    title = "Default security group allows traffic"
    description = (
        "The default security group of each VPC should have no inbound and no outbound "
        "rules. A new ENI that is assigned this group then has no path."
    )
    severity = "high"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for region, group in load_security_groups(ctx):
            if group.get("GroupName") != "default":
                continue
            inbound = _permissions(group, "IpPermissions")
            outbound = _permissions(group, "IpPermissionsEgress")
            if not inbound and not outbound:
                continue
            group_id = group.get("GroupId", "unknown")
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.HIGH,
                    resource_id=_group_arn(region, group, ctx.account_id),
                    region=region,
                    description=(
                        f"Default security group {group_id} in {region} has "
                        f"{len(inbound)} inbound and {len(outbound)} outbound rule(s). "
                        "AWS creates it with a self-referencing inbound rule and an "
                        "allow-all outbound rule. Both should be removed."
                    ),
                    remediation=(
                        "Remove every inbound and outbound rule from the default security "
                        "group. Do not attach it to workloads. Create a dedicated group "
                        "with the rules that workload actually needs."
                    ),
                    reference=DEFAULT_SG_REFERENCE,
                )
            )
        return findings

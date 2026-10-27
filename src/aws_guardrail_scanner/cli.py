"""Command line interface."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime

import boto3
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

from aws_guardrail_scanner import __version__
from aws_guardrail_scanner.checks import UnknownCheckError, all_checks, select_checks
from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Severity
from aws_guardrail_scanner.output import render, render_catalogue
from aws_guardrail_scanner.runner import run_scan

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-guardrail-scanner",
        description=(
            "Read-only scan of an AWS account for common misconfigurations. "
            "Nothing in this tool creates, changes, or deletes resources."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--profile", help="AWS shared-config profile. Defaults to the normal boto3 chain."
    )
    parser.add_argument(
        "--region",
        action="append",
        default=[],
        help="Region to scan. Repeat the flag, or pass a comma-separated list.",
    )
    parser.add_argument(
        "--regions",
        help="Comma-separated Regions. Merged with --region.",
    )
    parser.add_argument(
        "--checks",
        action="append",
        default=[],
        help=(
            "Checks to run, as a comma-separated list of ids or prefixes "
            "(for example s3 or ec2-sg). Repeatable. Defaults to every check."
        ),
    )
    parser.add_argument(
        "--output",
        choices=("table", "json", "sarif"),
        default="table",
        help="Output format. JSON and SARIF are written to stdout.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(severity.value for severity in Severity),
        help=(
            "Exit 1 when any finding is at or above this severity. "
            "Without it, a completed scan exits 0 so the tool can be tried safely."
        ),
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="Print the check catalogue and exit. Does not call AWS.",
    )
    parser.add_argument("--verbose", action="store_true", help="Log each check as it runs.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    if args.list_checks:
        sys.stdout.write(render_catalogue(all_checks()))
        return 0

    try:
        regions = collect_regions(args.region, args.regions)
        tokens = collect_tokens(args.checks)
        checks = select_checks(tokens)
    except (UnknownCheckError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        if not regions:
            regions = [_default_region(args.profile)]
        session = boto3.Session(profile_name=args.profile, region_name=regions[0])
        identity = session.client("sts", region_name=regions[0]).get_caller_identity()
        account_id = identity["Account"]
    except ProfileNotFound as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (ClientError, BotoCoreError) as exc:
        print(f"ERROR: could not determine the AWS account: {exc}", file=sys.stderr)
        return 2

    if not isinstance(account_id, str) or not account_id:
        print("ERROR: STS did not return an account id.", file=sys.stderr)
        return 2

    ctx = ScanContext(
        session=session,
        regions=regions,
        account_id=account_id,
        now=datetime.now(UTC),
    )
    report = run_scan(ctx, checks)
    sys.stdout.write(render(report, args.output, checks))
    for error in report.errors:
        target = f" {error.resource_id}" if error.resource_id else ""
        print(f"ERROR {error.check_id}{target}: {error.message}", file=sys.stderr)
    if args.output != "table":
        summary = report.summary()
        print(
            "aws-guardrail-scanner: "
            f"{len(report.findings)} finding(s) "
            f"(critical={summary['critical']}, high={summary['high']}, "
            f"medium={summary['medium']}, low={summary['low']}, info={summary['info']})",
            file=sys.stderr,
        )
    threshold = Severity(args.fail_on) if args.fail_on else None
    if report.breached(threshold):
        logger.info("Failing because a finding met --fail-on %s", args.fail_on)
        return 1
    return 0


def collect_regions(repeated: list[str], comma_separated: str | None) -> list[str]:
    """Merge ``--region`` and ``--regions``, preserving order and dropping duplicates."""
    raw: list[str] = []
    for value in repeated:
        raw.extend(_split_csv(value, "region"))
    if comma_separated:
        raw.extend(_split_csv(comma_separated, "region"))
    regions: list[str] = []
    seen: set[str] = set()
    for region in raw:
        if region not in seen:
            seen.add(region)
            regions.append(region)
    return regions


def collect_tokens(repeated: list[str]) -> list[str]:
    tokens: list[str] = []
    for value in repeated:
        tokens.extend(_split_csv(value, "check"))
    return tokens


def _split_csv(value: str, label: str) -> list[str]:
    parts = [part.strip() for part in value.split(",")]
    if any(not part for part in parts):
        raise ValueError(f"Invalid {label} value: {value!r}")
    return parts


def _default_region(profile: str | None) -> str:
    session = boto3.Session(profile_name=profile)
    region = session.region_name
    if not region:
        raise ValueError(
            "No Region configured. Pass --region, or set AWS_DEFAULT_REGION "
            "(or the profile's region)."
        )
    return region

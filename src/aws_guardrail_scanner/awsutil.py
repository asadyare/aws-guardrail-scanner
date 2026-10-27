"""Small boto3 helpers. Every call made through here is a read."""

from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_guardrail_scanner import __version__

CLIENT_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "standard"},
    connect_timeout=5,
    read_timeout=60,
    user_agent_extra=f"aws-guardrail-scanner/{__version__}",
)


def session_client(session: boto3.Session, service: str, region: str) -> Any:
    """Return a service client tagged so CloudTrail shows who scanned.

    The service name is a plain string, which does not match boto3-stubs'
    per-service overloads. Callers treat the client as ``Any``.
    """
    return session.client(service, region_name=region, config=CLIENT_CONFIG)  # type: ignore[call-overload]


def aws_error_code(exc: BaseException) -> str:
    """Return the AWS error code, or an empty string when there is none."""
    if not isinstance(exc, ClientError):
        return ""
    error = exc.response.get("Error", {})
    code = error.get("Code") if isinstance(error, dict) else None
    return code if isinstance(code, str) else ""


def bucket_region_from_constraint(constraint: object) -> str:
    """Map ``GetBucketLocation``'s constraint onto a Region name.

    ``us-east-1`` is returned as ``None``. The legacy EU value is ``eu-west-1``.
    """
    if constraint is None or constraint == "":
        return "us-east-1"
    if constraint == "EU":
        return "eu-west-1"
    if isinstance(constraint, str):
        return constraint
    return "us-east-1"

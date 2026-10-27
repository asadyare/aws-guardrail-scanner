"""Keep tests off the real AWS credential chain and the instance metadata service."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from aws_guardrail_scanner.context import ScanContext

os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ["AWS_CONFIG_FILE"] = os.devnull
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull


@pytest.fixture
def aws() -> object:
    with mock_aws():
        yield


@pytest.fixture
def ctx(aws: object) -> ScanContext:
    session = boto3.Session(region_name="us-east-1")
    account_id = session.client("sts").get_caller_identity()["Account"]
    return ScanContext(
        session=session,
        regions=["us-east-1"],
        account_id=account_id,
        now=datetime(2026, 10, 27, tzinfo=UTC),
    )

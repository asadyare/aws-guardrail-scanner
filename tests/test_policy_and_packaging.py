"""The published IAM policy and the CI pins stay honest."""

from __future__ import annotations

import json
import re
from pathlib import Path

from aws_guardrail_scanner.iam_actions import REQUIRED_IAM_ACTIONS

ROOT = Path(__file__).resolve().parents[1]
READ_PREFIXES = ("Get", "List", "Describe")


def test_policy_matches_the_actions_the_code_calls() -> None:
    policy = json.loads((ROOT / "iam" / "scanner-policy.json").read_text(encoding="utf-8"))
    statement = policy["Statement"]
    assert len(statement) == 1
    assert statement[0]["Effect"] == "Allow"
    assert statement[0]["Resource"] == "*"
    actions = statement[0]["Action"]
    assert tuple(actions) == REQUIRED_IAM_ACTIONS
    for action in actions:
        assert "*" not in action
        _service, verb = action.split(":", maxsplit=1)
        assert verb.startswith(READ_PREFIXES)


def test_workflow_pins_actions_and_limits_permissions() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read\n" in workflow
    uses = [line for line in workflow.splitlines() if "uses:" in line]
    assert uses
    for line in uses:
        assert re.search(r"uses:\s+\S+@[0-9a-f]{40}\b", line), line
    dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert "cooldown:" in dependabot
    assert "default-days:" in dependabot


def test_readme_embeds_the_policy_and_the_managed_alternative() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    policy = (ROOT / "iam" / "scanner-policy.json").read_text(encoding="utf-8").strip()
    assert policy in readme
    assert "SecurityAudit" in readme


def test_image_is_pinned_and_non_root() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "@sha256:" in dockerfile.splitlines()[0]
    users = [line for line in dockerfile.splitlines() if line.startswith("USER ")]
    assert users == ["USER scanner"]

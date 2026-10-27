# Security policy

## Reporting a vulnerability

If you find a vulnerability in this scanner (for example a way it could leak
credentials, or a dependency issue in the published image), report it privately
through [GitHub security advisories](https://github.com/asadyare/aws-guardrail-scanner/security/advisories/new).

Please do not open a public issue for an unfixed security bug.

This project does not run a paid bug-bounty programme. You will get a credit
in the fix if you want one.

## Scope

The scanner is read-only by design. A finding is a report about an AWS account,
not a vulnerability in this repository. Questions about a finding belong in a
normal issue.

The IAM policy in `iam/scanner-policy.json` is the maximum this tool should be
granted. Do not add write actions to the role that runs it.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## What CI checks

On every pull request the workflow runs Ruff, mypy, pytest, Bandit, pip-audit,
and Trivy against the published image. That is a safety net for the tool
itself. It is not a scan of an AWS account.

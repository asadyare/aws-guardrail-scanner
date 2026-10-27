"""Allow ``python -m aws_guardrail_scanner``."""

from aws_guardrail_scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

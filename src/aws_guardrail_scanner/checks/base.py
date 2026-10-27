"""Check interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aws_guardrail_scanner.context import ScanContext
from aws_guardrail_scanner.models import Finding


class Check(ABC):
    """One read-only control.

    ``severity`` is the usual rating, for the catalogue. A check may still
    emit a lower severity when a guardrail already contains the exposure.
    """

    id: str
    title: str
    description: str
    severity: str

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Return findings for this account. Do not mutate AWS."""

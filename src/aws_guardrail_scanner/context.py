"""Per-scan state shared by checks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TypeVar, cast

import boto3

from aws_guardrail_scanner.models import ScanError

T = TypeVar("T")
_MISSING = object()


@dataclass(slots=True)
class ScanContext:
    """Credentials, scope, and a small cache for shared read-only calls."""

    session: boto3.Session
    regions: list[str]
    account_id: str
    now: datetime
    errors: list[ScanError] = field(default_factory=list)
    _cache: dict[str, object] = field(default_factory=dict)

    def add_error(
        self,
        check_id: str,
        message: str,
        resource_id: str | None = None,
    ) -> None:
        self.errors.append(ScanError(check_id=check_id, message=message, resource_id=resource_id))

    def remember(self, key: str, factory: Callable[[], T]) -> T:
        """Return a cached value, computing it once."""
        cached = self._cache.get(key, _MISSING)
        if cached is not _MISSING:
            return cast(T, cached)
        value = factory()
        self._cache[key] = value
        return value

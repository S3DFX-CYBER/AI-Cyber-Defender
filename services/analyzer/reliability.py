"""Reliability helpers: circuit breaker and latency utilities."""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class CircuitBreaker:
    """Simple in-memory circuit breaker for analyzer path failures."""

    failure_threshold: int = 5
    reset_timeout_seconds: float = 30.0

    def __post_init__(self):
        self._failures = 0
        self._opened_at = 0.0

    @property
    def is_open(self) -> bool:
        if self._failures < self.failure_threshold:
            return False
        if time.monotonic() - self._opened_at > self.reset_timeout_seconds:
            self._failures = 0
            return False
        return True

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = 0.0

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold and not self._opened_at:
            self._opened_at = time.monotonic()

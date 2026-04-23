"""Reliability and graceful degradation tests."""

from services.analyzer import app
from services.analyzer.reliability import CircuitBreaker


class ExplodingEngine:
    def analyze(self, *args, **kwargs):
        raise RuntimeError("boom")


def test_circuit_breaker_opens_after_failures():
    cb = CircuitBreaker(failure_threshold=2, reset_timeout_seconds=999)
    assert cb.is_open is False
    cb.record_failure()
    assert cb.is_open is False
    cb.record_failure()
    assert cb.is_open is True


def test_run_analysis_fallback_allow_on_engine_error(monkeypatch):
    monkeypatch.setattr(app, "engine", ExplodingEngine())
    monkeypatch.setattr(app, "circuit_breaker", CircuitBreaker(failure_threshold=1, reset_timeout_seconds=999))
    result = app.run_analysis("hello")
    assert result.verdict == "benign"
    assert result.details["method"] == "fallback_allow"

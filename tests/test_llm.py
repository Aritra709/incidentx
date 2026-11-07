from __future__ import annotations

from typing import Any, Dict, List, Optional

from incidentx.classifier.hybrid import HybridClassifier
from incidentx.classifier.llm import LLMReasoner
from incidentx.models import LogEntry


def make_reasoner(enabled: bool = True) -> LLMReasoner:
    return LLMReasoner(
        {
            "enabled": enabled,
            "api_key": "test-key",
            "base_url": "http://localhost:11434/v1",
            "model": "test-model",
            "timeout_seconds": 1,
        }
    )


class FakeReasoner(LLMReasoner):
    def __init__(self) -> None:
        super().__init__(
            {
                "enabled": True,
                "api_key": "test-key",
                "base_url": "http://localhost:11434/v1",
                "model": "test-model",
                "timeout_seconds": 1,
            }
        )
        self.calls = 0

    def classify_error(
        self,
        message: str,
        level: str,
        service: str,
        allowed_categories: List[str],
    ) -> Optional[Dict[str, Any]]:
        self.calls += 1
        return {
            "category": "API_TIMEOUT",
            "family": "DEPENDENCY",
            "confidence": 0.8,
            "reason": "fake classification",
        }


def test_disabled_reasoner_returns_none():
    reasoner = make_reasoner(enabled=False)
    assert reasoner.classify_error("x", "ERROR", "svc", ["API_TIMEOUT"]) is None
    assert reasoner.explain_incident({"incident": "x"}) is None


def test_classify_error_parses_fenced_json_and_clamps_confidence(monkeypatch):
    reasoner = make_reasoner()
    monkeypatch.setattr(
        reasoner,
        "_chat",
        lambda *args, **kwargs: (
            '```json\n{"category":"api_timeout","family":"dependency",'
            '"confidence":1.5,"reason":"upstream stalled"}\n```'
        ),
    )
    result = reasoner.classify_error("request timed out", "ERROR", "checkout-api", ["API_TIMEOUT"])
    assert result == {
        "category": "API_TIMEOUT",
        "family": "DEPENDENCY",
        "confidence": 0.95,
        "reason": "upstream stalled",
    }


def test_classify_error_rejects_unknown_category(monkeypatch):
    reasoner = make_reasoner()
    monkeypatch.setattr(
        reasoner,
        "_chat",
        lambda *args, **kwargs: '{"category":"MADE_UP","confidence":0.9}',
    )
    assert reasoner.classify_error("x", "ERROR", "svc", ["API_TIMEOUT"]) is None


def test_classify_error_handles_invalid_json(monkeypatch):
    reasoner = make_reasoner()
    monkeypatch.setattr(reasoner, "_chat", lambda *args, **kwargs: "not json at all")
    assert reasoner.classify_error("x", "ERROR", "svc", ["API_TIMEOUT"]) is None


def test_hybrid_uses_llm_only_for_unknown_signatures():
    fake = FakeReasoner()
    classifier = HybridClassifier(llm=fake, use_llm=True)
    entries = [
        LogEntry(message="novel checkout failure xyz", level="ERROR", service="checkout-api"),
        LogEntry(message="connection pool exhausted", level="ERROR", service="checkout-api"),
    ]

    events, warnings = classifier.detect_errors(entries)

    assert not warnings
    assert fake.calls == 1
    assert events[0].category == "API_TIMEOUT"
    assert events[0].source == "llm"
    assert events[1].category == "CONNECTION_POOL_EXHAUSTED"
    assert events[1].source == "rules"


def test_hybrid_caps_llm_classification_attempts():
    fake = FakeReasoner()
    classifier = HybridClassifier(llm=fake, use_llm=True)
    entries = [
        LogEntry(message=f"novel failure {index}", level="ERROR", service="checkout-api")
        for index in range(10)
    ]

    events, warnings = classifier.detect_errors(entries)

    assert fake.calls == 8
    assert len(events) == 10
    assert any("capped at 8" in warning for warning in warnings)
    assert events[-1].category == "UNKNOWN"


def test_hybrid_honors_per_call_use_llm_flag():
    fake = FakeReasoner()
    classifier = HybridClassifier(llm=fake, use_llm=True)
    entries = [
        LogEntry(message="novel checkout failure xyz", level="ERROR", service="checkout-api")
    ]

    events, warnings = classifier.detect_errors(entries, use_llm=False)

    assert not warnings
    assert fake.calls == 0
    assert events[0].category == "UNKNOWN"


def test_failed_llm_request_trips_circuit_breaker(monkeypatch):
    calls = {"count": 0}

    def fail(*args, **kwargs):
        calls["count"] += 1
        raise RuntimeError("llm down")

    monkeypatch.setattr("incidentx.classifier.llm.requests.post", fail)
    reasoner = make_reasoner()

    assert reasoner.classify_error("x", "ERROR", "svc", ["API_TIMEOUT"]) is None
    assert not reasoner.available
    assert reasoner.classify_error("y", "ERROR", "svc", ["API_TIMEOUT"]) is None
    assert calls["count"] == 1


def test_reset_health_allows_retry(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("llm down")

    monkeypatch.setattr("incidentx.classifier.llm.requests.post", fail)
    reasoner = make_reasoner()
    assert reasoner.classify_error("x", "ERROR", "svc", ["API_TIMEOUT"]) is None
    assert not reasoner.available

    reasoner.reset_health()
    monkeypatch.setattr(
        reasoner,
        "_chat",
        lambda *args, **kwargs: '{"category":"API_TIMEOUT","confidence":0.7}',
    )
    result = reasoner.classify_error("x", "ERROR", "svc", ["API_TIMEOUT"])
    assert result is not None
    assert result["category"] == "API_TIMEOUT"


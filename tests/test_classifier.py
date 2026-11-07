from incidentx.classifier.rules import RuleBasedClassifier, build_signature
from incidentx.models import LogEntry


def entry(message: str, level: str = "ERROR", service: str = "checkout-api") -> LogEntry:
    return LogEntry(message=message, level=level, service=service)


def test_detects_database_connection():
    classifier = RuleBasedClassifier()
    event = classifier.classify(entry("Failed to connect to database: connection refused"))
    assert event is not None
    assert event.category == "DATABASE_CONNECTION"
    assert event.family == "INFRASTRUCTURE"
    assert event.confidence > 0.7


def test_detects_pool_exhaustion():
    classifier = RuleBasedClassifier()
    event = classifier.classify(entry("connection pool exhausted (max=8, waiting=64)"))
    assert event is not None
    assert event.category == "CONNECTION_POOL_EXHAUSTED"


def test_service_scope_boost():
    classifier = RuleBasedClassifier()
    api = classifier.classify(
        entry("upstream request timeout", service="web-frontend")
    )
    unrelated = classifier.classify(
        entry("upstream request timeout", service="notification-worker")
    )
    assert api is not None and unrelated is not None
    assert api.category == "API_TIMEOUT"
    assert api.confidence > unrelated.confidence


def test_unknown_error_escalated_but_unmatched_warn_ignored():
    classifier = RuleBasedClassifier()
    unknown = classifier.classify(entry("the flux capacitor inverted"))
    assert unknown is not None
    assert unknown.category == "UNKNOWN"
    assert classifier.classify(entry("the flux capacitor inverted", level="WARN")) is None


def test_prefers_longer_specific_match_when_scores_tie():
    classifier = RuleBasedClassifier()
    event = classifier.classify(
        entry(
            "Checkout request failed: upstream timeout after 5000ms",
            level="WARN",
            service="web-frontend",
        )
    )
    assert event is not None
    assert event.category == "API_TIMEOUT"
    assert event.matched_pattern == "timeout after 5000ms"


def test_signature_normalizes_numbers_and_ids():
    signature = build_signature(
        "Pool waiter 123 blocked for user 99 at 0xdeadbeef"
    )
    assert "123" not in signature
    assert "0xdeadbeef" not in signature
    assert "n" in signature.split()
    assert "id" in signature.split()

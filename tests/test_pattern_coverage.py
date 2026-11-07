from incidentx.classifier.rules import RuleBasedClassifier
from incidentx.models import LogEntry

SAMPLES = [
    ("DATABASE_CONNECTION", "payments-api", "failed to connect to database: connection refused"),
    ("CONNECTION_POOL_EXHAUSTED", "checkout-api", "connection pool exhausted"),
    ("QUERY_FAILED", "payments-api", "query failed: deadlock detected"),
    ("NETWORK_TIMEOUT", "payments-api", "i/o timeout"),
    ("API_TIMEOUT", "checkout-api", "upstream request timeout"),
    ("DISK_FULL", "admin-dashboard", "no space left on device"),
    ("MEMORY_EXHAUSTION", "payments-api", "out of memory"),
    ("CPU_THROTTLING", "admin-dashboard", "cpu throttling detected"),
    ("OOM_KILLER", "payments-api", "oom killer terminated process 412"),
    ("NULL_POINTER", "catalog-service", "NullPointerException at OrderService.java"),
    ("UNHANDLED_EXCEPTION", "notification-worker", "unhandled exception in worker"),
    ("VALIDATION_ERROR", "web-frontend", "validation error: missing email"),
    ("AUTH_FAILURE", "auth-service", "authentication failed"),
    ("RATE_LIMIT", "payments-api", "rate limit exceeded"),
    ("EXTERNAL_API_DOWN", "payments-api", "payment provider unavailable"),
    ("THIRD_PARTY_TIMEOUT", "payments-api", "third-party API timed out"),
    ("MESSAGE_QUEUE_BACKUP", "notification-worker", "consumer lag 5000"),
    ("SERVICE_UNAVAILABLE", "web-frontend", "bad gateway"),
    ("MISSING_CONFIG", "checkout-api", "environment variable DATABASE_URL not set"),
    ("INVALID_CONFIG", "checkout-api", "invalid config: pool size must be positive"),
    ("FEATURE_FLAG_ERROR", "web-frontend", "unknown feature flag checkout_v2"),
    ("UNAUTHORIZED_ACCESS", "admin-dashboard", "forbidden: admin role required"),
    ("INJECTION_ATTEMPT", "web-frontend", "sql injection attempt blocked"),
    ("BRUTE_FORCE", "auth-service", "multiple failed login attempts"),
    ("CERTIFICATE_EXPIRED", "web-frontend", "certificate has expired"),
    ("LOG_WRITE_FAILURE", "admin-dashboard", "failed to write log"),
    ("CACHE_WRITE_FAILURE", "catalog-service", "cache write failed"),
    ("BACKUP_FAILURE", "admin-dashboard", "backup failed for orders-db"),
    ("SERVICE_CRASH", "payments-api", "crashloopbackoff"),
    ("DEPLOY_FAILURE", "checkout-api", "deployment checkout-api failed"),
]


def test_every_configured_pattern_has_a_classifiable_sample():
    classifier = RuleBasedClassifier()
    assert len(classifier.patterns) == len(SAMPLES)
    assert {category for category, _, _ in SAMPLES} == set(classifier.patterns)


def test_curated_signatures_classify_to_expected_categories():
    classifier = RuleBasedClassifier()
    misses = []
    for expected, service, message in SAMPLES:
        entry = LogEntry(
            raw_text=message,
            level="ERROR",
            service=service,
            message=message,
        )
        event = classifier.classify(entry)
        actual = event.category if event else None
        if actual != expected:
            misses.append((expected, actual, message))
    assert not misses, f"Pattern samples classified incorrectly: {misses}"

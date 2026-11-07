from incidentx.changes.tracker import parse_changes_text
from incidentx.classifier.rules import RuleBasedClassifier
from incidentx.correlator.engine import CorrelationEngine
from incidentx.ingestion.parser import parse_text
from incidentx.models import LogFormat
from incidentx.preprocessor.normalizer import normalize_entries


def make_cluster(lines):
    entries = parse_text("\n".join(lines), LogFormat.TXT)
    entries = normalize_entries(entries)
    errors = RuleBasedClassifier().detect_errors(entries)
    return CorrelationEngine().correlate_errors(errors, 5)[0]


def test_temporal_clustering_groups_cascade():
    cluster = make_cluster(
        [
            "2026-11-07 19:55:02 ERROR [checkout-api] connection pool exhausted",
            "2026-11-07 19:55:03 ERROR [checkout-api] database connection timeout",
            "2026-11-07 19:55:04 ERROR [web-frontend] upstream request timeout",
            "2026-11-07 20:20:00 ERROR [auth-service] authentication failed",
        ]
    )
    assert set(cluster.affected_services) == {"checkout-api", "web-frontend"}


def test_causal_root_is_earliest_primary():
    cluster = make_cluster(
        [
            "2026-11-07 19:55:02 ERROR [checkout-api] connection pool exhausted",
            "2026-11-07 19:55:03 ERROR [checkout-api] database connection timeout",
            "2026-11-07 19:55:04 ERROR [web-frontend] upstream request timeout",
            "2026-11-07 19:55:09 ERROR [web-frontend] 503 Service Unavailable",
        ]
    )
    root = CorrelationEngine().identify_root_cause(cluster)
    assert root.primary_category == "CONNECTION_POOL_EXHAUSTED"
    assert root.primary_service == "checkout-api"


def test_change_linking_prefers_affected_service():
    cluster = make_cluster(
        [
            "2026-11-07 19:55:02 ERROR [checkout-api] connection pool exhausted",
            "2026-11-07 19:55:04 ERROR [web-frontend] upstream request timeout",
        ]
    )
    changes = parse_changes_text(
        """
        changes:
          - id: deploy-checkout
            timestamp: "2026-11-07 19:52:10"
            type: deploy
            service: checkout-api
            description: "reduce connection pool max from 40 to 8"
            rollback: "kubectl rollout undo deployment/checkout-api"
          - id: deploy-catalog
            timestamp: "2026-11-07 19:40:00"
            type: deploy
            service: catalog-service
            description: "update product image CDN"
        """
    )
    matches = CorrelationEngine().link_changes(cluster, changes)
    assert matches
    assert matches[0].change.id == "deploy-checkout"
    assert matches[0].confidence > matches[-1].confidence


def test_trace_ids_split_clusters():
    lines = [
        '{"timestamp":"2026-11-07 19:55:02","level":"ERROR","service":"checkout-api",'
        '"message":"connection pool exhausted","trace_id":"a"}',
        '{"timestamp":"2026-11-07 19:55:03","level":"ERROR","service":"checkout-api",'
        '"message":"connection pool exhausted","trace_id":"b"}',
    ]
    entries = parse_text("\n".join(lines), LogFormat.JSON)
    entries = normalize_entries(entries)
    errors = RuleBasedClassifier().detect_errors(entries)
    clusters = CorrelationEngine().correlate_errors(errors, 5)
    assert len(clusters) == 2

from incidentx.knowledge_base.loader import KnowledgeBase
from incidentx.knowledge_base.remediation import RemediationEngine
from incidentx.models import IncidentCluster, ErrorEvent, LogEntry, RootCauseAnalysis, SeverityAssessment
from datetime import datetime


def build_cluster():
    log = LogEntry(
        raw_text="ERROR [checkout-api] connection pool exhausted",
        timestamp=datetime(2026, 11, 7, 19, 55),
        level="ERROR",
        service="checkout-api",
        message="connection pool exhausted",
    )
    error = ErrorEvent(
        log_entry=log,
        category="CONNECTION_POOL_EXHAUSTED",
        family="INFRASTRUCTURE",
        signature="connection pool exhausted",
        confidence=0.9,
    )
    return IncidentCluster(
        id="INC-TEST",
        errors=[error],
        start=log.timestamp,
        end=log.timestamp,
        affected_services=["checkout-api"],
    )


def test_rollback_is_approval_gated_and_never_executed():
    cluster = build_cluster()
    severity = SeverityAssessment(level="HIGH", score=70)
    root = RootCauseAnalysis(
        primary_category="CONNECTION_POOL_EXHAUSTED",
        primary_service="checkout-api",
    )
    engine = RemediationEngine(KnowledgeBase())
    plan = engine.build_plan(cluster, severity, root)
    assert plan.actions
    assert any(action.requires_approval for action in plan.actions)
    action = plan.actions[0]
    dry = engine.dry_run(plan, action.id)
    assert dry is not None
    assert "No command was run" in (dry.dry_run_output or "")
    approved = engine.approve(plan, action.id, "tester")
    assert approved is not None
    assert approved.status == "approved_simulated"
    assert "simulated" in (approved.note or "").lower()


def test_unknown_category_falls_back_to_default():
    kb = KnowledgeBase()
    rule = kb.get_remediation("SOMETHING_NEW")
    assert rule
    assert rule.get("immediate")

from fastapi.testclient import TestClient

from incidentx.api.routes import app
from incidentx.pipeline.orchestrator import IncidentXPipeline

client = TestClient(app)


def demo_text() -> tuple[str, str]:
    paths = IncidentXPipeline.demo_paths()
    return (
        paths["logs"].read_text(encoding="utf-8"),
        paths["changes"].read_text(encoding="utf-8"),
    )


def test_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["patterns_loaded"] > 20
    assert body["services_in_catalog"] > 5


def test_patterns():
    response = client.get("/api/v1/patterns")
    assert response.status_code == 200
    categories = {item["category"] for item in response.json()}
    assert {"DATABASE_CONNECTION", "CONNECTION_POOL_EXHAUSTED"} <= categories


def test_runbook():
    response = client.get("/api/v1/runbooks/CONNECTION_POOL_EXHAUSTED")
    assert response.status_code == 200
    body = response.json()
    assert body["runbook"] == "connection_pool_exhausted.md"
    assert "pool" in body["content"].lower()


def test_analyze_demo():
    logs, changes = demo_text()
    response = client.post(
        "/api/v1/analyze",
        json={
            "logs": logs,
            "format": "txt",
            "changes": changes,
            "options": {"use_llm": False},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["incidents"]) == 1
    incident = body["incidents"][0]
    assert incident["severity"]["level"] == "CRITICAL"
    assert incident["severity"]["baseline_level"] == "MEDIUM"
    assert incident["root_cause"]["primary_category"] == "CONNECTION_POOL_EXHAUSTED"
    assert incident["suspected_change"]["id"] == "chg-20261107-001"
    assert any(
        action["requires_approval"] for action in incident["remediation"]
    )
    assert "What Changed?" in incident["report_markdown"]
    assert incident["customer_status_update"]
    assert any(entry["type"].startswith("CHANGE") for entry in incident["timeline"])


def test_analyze_rejects_empty_logs():
    response = client.post("/api/v1/analyze", json={"logs": "   "})
    assert response.status_code == 400


def test_analyze_can_skip_remediation():
    logs, changes = demo_text()
    response = client.post(
        "/api/v1/analyze",
        json={
            "logs": logs,
            "changes": changes,
            "options": {"use_llm": False, "include_remediation": False},
        },
    )
    assert response.status_code == 200
    incident = response.json()["incidents"][0]
    assert incident["remediation"] == []
    assert incident["prevention"] == []


def test_business_profile():
    response = client.get("/api/v1/business-profile")
    assert response.status_code == 200
    body = response.json()
    assert "checkout-api" in body["revenue_services"]
    assert body["revenue_windows"]

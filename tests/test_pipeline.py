import pytest

from incidentx.pipeline.orchestrator import IncidentXPipeline


@pytest.fixture
def pipeline(tmp_path):
    return IncidentXPipeline(memory_path=tmp_path / "memory.json")


def run_demo(pipeline):
    paths = IncidentXPipeline.demo_paths()
    return pipeline.analyze(
        logs_path=paths["logs"],
        changes_path=paths["changes"],
        use_llm=False,
    )


def test_demo_end_to_end(pipeline):
    result = run_demo(pipeline)
    assert result.logs_processed > 20
    assert result.errors_detected > 15
    assert result.changes_loaded == 4
    assert len(result.incidents) == 1

    report = result.incidents[0]
    assert report.severity.level == "CRITICAL"
    assert report.severity.boosted is True
    assert report.severity.baseline_level == "MEDIUM"
    assert report.severity.revenue_window == "Saturday flash sale"
    assert report.root_cause.primary_category == "CONNECTION_POOL_EXHAUSTED"
    assert report.root_cause.primary_service == "checkout-api"
    assert report.cluster.suspected_change is not None
    assert report.cluster.suspected_change.id == "chg-20261107-001"
    assert "checkout" in report.plain_english.headline.lower()
    assert "checkout" in report.customer_status_update.lower()
    assert report.remediation.proposed_rollback == (
        "kubectl rollout undo deployment/checkout-api"
    )
    assert "What Changed?" in report.engineer_markdown
    assert "Ready-to-Send Customer Update" in report.engineer_markdown


def test_red_herring_change_ranks_lower(pipeline):
    result = run_demo(pipeline)
    report = result.incidents[0]
    assert report.root_cause.change_confidence > 0.8
    assert report.root_cause.suspected_change_id == "chg-20261107-001"


def test_incident_memory_matches_seed(pipeline):
    result = run_demo(pipeline)
    report = result.incidents[0]
    assert report.cluster.similar_incidents
    assert report.cluster.similar_incidents[0].incident_id == "INC-20261024-001"
    assert report.cluster.similar_incidents[0].similarity >= 0.3


def test_severity_drops_outside_business_window(pipeline):
    result = run_demo(pipeline)
    report = result.incidents[0]
    baseline = pipeline.assessor.assess(report.cluster, ignore_windows=True)
    assert baseline.level == "MEDIUM"
    assert baseline.score < report.severity.score


def test_result_reports_llm_off_when_request_disables_it(pipeline):
    pipeline.llm.enabled = True
    result = run_demo(pipeline)
    assert result.llm_available is False


def test_html_export_escapes_untrusted_text(pipeline):
    report = run_demo(pipeline).incidents[0]
    report.title = "<script>alert(1)</script>"

    document = pipeline.reporter.export_html(report)

    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document


def test_reports_written(pipeline, tmp_path):
    result = run_demo(pipeline)
    output = tmp_path / "reports"
    written = pipeline.write_reports(result.incidents, output)
    assert len(written) == 3
    assert all(path.exists() for path in written)
    assert any(path.suffix == ".md" for path in written)
    assert any(path.suffix == ".json" for path in written)
    assert any(path.suffix == ".html" for path in written)
    html = next(path for path in written if path.suffix == ".html").read_text(
        encoding="utf-8"
    )
    assert "Ready-to-send customer update" in html
    assert "Saturday flash sale" in html

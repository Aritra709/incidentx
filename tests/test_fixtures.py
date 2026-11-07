from pathlib import Path

import pytest

from incidentx.ingestion.parser import detect_format
from incidentx.models import LogFormat
from incidentx.pipeline.orchestrator import IncidentXPipeline

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pipeline(tmp_path):
    return IncidentXPipeline(memory_path=tmp_path / "memory.json")


def analyze_fixture(pipeline, relative_path):
    path = FIXTURES / relative_path
    return pipeline.analyze(logs_path=path, use_llm=False)


def test_fixture_formats_are_detected():
    assert detect_format(FIXTURES / "txt" / "multi_incident.txt") == LogFormat.TXT
    assert detect_format(FIXTURES / "json" / "api_timeout_spike.json") == LogFormat.JSON
    assert detect_format(FIXTURES / "csv" / "disk_full.csv") == LogFormat.CSV


def test_multi_incident_fixture_separates_txt_incidents(pipeline):
    result = analyze_fixture(pipeline, "txt/multi_incident.txt")
    assert result.logs_processed == 9
    assert result.errors_detected == 9
    assert len(result.incidents) == 2

    roots = {report.root_cause.primary_category for report in result.incidents}
    assert roots == {"DISK_FULL", "AUTH_FAILURE"}
    for report in result.incidents:
        assert report.remediation.actions
        assert report.plain_english.headline
        assert report.customer_status_update


def test_json_fixture_correlates_api_timeout(pipeline):
    result = analyze_fixture(pipeline, "json/api_timeout_spike.json")
    assert result.logs_processed == 4
    assert result.errors_detected == 4
    assert len(result.incidents) == 1

    report = result.incidents[0]
    assert report.root_cause.primary_category == "API_TIMEOUT"
    assert set(report.cluster.affected_services) == {"web-frontend", "mobile-app"}
    assert report.severity.level in {"MEDIUM", "HIGH", "CRITICAL"}


def test_csv_fixture_detects_disk_full(pipeline):
    result = analyze_fixture(pipeline, "csv/disk_full.csv")
    assert result.logs_processed == 4
    assert result.errors_detected == 4
    assert len(result.incidents) == 1

    report = result.incidents[0]
    assert report.root_cause.primary_category == "DISK_FULL"
    assert report.cluster.affected_services == ["admin-dashboard"]
    assert report.remediation.runbook == "service_unavailable.md"


def test_include_remediation_can_be_disabled(pipeline):
    result = pipeline.analyze(
        logs_path=FIXTURES / "csv" / "disk_full.csv",
        use_llm=False,
        include_remediation=False,
    )
    report = result.incidents[0]
    assert report.remediation.actions == []
    assert report.remediation.prevention == []

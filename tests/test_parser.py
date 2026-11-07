from datetime import datetime

from incidentx.ingestion.parser import detect_format, parse_text
from incidentx.models import LogFormat


def test_parse_txt_bracket_format():
    entries = parse_text(
        "2026-11-07 19:55:02 ERROR [checkout-api] connection pool exhausted\n",
        LogFormat.TXT,
    )
    assert len(entries) == 1
    entry = entries[0]
    assert entry.timestamp == datetime(2026, 11, 7, 19, 55, 2)
    assert entry.level == "ERROR"
    assert entry.service == "checkout-api"
    assert "pool exhausted" in entry.message


def test_parse_txt_service_level_format():
    entries = parse_text(
        "2026-11-07 20:00:05 checkout-api ERROR database timeout\n",
        LogFormat.TXT,
    )
    assert entries[0].service == "checkout-api"
    assert entries[0].level == "ERROR"


def test_parse_json_aliases_and_metadata():
    text = """
    [
      {"@timestamp": "2026-11-07T20:00:05Z", "severity": "error",
       "service_name": "payments-api", "msg": "request timed out",
       "trace": {"id": "abc"}}
    ]
    """
    entries = parse_text(text, LogFormat.JSON)
    entry = entries[0]
    assert entry.service == "payments-api"
    assert entry.level == "ERROR"
    assert entry.message == "request timed out"
    assert entry.metadata.get("trace.id") == "abc"


def test_parse_csv():
    text = (
        "timestamp,level,service,message\n"
        "2026-11-07 20:01:00,ERROR,web-frontend,503 Service Unavailable\n"
    )
    entries = parse_text(text, LogFormat.CSV)
    assert entries[0].timestamp == datetime(2026, 11, 7, 20, 1)
    assert entries[0].service == "web-frontend"
    assert entries[0].level == "ERROR"


def test_unknown_line_infers_level():
    entries = parse_text("something failed badly\n", LogFormat.TXT)
    assert entries[0].level == "ERROR"
    assert entries[0].service == "unknown"


def test_detect_format(tmp_path):
    path = tmp_path / "logs.ndjson"
    path.write_text("{}\n", encoding="utf-8")
    assert detect_format(path) == LogFormat.JSON

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from dateutil import parser as date_parser

from ..models import LEVEL_ORDER, LogEntry, LogFormat

TXT_PATTERNS = [
    re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
        r"\s+(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)"
        r"\s+\[?(?P<service>[A-Za-z0-9_.\-/]+)\]?\s*[:\-]?\s*(?P<msg>.*)$"
    ),
    re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
        r"\s+(?P<service>[A-Za-z0-9_.\-/]+)"
        r"\s+(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)"
        r"\s+(?P<msg>.*)$"
    ),
]

SYSLOG_PATTERN = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+(?P<service>[A-Za-z0-9_.\-/]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)

LEVEL_ALIASES = {
    "WARNING": "WARN",
    "ERR": "ERROR",
    "CRIT": "CRITICAL",
    "EMERG": "CRITICAL",
    "ALERT": "CRITICAL",
    "NOTICE": "INFO",
    "TRACE": "DEBUG",
}

TIMESTAMP_KEYS = (
    "timestamp",
    "time",
    "ts",
    "@timestamp",
    "datetime",
    "date",
    "eventTime",
    "logged_at",
    "loggedAt",
)
LEVEL_KEYS = ("level", "severity", "log_level", "loglevel", "priority", "log.level")
SERVICE_KEYS = (
    "service",
    "service_name",
    "serviceName",
    "app",
    "application",
    "logger",
    "source",
    "component",
    "container_name",
)
MESSAGE_KEYS = (
    "message",
    "msg",
    "log",
    "text",
    "event",
    "error",
    "description",
    "body",
)


def _to_naive(value: datetime) -> datetime:
    if value.tzinfo is not None:
        value = value.astimezone().replace(tzinfo=None)
    return value


def parse_timestamp(value: Any, default_year: Optional[int] = None) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return _to_naive(value)
    if isinstance(value, (int, float)):
        try:
            seconds = value / 1000.0 if value > 10_000_000_000 else value
            return datetime.fromtimestamp(seconds)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{10,13}", text):
        try:
            number = int(text)
            seconds = number / 1000.0 if len(text) == 13 else number
            return datetime.fromtimestamp(seconds)
        except (OverflowError, OSError, ValueError):
            pass
    try:
        default = datetime(default_year or datetime.now().year, 1, 1)
        return _to_naive(date_parser.parse(text, default=default))
    except (ValueError, OverflowError, TypeError):
        return None


def normalize_level(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    text = str(value).strip().upper()
    if not text:
        return "UNKNOWN"
    text = LEVEL_ALIASES.get(text, text)
    return text if text in LEVEL_ORDER else "UNKNOWN"


def infer_level(message: str) -> str:
    text = (message or "").lower()
    if any(
        token in text
        for token in (
            "fatal",
            "panic",
            "segmentation fault",
            "oom-killer",
            "oom killer",
            "out of memory",
            "outofmemory",
        )
    ):
        return "CRITICAL"
    if any(
        token in text
        for token in (
            "error",
            "exception",
            "traceback",
            "failed",
            "failure",
            "refused",
            "unavailable",
            "denied",
            "crash",
            "deadlock",
            "5xx",
        )
    ):
        return "ERROR"
    if any(
        token in text
        for token in (
            "warn",
            "timeout",
            "timed out",
            "slow",
            "degraded",
            "retry",
            "retrying",
            "backlog",
            "throttl",
            "high latency",
        )
    ):
        return "WARN"
    return "INFO"


def _first_present(record: Dict[str, Any], keys: tuple) -> Any:
    key, value = _first_present_with_key(record, keys)
    return value


def _first_present_with_key(record: Dict[str, Any], keys: tuple) -> tuple:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return key, record[key]
    lowered = {str(key).lower(): key for key in record}
    for key in keys:
        actual = lowered.get(key.lower())
        if actual is not None and record[actual] not in (None, ""):
            return actual, record[actual]
    return None, None


def _flatten_metadata(record: Dict[str, Any], consumed: set) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    for key, value in record.items():
        if key in consumed:
            continue
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                metadata[f"{key}.{nested_key}"] = nested_value
        else:
            metadata[key] = value
    return metadata


def parse_txt_line(
    line: str,
    source_file: str = "<text>",
    line_number: int = 0,
    default_year: Optional[int] = None,
) -> LogEntry:
    raw = line.rstrip("\r\n")
    stripped = raw.strip()
    if not stripped:
        return LogEntry(
            raw_text=raw,
            source_file=source_file,
            line_number=line_number,
            message="",
        )

    for pattern in TXT_PATTERNS:
        match = pattern.match(stripped)
        if match:
            data = match.groupdict()
            message = data.get("msg", "")
            return LogEntry(
                raw_text=raw,
                timestamp=parse_timestamp(data.get("ts"), default_year),
                level=normalize_level(data.get("level")) or infer_level(message),
                service=(data.get("service") or "unknown").strip(),
                message=message.strip(),
                source_file=source_file,
                line_number=line_number,
            )

    match = SYSLOG_PATTERN.match(stripped)
    if match:
        data = match.groupdict()
        message = data.get("msg", "")
        return LogEntry(
            raw_text=raw,
            timestamp=parse_timestamp(data.get("ts"), default_year),
            level=normalize_level(infer_level(message)),
            service=(data.get("service") or "unknown").strip(),
            message=message.strip(),
            source_file=source_file,
            line_number=line_number,
        )

    return LogEntry(
        raw_text=raw,
        timestamp=None,
        level=infer_level(stripped),
        service="unknown",
        message=stripped,
        source_file=source_file,
        line_number=line_number,
    )


def parse_txt(text: str, source_file: str = "<text>") -> List[LogEntry]:
    entries: List[LogEntry] = []
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        entries.append(parse_txt_line(line, source_file, index))
    return entries


def _parse_json_record(
    record: Any,
    source_file: str,
    line_number: int,
    default_year: Optional[int] = None,
) -> Optional[LogEntry]:
    if isinstance(record, str):
        return parse_txt_line(record, source_file, line_number, default_year)
    if not isinstance(record, dict):
        return None

    consumed: set = set()
    ts_key, timestamp_value = _first_present_with_key(record, TIMESTAMP_KEYS)
    level_key, level_value = _first_present_with_key(record, LEVEL_KEYS)
    service_key, service_value = _first_present_with_key(record, SERVICE_KEYS)
    message_key, message_value = _first_present_with_key(record, MESSAGE_KEYS)
    consumed.update(
        key for key in (ts_key, level_key, service_key, message_key) if key is not None
    )

    if isinstance(message_value, (dict, list)):
        message_value = json.dumps(message_value, ensure_ascii=False)
    message = str(message_value) if message_value is not None else ""

    level = normalize_level(level_value)
    if level == "UNKNOWN":
        level = infer_level(message)

    raw = json.dumps(record, ensure_ascii=False)
    return LogEntry(
        raw_text=raw,
        timestamp=parse_timestamp(timestamp_value, default_year),
        level=level,
        service=str(service_value).strip() if service_value else "unknown",
        message=message,
        metadata=_flatten_metadata(record, consumed),
        source_file=source_file,
        line_number=line_number,
    )


def parse_json(text: str, source_file: str = "<text>") -> List[LogEntry]:
    try:
        records: Any = json.loads(text)
    except json.JSONDecodeError:
        entries: List[LogEntry] = []
        for index, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                entries.append(parse_txt_line(line, source_file, index))
                continue
            entry = _parse_json_record(record, source_file, index)
            if entry is not None:
                entries.append(entry)
        return entries

    if isinstance(records, dict):
        for key in ("logs", "events", "records", "entries", "data"):
            if isinstance(records.get(key), list):
                records = records[key]
                break
        else:
            records = [records]
    if not isinstance(records, list):
        records = [records]

    entries: List[LogEntry] = []
    for index, record in enumerate(records, start=1):
        entry = _parse_json_record(record, source_file, index)
        if entry is not None:
            entries.append(entry)
    return entries


def parse_csv(text: str, source_file: str = "<text>") -> List[LogEntry]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return parse_txt(text, source_file)

    entries: List[LogEntry] = []
    for index, row in enumerate(reader, start=2):
        record = {key: value for key, value in row.items() if key is not None}
        entry = _parse_json_record(record, source_file, index)
        if entry is not None:
            entries.append(entry)
    return entries


def detect_format(path: Path | str) -> LogFormat:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return LogFormat.JSON
    if suffix in {".csv", ".tsv"}:
        return LogFormat.CSV
    if suffix in {".txt", ".log", ".out", ".err"}:
        return LogFormat.TXT

    try:
        sample = path.read_text(encoding="utf-8", errors="replace")[:4096].lstrip()
    except OSError:
        return LogFormat.TXT
    if sample.startswith("{") or sample.startswith("["):
        return LogFormat.JSON
    first_line = sample.splitlines()[0] if sample.splitlines() else ""
    if "," in first_line and len(first_line.split(",")) >= 3:
        return LogFormat.CSV
    return LogFormat.TXT


def parse_text(
    text: str,
    log_format: LogFormat | str | None = None,
    source_file: str = "<text>",
) -> List[LogEntry]:
    if log_format is None:
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            log_format = LogFormat.JSON
        else:
            log_format = LogFormat.TXT
    if isinstance(log_format, str):
        log_format = LogFormat(log_format.lower())

    if log_format == LogFormat.JSON:
        return parse_json(text, source_file)
    if log_format == LogFormat.CSV:
        return parse_csv(text, source_file)
    return parse_txt(text, source_file)


def parse_file(path: Path | str, log_format: LogFormat | str | None = None) -> List[LogEntry]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    if log_format is None:
        log_format = detect_format(path)
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    return parse_text(text, log_format, source_file=str(path))

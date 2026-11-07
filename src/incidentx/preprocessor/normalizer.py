from __future__ import annotations

import re
from datetime import datetime
from functools import lru_cache
from typing import Dict, Iterable, List, Optional

from ..models import LogEntry

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
BEARER_RE = re.compile(r"(?i)\b(bearer|token|api[_-]?key)\s*[:=]?\s*[A-Za-z0-9._\-]{12,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WHITESPACE_RE = re.compile(r"\s+")


@lru_cache(maxsize=8192)
def clean_message(message: str) -> str:
    if not message:
        return ""
    cleaned = EMAIL_RE.sub("[redacted-email]", message)
    cleaned = BEARER_RE.sub(lambda match: f"{match.group(1)} [redacted]", cleaned)
    cleaned = CARD_RE.sub("[redacted-number]", cleaned)
    cleaned = IP_RE.sub("[redacted-ip]", cleaned)
    return WHITESPACE_RE.sub(" ", cleaned).strip()


def build_service_alias_map(service_names: Iterable[str]) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for name in service_names:
        normalized = name.strip().lower()
        aliases[normalized] = name
        aliases[normalized.replace("-", "_")] = name
        aliases[normalized.replace("_", "-")] = name
        aliases[normalized.replace("-", "")] = name
    return aliases


def standardize_service(service: str, aliases: Optional[Dict[str, str]] = None) -> str:
    if not service:
        return "unknown"
    cleaned = service.strip().strip("[]").lower()
    if aliases and cleaned in aliases:
        return aliases[cleaned]
    if aliases:
        for delimiter in ("_", "."):
            if cleaned.replace(delimiter, "-") in aliases:
                return aliases[cleaned.replace(delimiter, "-")]
    return cleaned.replace("_", "-").replace(".", "-")


def normalize_entries(
    entries: List[LogEntry],
    service_aliases: Optional[Dict[str, str]] = None,
    clean: bool = True,
    deduplicate: bool = True,
    fill_missing_timestamps: bool = True,
) -> List[LogEntry]:
    normalized: List[LogEntry] = []
    for entry in entries:
        entry.service = standardize_service(entry.service, service_aliases)
        if clean:
            entry.message = clean_message(entry.message)
        normalized.append(entry)

    if fill_missing_timestamps:
        last_seen = None
        for entry in normalized:
            if entry.timestamp is None:
                entry.timestamp = last_seen
            else:
                last_seen = entry.timestamp
        first_seen = next(
            (entry.timestamp for entry in normalized if entry.timestamp is not None), None
        )
        if first_seen is not None:
            for entry in normalized:
                if entry.timestamp is None:
                    entry.timestamp = first_seen

    normalized.sort(
        key=lambda entry: (
            entry.timestamp is None,
            entry.timestamp or datetime.min,
            entry.line_number,
        )
    )

    if not deduplicate:
        return normalized

    seen = set()
    unique: List[LogEntry] = []
    for entry in normalized:
        key = (entry.timestamp, entry.service, entry.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def segment_by_time_window(
    entries: List[LogEntry], window_minutes: int = 5
) -> List[List[LogEntry]]:
    if not entries:
        return []
    ordered = sorted(entries, key=lambda entry: entry.timestamp or entries[0].timestamp)
    segments: List[List[LogEntry]] = [[ordered[0]]]
    window_seconds = max(window_minutes, 1) * 60

    for entry in ordered[1:]:
        previous = segments[-1][-1]
        if (
            entry.timestamp is not None
            and previous.timestamp is not None
            and (entry.timestamp - previous.timestamp).total_seconds() <= window_seconds
        ):
            segments[-1].append(entry)
        else:
            segments.append([entry])
    return segments

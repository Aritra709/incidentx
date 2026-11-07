from __future__ import annotations

import csv
import io
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from ..ingestion.parser import parse_timestamp
from ..models import ChangeEvent, IncidentCluster
from ..preprocessor.normalizer import normalize_entries
from ..service_graph import ServiceGraph


STOPWORDS = {
    "the",
    "a",
    "an",
    "to",
    "from",
    "for",
    "of",
    "and",
    "or",
    "in",
    "on",
    "at",
    "by",
    "with",
    "after",
    "before",
    "this",
    "that",
    "is",
    "are",
    "was",
    "were",
    "be",
    "has",
    "have",
    "had",
    "we",
    "our",
    "it",
    "its",
    "as",
    "into",
    "than",
    "then",
    "max",
    "min",
    "new",
    "update",
    "updated",
}


@dataclass
class ChangeMatch:
    change: ChangeEvent
    confidence: float
    reason: str
    rank: int = 1


def _tokenize(text: str) -> set:
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return {word for word in words if len(word) > 2 and word not in STOPWORDS}


def _keyword_overlap(change: ChangeEvent, cluster: IncidentCluster) -> float:
    change_tokens = _tokenize(
        f"{change.description} {change.type} "
        + " ".join(str(value) for value in (change.metadata or {}).values())
    )
    error_tokens: set = set()
    for error in cluster.errors:
        error_tokens |= _tokenize(error.log_entry.message)
        error_tokens |= _tokenize(error.category.replace("_", " "))
    if not change_tokens or not error_tokens:
        return 0.0
    overlap = change_tokens & error_tokens
    return min(len(overlap) / max(len(change_tokens), 4), 1.0)


def _coerce_change(record: Dict[str, Any], index: int) -> Optional[ChangeEvent]:
    if not isinstance(record, dict):
        return None
    timestamp = parse_timestamp(
        record.get("timestamp")
        or record.get("time")
        or record.get("ts")
        or record.get("@timestamp")
    )
    if timestamp is None:
        return None
    change_id = str(
        record.get("id")
        or record.get("change_id")
        or f"chg-{timestamp:%Y%m%d%H%M%S}-{index:03d}"
    )
    change_type = str(record.get("type") or record.get("kind") or "other").lower()
    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {
            key: value
            for key, value in record.items()
            if key
            not in {
                "id",
                "change_id",
                "timestamp",
                "time",
                "ts",
                "@timestamp",
                "type",
                "kind",
                "service",
                "description",
                "author",
                "environment",
                "rollback",
                "metadata",
            }
        }
    return ChangeEvent(
        id=change_id,
        timestamp=timestamp,
        type=change_type,
        service=str(
            record.get("service")
            or record.get("service_name")
            or record.get("component")
            or "unknown"
        ).strip(),
        description=str(
            record.get("description") or record.get("summary") or record.get("message") or ""
        ).strip(),
        author=str(record.get("author") or record.get("user") or record.get("by") or "").strip(),
        environment=str(record.get("environment") or record.get("env") or "production").strip(),
        rollback=(
            str(record.get("rollback")).strip()
            if record.get("rollback") not in (None, "")
            else None
        ),
        metadata=metadata,
    )


def parse_changes_text(
    text: str,
    source_type: str = "yaml",
    service_aliases: Optional[Dict[str, str]] = None,
) -> List[ChangeEvent]:
    records: Any = None
    if source_type == "json":
        try:
            records = json.loads(text)
        except json.JSONDecodeError:
            records = []
            for line in text.splitlines():
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    elif source_type == "csv":
        records = list(csv.DictReader(io.StringIO(text)))
    else:
        try:
            loaded = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            loaded = {}
        if isinstance(loaded, dict):
            records = loaded.get("changes", loaded.get("events", []))
        else:
            records = loaded

    if not isinstance(records, list):
        records = [records] if records else []

    changes: List[ChangeEvent] = []
    for index, record in enumerate(records, start=1):
        change = _coerce_change(record, index)
        if change is None:
            continue
        if service_aliases and change.service.lower() in service_aliases:
            change.service = service_aliases[change.service.lower()]
        changes.append(change)
    return changes


def load_changes(path: Path | str) -> List[ChangeEvent]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Changes file not found: {path}")
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl"}:
        source_type = "json"
    elif suffix in {".csv", ".tsv"}:
        source_type = "csv"
    else:
        source_type = "yaml"
    return parse_changes_text(path.read_text(encoding="utf-8-sig"), source_type)


def find_related_change(
    cluster: IncidentCluster,
    changes: Iterable[ChangeEvent],
    service_graph: Optional[ServiceGraph] = None,
    lookback_minutes: int = 45,
    minimum_confidence: float = 0.45,
) -> List[ChangeMatch]:
    graph = service_graph or ServiceGraph()
    lookback = timedelta(minutes=lookback_minutes)
    window_end = cluster.start + timedelta(minutes=2)
    matches: List[ChangeMatch] = []

    for change in changes:
        if change.timestamp > window_end or change.timestamp < cluster.start - lookback:
            continue
        delta_minutes = (cluster.start - change.timestamp).total_seconds() / 60.0
        if delta_minutes >= 0:
            time_score = max(0.0, 1.0 - delta_minutes / lookback_minutes)
            time_reason = f"made {delta_minutes:.0f} min before the first error"
        else:
            time_score = 0.25
            time_reason = f"made {abs(delta_minutes):.0f} min after the first error"

        service_relevance = graph.change_relevance(change.service, cluster.affected_services)
        if service_relevance >= 0.95:
            service_reason = f"touches affected service {change.service}"
        elif service_relevance >= 0.6:
            service_reason = f"touches a dependency of an affected service ({change.service})"
        elif service_relevance >= 0.35:
            service_reason = f"touches a downstream service ({change.service})"
        else:
            service_reason = f"does not touch the affected services ({change.service})"

        type_weights = {
            "deploy": 1.0,
            "config": 0.9,
            "migration": 0.8,
            "scale": 0.6,
            "security": 0.6,
            "other": 0.4,
        }
        type_score = type_weights.get(str(change.type).lower(), 0.4)
        keyword_score = _keyword_overlap(change, cluster)

        confidence = (
            0.45 * time_score
            + 0.30 * service_relevance
            + 0.10 * type_score
            + 0.15 * keyword_score
        )
        confidence = round(min(confidence, 0.98), 3)
        if confidence < minimum_confidence:
            continue

        reason = (
            f"{change.type} on {change.service} {time_reason}; {service_reason}; "
            f"keyword overlap with the errors is {keyword_score:.0%}."
        )
        matches.append(
            ChangeMatch(change=change, confidence=confidence, reason=reason)
        )

    matches.sort(key=lambda match: (-match.confidence, match.change.timestamp))
    for rank, match in enumerate(matches, start=1):
        match.rank = rank
    return matches

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from ..config import DEFAULT_DATA_DIR
from ..models import IncidentCluster, IncidentReport, SimilarIncident


TOKEN_RE = re.compile(r"[a-z0-9]+")
MEMORY_STOPWORDS = {
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
}


def _tokens(text: str) -> Set[str]:
    return {
        token
        for token in TOKEN_RE.findall((text or "").lower())
        if token not in MEMORY_STOPWORDS and len(token) > 2
    }


def _jaccard(left: Set[str], right: Set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


class MemoryStore:
    """Small JSON incident memory. Says "this looks like the one from last week"."""

    DEFAULT_PATH = DEFAULT_DATA_DIR / "runtime" / "memory.json"
    SEED_PATH = DEFAULT_DATA_DIR / "seed_memory.json"

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else self.DEFAULT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() and self.SEED_PATH.exists():
            self._write(self._read(self.SEED_PATH))

    def _read(self, path: Path) -> List[Dict[str, Any]]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return data if isinstance(data, list) else data.get("incidents", [])

    def _write(self, entries: List[Dict[str, Any]]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(entries, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def load(self) -> List[Dict[str, Any]]:
        return self._read(self.path) if self.path.exists() else []

    def find_similar(
        self, cluster: IncidentCluster, limit: int = 3, minimum: float = 0.3
    ) -> List[SimilarIncident]:
        current_categories = set(cluster.categories)
        current_services = set(cluster.affected_services)
        current_tokens: Set[str] = set()
        for error in cluster.errors:
            current_tokens |= _tokens(error.log_entry.message)

        matches: List[SimilarIncident] = []
        for entry in self.load():
            if entry.get("status") == "open":
                continue
            entry_categories = set(entry.get("categories", []))
            entry_services = set(entry.get("services", []))
            entry_tokens: Set[str] = set()
            for signature in entry.get("signatures", []):
                entry_tokens |= _tokens(signature)

            category_score = _jaccard(current_categories, entry_categories)
            signature_score = _jaccard(current_tokens, entry_tokens)
            service_score = _jaccard(current_services, entry_services)
            similarity = (
                0.45 * category_score
                + 0.35 * signature_score
                + 0.20 * service_score
            )
            if similarity < minimum:
                continue
            matches.append(
                SimilarIncident(
                    incident_id=str(entry.get("incident_id", "unknown")),
                    timestamp=entry.get("timestamp"),
                    title=str(entry.get("title", "")),
                    similarity=round(similarity, 3),
                    severity=str(entry.get("severity", "")),
                    root_cause=str(entry.get("root_cause", "")),
                    resolution=[str(step) for step in entry.get("resolution", [])],
                )
            )
        matches.sort(key=lambda match: match.similarity, reverse=True)
        return matches[:limit]

    def save_report(
        self,
        report: IncidentReport,
        resolution: Optional[Iterable[str]] = None,
        status: str = "resolved",
    ) -> bool:
        entries = self.load()
        if any(
            entry.get("incident_id") == report.id and entry.get("status") == status
            for entry in entries
        ):
            return False
        resolution_steps = list(resolution or [])
        if not resolution_steps:
            resolution_steps = [
                action.action
                for action in report.remediation.by_phase("resolution")
            ]
        entry = {
            "incident_id": report.id,
            "timestamp": report.cluster.start.isoformat(),
            "title": report.title,
            "signatures": sorted(
                {error.signature for error in report.cluster.errors if error.signature}
            ),
            "categories": report.cluster.categories,
            "services": report.cluster.affected_services,
            "severity": report.severity.level,
            "root_cause": report.root_cause.reasoning,
            "resolution": resolution_steps,
            "status": status,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
        }
        entries = [
            existing
            for existing in entries
            if not (
                existing.get("incident_id") == report.id
                and existing.get("status") == status
            )
        ]
        entries.append(entry)
        self._write(entries)
        return True

    def resolve(
        self, incident_id: str, resolution: Optional[Iterable[str]] = None
    ) -> bool:
        entries = self.load()
        changed = False
        for entry in entries:
            if entry.get("incident_id") != incident_id:
                continue
            entry["status"] = "resolved"
            if resolution:
                entry["resolution"] = list(resolution)
            changed = True
        if changed:
            self._write(entries)
        return changed

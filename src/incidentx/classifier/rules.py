from __future__ import annotations

import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..config import DEFAULT_CONFIG_DIR, load_config
from ..models import ErrorEvent, LogEntry

UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
HEX_RE = re.compile(r"\b(?:0x)?[0-9a-f]{8,}\b", re.IGNORECASE)
NUMBER_RE = re.compile(r"\b\d+(?:[.,]\d+)?\b")
QUOTED_RE = re.compile(r"(['\"])(?:(?!\1).){1,120}\1")
NON_WORD_RE = re.compile(r"[^a-z0-9]+")


def build_signature(message: str, limit: int = 180) -> str:
    text = (message or "").lower()
    text = UUID_RE.sub("<id>", text)
    text = HEX_RE.sub("<id>", text)
    text = NUMBER_RE.sub("<n>", text)
    text = QUOTED_RE.sub("<value>", text)
    text = NON_WORD_RE.sub(" ", text)
    signature = " ".join(text.split())
    return signature[:limit]


class RuleBasedClassifier:
    """Fast, transparent, regex-based error detector."""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        patterns: Optional[Dict[str, dict]] = None,
    ):
        if patterns is None:
            raw = load_config("error_patterns.yaml", config_dir or DEFAULT_CONFIG_DIR)
            patterns = raw.get("patterns", {})
        self.patterns = patterns
        self.compiled: Dict[str, dict] = {}
        for category, spec in self.patterns.items():
            regexes = [re.compile(pattern, re.IGNORECASE) for pattern in spec.get("regex", [])]
            self.compiled[category] = {
                "regex": regexes,
                "levels": {level.upper() for level in spec.get("levels", [])},
                "services": spec.get("services", ["*"]),
                "family": spec.get("family", "UNKNOWN"),
                "description": spec.get("description", ""),
            }

    def classify(self, entry: LogEntry) -> Optional[ErrorEvent]:
        best: Optional[Tuple[float, str, str]] = None
        best_reason = ""

        for category, spec in self.compiled.items():
            if not spec["levels"]:
                level_ok = True
            else:
                level_ok = entry.level in spec["levels"]
            service_ok = any(
                fnmatch(entry.service, pattern) or pattern == "*"
                for pattern in spec["services"]
            )
            for regex in spec["regex"]:
                match = regex.search(entry.message)
                if not match:
                    continue
                score = 0.68
                reasons = [f"matched '{match.group(0)}'"]
                if level_ok:
                    score += 0.10
                    reasons.append(f"level {entry.level} fits")
                if service_ok:
                    score += 0.10
                    reasons.append(f"service {entry.service} is in scope")
                specificity = len(match.group(0)) / max(len(entry.message), 1)
                score += min(specificity, 0.10)
                score = min(score, 0.98)
                if best is None or score > best[0]:
                    best = (score, category, match.group(0))
                    best_reason = "; ".join(reasons)

        if best is None:
            if entry.is_error:
                return ErrorEvent(
                    log_entry=entry,
                    category="UNKNOWN",
                    family="UNKNOWN",
                    signature=build_signature(entry.message),
                    confidence=0.25,
                    matched_pattern=None,
                    source="heuristic",
                    reason="No known signature matched; marked for LLM review.",
                )
            return None

        score, category, matched = best
        family = self.compiled[category]["family"]
        return ErrorEvent(
            log_entry=entry,
            category=category,
            family=family,
            signature=build_signature(entry.message),
            confidence=round(score, 3),
            matched_pattern=matched,
            source="rules",
            reason=best_reason,
        )

    def detect_errors(self, entries: List[LogEntry]) -> List[ErrorEvent]:
        events: List[ErrorEvent] = []
        for entry in entries:
            event = self.classify(entry)
            if event is not None:
                events.append(event)
        return events

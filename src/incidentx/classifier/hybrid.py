from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import ErrorEvent, LogEntry
from .llm import LLMReasoner
from .rules import RuleBasedClassifier


class HybridClassifier:
    """Rules first; LLM only for unknown error signatures."""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        llm: Optional[LLMReasoner] = None,
        use_llm: bool = True,
    ):
        self.rules = RuleBasedClassifier(config_dir)
        self.llm = llm if llm is not None else LLMReasoner()
        self.use_llm = use_llm
        self.categories = list(self.rules.patterns.keys())
        self.families: Dict[str, str] = {
            category: spec.get("family", "UNKNOWN")
            for category, spec in self.rules.patterns.items()
        }

    def detect_errors(self, entries: List[LogEntry]) -> Tuple[List[ErrorEvent], List[str]]:
        warnings: List[str] = []
        events = self.rules.detect_errors(entries)
        if not (self.use_llm and self.llm.available):
            return events, warnings

        allowed = [category for category in self.categories if category != "UNKNOWN"]
        unknown_count = 0
        for event in events:
            if event.category != "UNKNOWN":
                continue
            if unknown_count >= 8:
                warnings.append("LLM classification capped at 8 unknown signatures.")
                break
            unknown_count += 1
            result = self.llm.classify_error(
                event.log_entry.message,
                event.log_entry.level,
                event.log_entry.service,
                allowed,
            )
            if result is None:
                continue
            event.category = result["category"]
            event.family = result.get("family") or self.families.get(event.category, "UNKNOWN")
            event.confidence = result["confidence"]
            event.source = "llm"
            event.reason = result.get("reason", "")
        return events, warnings

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import DEFAULT_KB_DIR, read_yaml


class KnowledgeBase:
    def __init__(self, kb_dir: Optional[Path] = None):
        self.kb_dir = Path(kb_dir) if kb_dir else DEFAULT_KB_DIR
        self.remediation_rules: Dict[str, Any] = read_yaml(
            self.kb_dir / "remediation_rules.yaml"
        ).get("rules", {})
        self.error_catalog: Dict[str, Any] = read_yaml(
            self.kb_dir / "error_catalog.yaml"
        ).get("errors", {})

    def get_remediation(self, category: str) -> Dict[str, Any]:
        return self.remediation_rules.get(category) or self.remediation_rules.get(
            "DEFAULT", {}
        )

    def get_error_info(self, category: str) -> Dict[str, Any]:
        return self.error_catalog.get(category) or self.error_catalog.get("UNKNOWN", {})

    def get_runbook(self, name: str) -> str:
        if not name:
            return ""
        path = self.kb_dir / "runbooks" / name
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    def error_plain_name(self, category: str) -> str:
        return str(self.get_error_info(category).get("plain_name", category.replace("_", " ").lower()))

    def customer_symptom(self, category: str) -> str:
        return str(
            self.get_error_info(category).get(
                "customer_symptom", "some actions may fail"
            )
        )

    def prevention_for(self, categories: List[str]) -> List[str]:
        seen: List[str] = []
        for category in categories:
            for item in self.get_remediation(category).get("prevention", []) or []:
                if item not in seen:
                    seen.append(str(item))
        return seen

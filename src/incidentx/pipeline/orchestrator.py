from __future__ import annotations

import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..changes.tracker import load_changes, parse_changes_text
from ..classifier.hybrid import HybridClassifier
from ..config import (
    DEFAULT_CONFIG_DIR,
    DEFAULT_DATA_DIR,
    DEFAULT_KB_DIR,
    DEFAULT_REPORT_DIR,
    load_config,
)
from ..correlator.engine import CorrelationEngine
from ..ingestion.parser import parse_file, parse_text
from ..knowledge_base.loader import KnowledgeBase
from ..knowledge_base.remediation import RemediationEngine
from ..memory.store import MemoryStore
from ..models import AnalysisResult, IncidentReport, LogFormat, RemediationPlan
from ..preprocessor.normalizer import build_service_alias_map, normalize_entries
from ..reporter.generator import IncidentReporter
from ..service_graph import ServiceGraph
from ..severity.assessor import SeverityAssessor


class IncidentXPipeline:
    """End-to-end: logs + changes -> incident reports."""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        knowledge_base_dir: Optional[Path] = None,
        report_dir: Optional[Path] = None,
        memory_path: Optional[Path] = None,
    ):
        self.config_dir = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
        self.kb_dir = Path(knowledge_base_dir) if knowledge_base_dir else DEFAULT_KB_DIR
        self.report_dir = Path(report_dir) if report_dir else DEFAULT_REPORT_DIR

        catalog = load_config("service_catalog.yaml", self.config_dir).get("services", {})
        self.graph = ServiceGraph(catalog)
        self.business_context = load_config("business_context.yaml", self.config_dir)
        self.aliases = build_service_alias_map(self.graph.catalog.keys())

        self.classifier = HybridClassifier(self.config_dir)
        self.correlator = CorrelationEngine(self.config_dir, self.graph)
        self.assessor = SeverityAssessor(self.config_dir, self.graph, self.business_context)
        self.kb = KnowledgeBase(self.kb_dir)
        self.remediator = RemediationEngine(self.kb)
        self.reporter = IncidentReporter(self.kb, self.graph, self.business_context)
        self.memory = MemoryStore(memory_path)
        self.llm = self.classifier.llm

    def _load_logs(
        self,
        logs_path: Optional[Path | str],
        log_text: Optional[str],
        log_format: Optional[LogFormat | str],
    ):
        if log_text is not None and log_text.strip():
            entries = parse_text(log_text, log_format, "<inline>")
            source = "inline text"
        elif logs_path:
            entries = parse_file(logs_path, log_format)
            source = str(logs_path)
        else:
            raise ValueError("Provide logs_path or log_text.")
        return entries, source

    def _load_changes(
        self,
        changes_path: Optional[Path | str],
        changes_text: Optional[str],
    ):
        if changes_text is not None and changes_text.strip():
            text = changes_text.lstrip()
            first_line = text.splitlines()[0].lower()
            if text.startswith("[") or text.startswith("{"):
                changes = parse_changes_text(changes_text, "json", self.aliases)
            elif "," in first_line and "timestamp" in first_line:
                changes = parse_changes_text(changes_text, "csv", self.aliases)
            else:
                changes = parse_changes_text(changes_text, "yaml", self.aliases)
            return changes, "inline text"
        if changes_path:
            return load_changes(changes_path), str(changes_path)
        return [], ""

    def analyze(
        self,
        logs_path: Optional[Path | str] = None,
        log_text: Optional[str] = None,
        changes_path: Optional[Path | str] = None,
        changes_text: Optional[str] = None,
        log_format: Optional[LogFormat | str] = None,
        time_window_minutes: int = 5,
        lookback_minutes: int = 45,
        use_llm: bool = True,
        persist_reports: bool = False,
        output_dir: Optional[Path | str] = None,
        remember: bool = False,
        include_remediation: bool = True,
    ) -> AnalysisResult:
        started = time.perf_counter()
        warnings: List[str] = []

        entries, source = self._load_logs(logs_path, log_text, log_format)
        if not entries:
            return AnalysisResult(
                logs_processed=0,
                processing_time_ms=(time.perf_counter() - started) * 1000,
                llm_available=self.llm.available,
                business_profile=self._business_profile(),
                warnings=["No log lines were found."],
            )

        entries = normalize_entries(entries, self.aliases)
        if all(entry.timestamp is None for entry in entries):
            base = datetime.now().replace(microsecond=0)
            for index, entry in enumerate(entries):
                entry.timestamp = base + timedelta(seconds=index)
            warnings.append(
                "No timestamps were found in the logs; arrival order was used as a timeline."
            )

        self.classifier.use_llm = use_llm
        errors, classifier_warnings = self.classifier.detect_errors(entries)
        warnings.extend(classifier_warnings)

        changes, changes_source = self._load_changes(changes_path, changes_text)
        clusters = self.correlator.correlate_errors(errors, time_window_minutes)
        reports: List[IncidentReport] = []

        for cluster in clusters:
            change_matches = self.correlator.link_changes(
                cluster, changes, lookback_minutes
            )
            root_cause = self.correlator.identify_root_cause(cluster, change_matches)
            cluster.root_cause = root_cause
            severity = self.assessor.assess(cluster)
            remediation = (
                self.remediator.build_plan(cluster, severity, root_cause)
                if include_remediation
                else RemediationPlan()
            )
            similar = self.memory.find_similar(cluster)

            llm_explanation = ""
            if use_llm and self.llm.available:
                llm_explanation = self.llm.explain_incident(
                    self._llm_context(cluster, severity, root_cause)
                ) or ""

            report = self.reporter.build(
                cluster=cluster,
                severity=severity,
                root_cause=root_cause,
                remediation=remediation,
                similar=similar,
                llm_explanation=llm_explanation,
                llm_used=bool(llm_explanation),
            )
            reports.append(report)

        reports.sort(key=lambda report: (-report.severity.score, report.cluster.start))

        if persist_reports:
            self.write_reports(reports, output_dir)
        if remember:
            for report in reports:
                self.memory.save_report(report)

        elapsed_ms = (time.perf_counter() - started) * 1000
        return AnalysisResult(
            incidents=reports,
            logs_processed=len(entries),
            errors_detected=len(errors),
            changes_loaded=len(changes),
            processing_time_ms=round(elapsed_ms, 1),
            llm_available=self.llm.available,
            business_profile=self._business_profile(),
            warnings=warnings,
        )

    def _business_profile(self) -> Dict[str, Any]:
        return {
            "company": self.business_context.get("company", ""),
            "description": self.business_context.get("description", ""),
            "revenue_services": self.business_context.get("revenue_services", []),
            "critical_services": self.business_context.get("critical_services", []),
            "revenue_windows": [
                {
                    "name": window.get("name"),
                    "days": window.get("days"),
                    "start": window.get("start"),
                    "end": window.get("end"),
                    "description": window.get("description"),
                }
                for window in self.business_context.get("revenue_windows", [])
            ],
        }

    def _llm_context(
        self,
        cluster,
        severity,
        root_cause,
    ) -> Dict[str, Any]:
        change = cluster.suspected_change
        return {
            "incident_id": cluster.id,
            "time_range_local": f"{cluster.start} to {cluster.end}",
            "affected_services": cluster.affected_services,
            "severity": {"level": severity.level, "score": severity.score},
            "business_window": severity.revenue_window,
            "root_cause": {
                "category": root_cause.primary_category,
                "service": root_cause.primary_service,
                "confidence": root_cause.confidence,
                "reasoning": root_cause.reasoning,
            },
            "suspected_change": (
                {
                    "id": change.id,
                    "time": str(change.timestamp),
                    "type": change.type,
                    "service": change.service,
                    "description": change.description,
                    "rollback": change.rollback,
                }
                if change
                else None
            ),
            "top_errors": [
                {
                    "time": str(error.timestamp),
                    "service": error.service,
                    "level": error.log_entry.level,
                    "category": error.category,
                    "message": error.log_entry.message,
                }
                for error in cluster.errors[:10]
            ],
        }

    def write_reports(
        self,
        reports: List[IncidentReport],
        output_dir: Optional[Path | str] = None,
    ) -> List[Path]:
        directory = Path(output_dir) if output_dir else self.report_dir
        directory.mkdir(parents=True, exist_ok=True)
        written: List[Path] = []
        for report in reports:
            markdown_path = directory / f"{report.id}.md"
            json_path = directory / f"{report.id}.json"
            html_path = directory / f"{report.id}.html"
            markdown_path.write_text(report.engineer_markdown, encoding="utf-8")
            json_path.write_text(
                self.reporter.export_json(report), encoding="utf-8"
            )
            html_path.write_text(self.reporter.export_html(report), encoding="utf-8")
            written.extend([markdown_path, json_path, html_path])
        return written

    @staticmethod
    def demo_paths() -> Dict[str, Path]:
        demo = DEFAULT_DATA_DIR / "demo"
        return {
            "logs": demo / "app.log",
            "changes": demo / "changes.yaml",
        }

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    FATAL = "FATAL"
    UNKNOWN = "UNKNOWN"


class LogFormat(str, Enum):
    TXT = "txt"
    JSON = "json"
    CSV = "csv"


class ChangeType(str, Enum):
    DEPLOY = "deploy"
    CONFIG = "config"
    SCALE = "scale"
    MIGRATION = "migration"
    SECURITY = "security"
    OTHER = "other"


class PatternType(str, Enum):
    TEMPORAL = "temporal"
    SERVICE = "service"
    CAUSAL = "causal"
    TRACE = "trace"


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


LEVEL_ORDER = {
    "DEBUG": 0,
    "INFO": 1,
    "WARN": 2,
    "ERROR": 3,
    "CRITICAL": 4,
    "FATAL": 5,
    "UNKNOWN": -1,
}

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class LogEntry(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    raw_text: str = ""
    timestamp: Optional[datetime] = None
    level: str = LogLevel.UNKNOWN.value
    service: str = "unknown"
    message: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    source_file: str = ""
    line_number: int = 0

    @property
    def is_error(self) -> bool:
        return LEVEL_ORDER.get(self.level, -1) >= LEVEL_ORDER["ERROR"]

    @property
    def is_actionable(self) -> bool:
        return LEVEL_ORDER.get(self.level, -1) >= LEVEL_ORDER["WARN"]


class ErrorEvent(BaseModel):
    log_entry: LogEntry
    category: str
    family: str = "UNKNOWN"
    signature: str = ""
    confidence: float = 0.0
    matched_pattern: Optional[str] = None
    source: str = "rules"
    reason: str = ""

    @property
    def timestamp(self) -> Optional[datetime]:
        return self.log_entry.timestamp

    @property
    def service(self) -> str:
        return self.log_entry.service


class ChangeEvent(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str
    timestamp: datetime
    type: str = ChangeType.OTHER.value
    service: str = "unknown"
    description: str = ""
    author: str = ""
    environment: str = "production"
    rollback: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SimilarIncident(BaseModel):
    incident_id: str
    timestamp: Optional[datetime] = None
    title: str = ""
    similarity: float = 0.0
    severity: str = ""
    root_cause: str = ""
    resolution: List[str] = Field(default_factory=list)


class RootCauseAnalysis(BaseModel):
    primary_category: str
    primary_service: str
    confidence: float = 0.0
    reasoning: str = ""
    suspected_change_id: Optional[str] = None
    change_confidence: float = 0.0
    change_reason: str = ""
    contributing_categories: List[str] = Field(default_factory=list)
    contributing_services: List[str] = Field(default_factory=list)


class LLMHypothesis(BaseModel):
    hypothesis: str
    confidence: float = 0.0
    supporting_evidence: List[str] = Field(default_factory=list)
    conflicting_evidence: List[str] = Field(default_factory=list)
    validation: str = ""


class LLMReasoning(BaseModel):
    summary: str = ""
    causal_chain: List[str] = Field(default_factory=list)
    hypotheses: List[LLMHypothesis] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    recommended_checks: List[str] = Field(default_factory=list)
    operator_briefing: str = ""



class IncidentCluster(BaseModel):
    id: str
    errors: List[ErrorEvent] = Field(default_factory=list)
    start: datetime
    end: datetime
    affected_services: List[str] = Field(default_factory=list)
    pattern_type: str = PatternType.TEMPORAL.value
    root_cause: Optional[RootCauseAnalysis] = None
    suspected_change: Optional[ChangeEvent] = None
    similar_incidents: List[SimilarIncident] = Field(default_factory=list)

    @property
    def duration_minutes(self) -> float:
        seconds = (self.end - self.start).total_seconds()
        return max(seconds / 60.0, 1.0 / 60.0)

    @property
    def error_rate_per_minute(self) -> float:
        return len(self.errors) / self.duration_minutes

    @property
    def categories(self) -> List[str]:
        seen: List[str] = []
        for error in self.errors:
            if error.category not in seen:
                seen.append(error.category)
        return seen


class SeverityAssessment(BaseModel):
    level: str = SeverityLevel.LOW.value
    score: float = 0.0
    factors: Dict[str, float] = Field(default_factory=dict)
    justification: str = ""
    business_summary: str = ""
    revenue_window: Optional[str] = None
    baseline_level: str = SeverityLevel.LOW.value
    baseline_score: float = 0.0
    boosted: bool = False


class RemediationAction(BaseModel):
    id: str
    action: str
    phase: str = "immediate"
    automated: bool = False
    requires_approval: bool = False
    command: Optional[str] = None
    status: str = "proposed"
    dry_run_output: Optional[str] = None
    approved_by: Optional[str] = None
    note: Optional[str] = None


class RemediationPlan(BaseModel):
    actions: List[RemediationAction] = Field(default_factory=list)
    prevention: List[str] = Field(default_factory=list)
    runbook: str = ""
    escalation: str = ""
    proposed_rollback: Optional[str] = None

    def by_phase(self, phase: str) -> List[RemediationAction]:
        return [action for action in self.actions if action.phase == phase]


class PlainEnglishSummary(BaseModel):
    headline: str = ""
    what_broken: str = ""
    who_affected: str = ""
    what_we_are_doing: str = ""
    what_you_can_do: str = ""
    when: str = ""


class IncidentReport(BaseModel):
    id: str
    title: str
    severity: SeverityAssessment
    cluster: IncidentCluster
    root_cause: RootCauseAnalysis
    remediation: RemediationPlan
    plain_english: PlainEnglishSummary
    customer_status_update: str = ""
    engineer_markdown: str = ""
    llm_explanation: str = ""
    llm_reasoning: Optional[LLMReasoning] = None
    generated_at: datetime = Field(default_factory=datetime.now)
    llm_used: bool = False


class AnalysisResult(BaseModel):
    incidents: List[IncidentReport] = Field(default_factory=list)
    logs_processed: int = 0
    errors_detected: int = 0
    changes_loaded: int = 0
    processing_time_ms: float = 0.0
    llm_available: bool = False
    business_profile: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)

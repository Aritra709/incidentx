from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class AnalyzeOptions(BaseModel):
    time_window_minutes: int = Field(5, ge=1, le=60)
    lookback_minutes: int = Field(45, ge=1, le=1440)
    use_llm: bool = True
    include_remediation: bool = True


class AnalyzeRequest(BaseModel):
    logs: str = Field(description="Raw log text (TXT, JSON, or CSV).")
    format: Optional[Literal["txt", "json", "csv"]] = None
    changes: Optional[str] = Field(
        default=None, description="Optional changelog text (YAML or JSON)."
    )
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)


class SeverityResponse(BaseModel):
    level: str
    score: float
    baseline_level: str
    baseline_score: float
    revenue_window: Optional[str] = None
    boosted: bool = False
    justification: str = ""
    business_summary: str = ""
    factors: Dict[str, float] = Field(default_factory=dict)


class RootCauseResponse(BaseModel):
    primary_category: str
    primary_service: str
    confidence: float
    reasoning: str
    linkage_confidence: float = 0.0
    contributing_categories: List[str] = Field(default_factory=list)


class ChangeResponse(BaseModel):
    id: str
    timestamp: str
    type: str
    service: str
    description: str
    author: str = ""
    rollback: Optional[str] = None


class TimelineEntry(BaseModel):
    time: str
    service: str
    type: str
    message: str


class RemediationActionResponse(BaseModel):
    id: str
    phase: str
    action: str
    command: Optional[str] = None
    automated: bool = False
    requires_approval: bool = False
    status: str = "proposed"


class SimilarIncidentResponse(BaseModel):
    incident_id: str
    title: str
    similarity: float
    severity: str
    root_cause: str = ""
    resolution: List[str] = Field(default_factory=list)


class IncidentResponse(BaseModel):
    id: str
    title: str
    summary: str
    severity: SeverityResponse
    root_cause: RootCauseResponse
    suspected_change: Optional[ChangeResponse] = None
    affected_services: List[str] = Field(default_factory=list)
    timeline: List[TimelineEntry] = Field(default_factory=list)
    remediation: List[RemediationActionResponse] = Field(default_factory=list)
    prevention: List[str] = Field(default_factory=list)
    similar_incidents: List[SimilarIncidentResponse] = Field(default_factory=list)
    plain_english: Dict[str, Any] = Field(default_factory=dict)
    customer_status_update: str = ""
    report_markdown: str = ""


class AnalyzeResponse(BaseModel):
    incidents: List[IncidentResponse] = Field(default_factory=list)
    logs_processed: int = 0
    errors_detected: int = 0
    changes_loaded: int = 0
    processing_time_ms: float = 0.0
    llm_available: bool = False
    warnings: List[str] = Field(default_factory=list)

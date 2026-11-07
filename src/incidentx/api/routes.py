from __future__ import annotations

from typing import Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from ..pipeline.orchestrator import IncidentXPipeline
from .schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ChangeResponse,
    IncidentResponse,
    RemediationActionResponse,
    RootCauseResponse,
    SeverityResponse,
    SimilarIncidentResponse,
    TimelineEntry,
)

app = FastAPI(
    title="IncidentX API",
    version=__version__,
    description=(
        "Autonomous IT incident response for small teams with no on-call engineer. "
        "Read-only: remediation commands are proposals, never executions."
    ),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_pipeline: IncidentXPipeline | None = None


def pipeline() -> IncidentXPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = IncidentXPipeline()
    return _pipeline


def _to_incident(report) -> IncidentResponse:
    cluster = report.cluster
    root = report.root_cause
    severity = report.severity
    change = cluster.suspected_change

    timeline: List[TimelineEntry] = []
    for error in cluster.errors:
        if error.timestamp is None:
            continue
        timeline.append(
            TimelineEntry(
                time=error.timestamp.isoformat(),
                service=error.service,
                type=error.category,
                message=error.log_entry.message,
            )
        )
    if change:
        timeline.append(
            TimelineEntry(
                time=change.timestamp.isoformat(),
                service=change.service,
                type=f"CHANGE ({change.type})",
                message=change.description,
            )
        )
    timeline.sort(key=lambda entry: entry.time)

    remediation = [
        RemediationActionResponse(
            id=action.id,
            phase=action.phase,
            action=action.action,
            command=action.command,
            automated=action.automated,
            requires_approval=action.requires_approval,
            status=action.status,
        )
        for action in report.remediation.actions
    ]
    similar = [
        SimilarIncidentResponse(
            incident_id=match.incident_id,
            title=match.title,
            similarity=match.similarity,
            severity=match.severity,
            root_cause=match.root_cause,
            resolution=match.resolution,
        )
        for match in cluster.similar_incidents
    ]
    return IncidentResponse(
        id=report.id,
        title=report.title,
        summary=severity.business_summary,
        severity=SeverityResponse(
            level=severity.level,
            score=severity.score,
            baseline_level=severity.baseline_level,
            baseline_score=severity.baseline_score,
            revenue_window=severity.revenue_window,
            boosted=severity.boosted,
            justification=severity.justification,
            business_summary=severity.business_summary,
            factors=severity.factors,
        ),
        root_cause=RootCauseResponse(
            primary_category=root.primary_category,
            primary_service=root.primary_service,
            confidence=root.confidence,
            reasoning=root.reasoning,
            linkage_confidence=root.change_confidence,
            contributing_categories=root.contributing_categories,
        ),
        suspected_change=(
            ChangeResponse(
                id=change.id,
                timestamp=change.timestamp.isoformat(),
                type=change.type,
                service=change.service,
                description=change.description,
                author=change.author,
                rollback=change.rollback,
            )
            if change
            else None
        ),
        affected_services=cluster.affected_services,
        timeline=timeline,
        remediation=remediation,
        prevention=report.remediation.prevention,
        similar_incidents=similar,
        plain_english=report.plain_english.model_dump(mode="json"),
        customer_status_update=report.customer_status_update,
        report_markdown=report.engineer_markdown,
    )


@app.get("/api/v1/health")
def health() -> Dict[str, object]:
    runtime = pipeline()
    return {
        "status": "ok",
        "version": __version__,
        "llm_available": runtime.llm.available,
        "patterns_loaded": len(runtime.classifier.rules.patterns),
        "services_in_catalog": len(runtime.graph.catalog),
        "incidents_in_memory": len(runtime.memory.load()),
    }


@app.get("/api/v1/patterns")
def patterns() -> List[Dict[str, object]]:
    runtime = pipeline()
    result: List[Dict[str, object]] = []
    for category, spec in runtime.classifier.rules.patterns.items():
        result.append(
            {
                "category": category,
                "family": spec.get("family", "UNKNOWN"),
                "description": spec.get("description", ""),
                "levels": spec.get("levels", []),
                "services": spec.get("services", ["*"]),
                "regex_count": len(spec.get("regex", [])),
            }
        )
    return sorted(result, key=lambda item: str(item["category"]))


@app.get("/api/v1/runbooks/{pattern}")
def runbook(pattern: str) -> Dict[str, str]:
    runtime = pipeline()
    category = pattern.upper()
    rule = runtime.kb.get_remediation(category)
    runbook_name = str(rule.get("runbook", ""))
    content = runtime.kb.get_runbook(runbook_name)
    if not runbook_name or not content:
        raise HTTPException(
            status_code=404, detail=f"No runbook found for pattern '{pattern}'."
        )
    return {"pattern": category, "runbook": runbook_name, "content": content}


@app.get("/api/v1/business-profile")
def business_profile() -> Dict[str, object]:
    return pipeline()._business_profile()


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    if not request.logs.strip():
        raise HTTPException(status_code=400, detail="Field 'logs' must not be empty.")
    runtime = pipeline()
    try:
        result = runtime.analyze(
            log_text=request.logs,
            changes_text=request.changes,
            log_format=request.format,
            time_window_minutes=request.options.time_window_minutes,
            lookback_minutes=request.options.lookback_minutes,
            use_llm=request.options.use_llm,
            persist_reports=False,
            include_remediation=request.options.include_remediation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalyzeResponse(
        incidents=[_to_incident(report) for report in result.incidents],
        logs_processed=result.logs_processed,
        errors_detected=result.errors_detected,
        changes_loaded=result.changes_loaded,
        processing_time_ms=result.processing_time_ms,
        llm_available=result.llm_available,
        warnings=result.warnings,
    )


@app.get("/")
def root() -> Dict[str, str]:
    return {
        "service": "IncidentX API",
        "version": __version__,
        "docs": "/docs",
        "health": "/api/v1/health",
    }

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional

from ..knowledge_base.loader import KnowledgeBase
from ..models import (
    IncidentCluster,
    IncidentReport,
    PlainEnglishSummary,
    RemediationPlan,
    RootCauseAnalysis,
    SeverityAssessment,
    SimilarIncident,
)
from ..service_graph import ServiceGraph


class IncidentReporter:
    def __init__(
        self,
        knowledge_base: Optional[KnowledgeBase] = None,
        service_graph: Optional[ServiceGraph] = None,
        business_context: Optional[Dict[str, Any]] = None,
    ):
        self.kb = knowledge_base or KnowledgeBase()
        self.graph = service_graph or ServiceGraph()
        self.business = business_context or {}
        self.revenue_services = {
            service.lower() for service in self.business.get("revenue_services", [])
        }
        self.user_facing_services = {
            service.lower() for service in self.business.get("user_facing_services", [])
        }

    def build(
        self,
        cluster: IncidentCluster,
        severity: SeverityAssessment,
        root_cause: RootCauseAnalysis,
        remediation: RemediationPlan,
        similar: Optional[List[SimilarIncident]] = None,
        llm_explanation: str = "",
        llm_used: bool = False,
    ) -> IncidentReport:
        similar = similar or []
        cluster.similar_incidents = similar
        title = self._title(cluster, root_cause)
        plain = self._plain_english(cluster, severity, root_cause, remediation)
        status_update = self._status_update(cluster, severity, root_cause, remediation)
        report = IncidentReport(
            id=cluster.id,
            title=title,
            severity=severity,
            cluster=cluster,
            root_cause=root_cause,
            remediation=remediation,
            plain_english=plain,
            customer_status_update=status_update,
            llm_explanation=llm_explanation,
            llm_used=llm_used,
        )
        report.engineer_markdown = self._engineer_markdown(report)
        return report

    def _title(self, cluster: IncidentCluster, root_cause: RootCauseAnalysis) -> str:
        display = self.graph.display_name(root_cause.primary_service)
        plain = self.kb.error_plain_name(root_cause.primary_category)
        if cluster.suspected_change:
            change = cluster.suspected_change
            return f"{display}: {plain} after {change.type}"
        return f"{display}: {plain}"

    def _customer_service_names(self, cluster: IncidentCluster) -> List[str]:
        names: List[str] = []
        for service in cluster.affected_services:
            if (
                service.lower() in self.revenue_services
                or service.lower() in self.user_facing_services
                or self.graph.is_user_facing(service)
            ):
                names.append(self.graph.display_name(service))
        return names

    def _plain_english(
        self,
        cluster: IncidentCluster,
        severity: SeverityAssessment,
        root_cause: RootCauseAnalysis,
        remediation: RemediationPlan,
    ) -> PlainEnglishSummary:
        customer_services = self._customer_service_names(cluster)
        root_display = self.graph.display_name(root_cause.primary_service)
        plain_error = self.kb.error_plain_name(root_cause.primary_category)
        revenue_hit = any(
            service.lower() in self.revenue_services for service in cluster.affected_services
        )

        if revenue_hit and severity.revenue_window:
            headline = "Customers cannot complete checkout right now"
        elif customer_services:
            headline = f"Customers are having trouble with {', '.join(customer_services[:2])}"
        else:
            headline = f"Internal service issue: {root_display}"

        change = cluster.suspected_change
        if change:
            doing = (
                f"We linked the failure to a {change.type} made at "
                f"{change.timestamp:%H:%M} on {self.graph.display_name(change.service)}. "
                "We are preparing a rollback and checking that the fix is safe before it runs."
            )
        else:
            doing = (
                f"We are checking {root_display} and its dependencies. "
                "We have not yet identified a single cause."
            )

        if revenue_hit and severity.revenue_window:
            who = (
                f"Customers trying to buy. {', '.join(customer_services) or 'Customer-facing services'} "
                "are affected; failures started during the live sale."
            )
            can_do = (
                "If you are a customer, please retry in a few minutes. "
                "Support can use the ready-to-send update below."
            )
        elif customer_services:
            who = f"Some customers using {', '.join(customer_services)}."
            can_do = "Customers can retry shortly. Support can use the update below."
        else:
            who = "No direct customer impact detected; internal services are affected."
            can_do = "No customer-facing action is needed yet."

        return PlainEnglishSummary(
            headline=headline,
            what_broken=(
                f"{plain_error.capitalize()} on {root_display}. "
                f"IncidentX grouped {len(cluster.errors)} related errors between "
                f"{cluster.start:%H:%M} and {cluster.end:%H:%M}."
            ),
            who_affected=who,
            what_we_are_doing=doing,
            what_you_can_do=can_do,
            when=(
                f"{cluster.start:%A %d %B %Y}, {cluster.start:%H:%M}-{cluster.end:%H:%M} "
                "local time"
            ),
        )

    def _status_update(
        self,
        cluster: IncidentCluster,
        severity: SeverityAssessment,
        root_cause: RootCauseAnalysis,
        remediation: RemediationPlan,
    ) -> str:
        company = self.business.get("company", "Our team")
        revenue_hit = any(
            service.lower() in self.revenue_services for service in cluster.affected_services
        )
        next_update = cluster.end + timedelta(minutes=30)
        if revenue_hit:
            opening = "We're aware that some customers are unable to complete checkout right now."
        else:
            opening = "We're aware that some customers are having trouble using parts of our service."
        if cluster.suspected_change:
            action = (
                "We've identified a recent change as the likely cause and are reviewing a rollback."
            )
        else:
            action = "Our team is investigating and will share the next update as soon as we can."
        return (
            f"Status update - {cluster.end:%H:%M} local time\n\n"
            f"{opening} {action}\n\n"
            f"We're sorry for the disruption. The next update will be posted by "
            f"{next_update:%H:%M} local time.\n\n"
            f"- {company}"
        )

    def _timeline_rows(self, cluster: IncidentCluster) -> List[str]:
        entries: List[tuple] = []
        for error in cluster.errors:
            if error.timestamp is None:
                continue
            entries.append(
                (
                    error.timestamp,
                    "error",
                    f"| {error.timestamp:%H:%M:%S} | `{error.service}` | "
                    f"{error.category} | {self._escape(error.log_entry.message)[:140]} |",
                )
            )
        if cluster.suspected_change:
            change = cluster.suspected_change
            entries.append(
                (
                    change.timestamp,
                    "change",
                    f"| {change.timestamp:%H:%M:%S} | `{change.service}` | "
                    f"CHANGE ({change.type}) | {self._escape(change.description)[:140]} |",
                )
            )
        entries.sort(key=lambda item: (item[0], item[1] != "change"))
        return [row for _, _, row in entries[:24]]

    def _engineer_markdown(self, report: IncidentReport) -> str:
        cluster = report.cluster
        severity = report.severity
        root = report.root_cause
        change = cluster.suspected_change

        lines: List[str] = []
        lines.append(f"# Incident Report: {report.id}")
        lines.append("")
        badge = {
            "CRITICAL": "**CRITICAL**",
            "HIGH": "**HIGH**",
            "MEDIUM": "**MEDIUM**",
            "LOW": "**LOW**",
        }.get(severity.level, severity.level)
        lines.append(
            f"{badge} ({severity.score:.0f}/100) | Detected {cluster.start:%Y-%m-%d %H:%M} "
            f"local | Duration {cluster.duration_minutes:.0f} min | "
            f"{len(cluster.errors)} error events | {len(cluster.affected_services)} services"
        )
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(
            f"{severity.level} incident on **{self.graph.display_name(root.primary_service)}**: "
            f"{self.kb.error_plain_name(root.primary_category)}."
        )
        if change:
            lines.append(
                f"The most likely trigger is {change.type} **{change.id}** on "
                f"`{change.service}` at {change.timestamp:%H:%M}: {change.description}."
            )
        lines.append(report.plain_english.what_broken)
        lines.append("")
        lines.append("## Business-Aware Severity")
        lines.append("")
        lines.append(f"- **Level:** {severity.level} ({severity.score:.0f}/100)")
        lines.append(
            f"- **Baseline without business context:** {severity.baseline_level} "
            f"({severity.baseline_score:.0f}/100)"
        )
        if severity.revenue_window:
            lines.append(f"- **Live business window:** {severity.revenue_window}")
        lines.append(f"- **Why:** {severity.justification}")
        lines.append("")
        lines.append("| Factor | Score (0-100) |")
        lines.append("|---|---|")
        for factor, value in severity.factors.items():
            lines.append(f"| {factor.replace('_', ' ').title()} | {value:.0f} |")
        lines.append("")
        lines.append("## What Changed? (Root Cause)")
        lines.append("")
        lines.append(
            f"**Primary cause:** `{root.primary_category}` in `{root.primary_service}` "
            f"(confidence {root.confidence:.0%})"
        )
        lines.append("")
        lines.append(root.reasoning)
        if change:
            lines.append("")
            lines.append("**Suspected change**")
            lines.append("")
            lines.append(f"- ID: `{change.id}`")
            lines.append(f"- Time: {change.timestamp:%Y-%m-%d %H:%M} local")
            lines.append(f"- Type: {change.type}")
            lines.append(f"- Service: `{change.service}`")
            lines.append(f"- Author: {change.author or 'unknown'}")
            lines.append(f"- Description: {change.description}")
            if root.change_confidence:
                lines.append(
                    f"- Link confidence: {root.change_confidence:.0%}. {root.change_reason}"
                )
            if change.rollback:
                lines.append(f"- Rollback path: `{change.rollback}`")
        if report.llm_explanation:
            lines.append("")
            lines.append("**LLM analysis**")
            lines.append("")
            lines.append(report.llm_explanation)
        lines.append("")
        lines.append("## Timeline")
        lines.append("")
        lines.append("| Time | Service | Type | Event |")
        lines.append("|---|---|---|---|")
        lines.extend(self._timeline_rows(cluster))
        lines.append("")
        lines.append("## Affected Services and Blast Radius")
        lines.append("")
        for service in cluster.affected_services:
            tier = self.graph.tier(service)
            lines.append(f"- `{service}` ({self.graph.display_name(service)}, tier: {tier})")
        downstream = self.graph.blast_radius(
            root.primary_service, cluster.affected_services
        ) - set(cluster.affected_services)
        if downstream:
            lines.append("")
            lines.append(
                "Downstream services that depend on the failing path: "
                + ", ".join(f"`{service}`" for service in sorted(downstream))
            )
        lines.append("")
        lines.append("## Evidence")
        lines.append("")
        lines.append("```log")
        for error in cluster.errors[:12]:
            lines.append(self._escape(error.log_entry.raw_text))
        lines.append("```")
        lines.append("")
        lines.append("## Remediation Plan")
        lines.append("")
        lines.append(
            "> IncidentX does not run commands. Proposed actions require human approval; "
            "the approval flow is simulated in this demo."
        )
        lines.append("")
        for phase, title in (
            ("immediate", "Immediate"),
            ("investigation", "Investigation"),
            ("resolution", "Resolution"),
        ):
            actions = report.remediation.by_phase(phase)
            if not actions:
                continue
            lines.append(f"### {title}")
            lines.append("")
            for action in actions:
                flags = []
                if action.automated:
                    flags.append("safe check")
                if action.requires_approval:
                    flags.append("approval required")
                suffix = f" _({', '.join(flags)})_" if flags else ""
                command = f" - `{action.command}`" if action.command else ""
                lines.append(f"- [ ] {action.action}{command}{suffix}")
            lines.append("")
        if report.remediation.prevention:
            lines.append("## Prevention Recommendations")
            lines.append("")
            for item in report.remediation.prevention:
                lines.append(f"- {item}")
            lines.append("")
        if report.remediation.escalation:
            lines.append(f"**Escalation:** {report.remediation.escalation}")
            lines.append("")
        if report.remediation.runbook:
            lines.append(f"**Runbook:** `{report.remediation.runbook}`")
            lines.append("")
        if cluster.similar_incidents:
            lines.append("## Incident Memory")
            lines.append("")
            for similar in cluster.similar_incidents:
                lines.append(
                    f"- **{similar.incident_id}** ({similar.similarity:.0%} similar, "
                    f"{similar.severity}): {similar.title}"
                )
                if similar.root_cause:
                    lines.append(f"  - Root cause: {similar.root_cause}")
                if similar.resolution:
                    lines.append(f"  - What worked: {'; '.join(similar.resolution)}")
            lines.append("")
        lines.append("## Plain-English Summary")
        lines.append("")
        plain = report.plain_english
        lines.append(f"**{plain.headline}**")
        lines.append("")
        lines.append(f"- **What is broken:** {plain.what_broken}")
        lines.append(f"- **Who is affected:** {plain.who_affected}")
        lines.append(f"- **What we are doing:** {plain.what_we_are_doing}")
        lines.append(f"- **What you can do:** {plain.what_you_can_do}")
        lines.append(f"- **When:** {plain.when}")
        lines.append("")
        lines.append("## Ready-to-Send Customer Update")
        lines.append("")
        lines.append("```text")
        lines.append(report.customer_status_update)
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("*Generated by IncidentX. Rules are the fast path; every conclusion links back to evidence.*")
        return "\n".join(lines)

    @staticmethod
    def _escape(text: str) -> str:
        return (text or "").replace("|", "\\|").replace("\n", " ")

    @staticmethod
    def export_json(report: IncidentReport) -> str:
        return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False)

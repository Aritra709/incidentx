from __future__ import annotations

import html as html_module
import json
from datetime import timedelta
from typing import Any, Dict, List, Optional

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

    def export_html(self, report: IncidentReport) -> str:
        severity = report.severity
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#2563eb",
        }
        color = colors.get(severity.level, "#475569")

        def escape(value: object) -> str:
            return html_module.escape(str(value)).replace("\n", "<br>")

        timeline_rows = []
        for error in report.cluster.errors[:24]:
            if error.timestamp is None:
                continue
            timeline_rows.append(
                "<tr>"
                f"<td>{error.timestamp:%H:%M:%S}</td>"
                f"<td><code>{escape(error.service)}</code></td>"
                f"<td>{escape(error.category)}</td>"
                f"<td>{escape(error.log_entry.message)}</td>"
                "</tr>"
            )
        change = report.cluster.suspected_change
        if change:
            timeline_rows.append(
                "<tr class='change'>"
                f"<td>{change.timestamp:%H:%M:%S}</td>"
                f"<td><code>{escape(change.service)}</code></td>"
                f"<td>CHANGE ({escape(change.type)})</td>"
                f"<td>{escape(change.description)}</td>"
                "</tr>"
            )

        remediation_html = []
        for phase, title in (
            ("immediate", "Immediate"),
            ("investigation", "Investigation"),
            ("resolution", "Resolution"),
        ):
            actions = report.remediation.by_phase(phase)
            if not actions:
                continue
            items = "".join(
                "<li>"
                + escape(action.action)
                + (f" <code>{escape(action.command)}</code>" if action.command else "")
                + (
                    " <span class='flag'>approval required</span>"
                    if action.requires_approval
                    else ""
                )
                + "</li>"
                for action in actions
            )
            remediation_html.append(f"<h3>{title}</h3><ul>{items}</ul>")
        prevention_html = "".join(
            f"<li>{escape(item)}</li>" for item in report.remediation.prevention
        )
        similar_html = "".join(
            "<li>"
            f"<strong>{escape(match.incident_id)}</strong> "
            f"({match.similarity:.0%} similar, {escape(match.severity)}) - "
            f"{escape(match.title)}"
            + (
                f"<br><span class='muted'>What worked: "
                f"{escape('; '.join(match.resolution))}</span>"
                if match.resolution
                else ""
            )
            + "</li>"
            for match in report.cluster.similar_incidents
        )
        downstream = self.graph.blast_radius(
            report.root_cause.primary_service, report.cluster.affected_services
        ) - set(report.cluster.affected_services)
        services_html = "".join(
            f"<li><code>{escape(service)}</code> "
            f"<span class='muted'>{escape(self.graph.tier(service))}</span></li>"
            for service in report.cluster.affected_services
        )
        downstream_html = "".join(
            f"<li><code>{escape(service)}</code></li>" for service in sorted(downstream)
        )
        change_html = ""
        if change:
            change_html = (
                "<h2>What changed?</h2>"
                f"<p><strong>{escape(change.type)} {escape(change.id)}</strong> at "
                f"{change.timestamp:%Y-%m-%d %H:%M} on <code>{escape(change.service)}</code></p>"
                f"<p>{escape(change.description)}</p>"
                f"<p class='muted'>Link confidence {report.root_cause.change_confidence:.0%}. "
                f"{escape(report.root_cause.change_reason)}</p>"
            )
            if change.rollback:
                change_html += f"<p>Rollback: <code>{escape(change.rollback)}</code></p>"

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(report.title)} - {escape(report.id)}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ margin: 0; font-family: "Segoe UI", Arial, sans-serif; color: #0f172a;
         background: #f1f5f9; line-height: 1.55; }}
  main {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }}
  .hero {{ background: linear-gradient(120deg, {color}, #0f172a);
           color: #fff; padding: 28px 30px; border-radius: 16px; }}
  .hero h1 {{ margin: 0 0 8px; font-size: 1.9rem; }}
  .badge {{ display: inline-block; background: rgba(255,255,255,.2);
            padding: 4px 12px; border-radius: 999px; font-weight: 700;
            letter-spacing: .04em; font-size: .8rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
           margin: 18px 0; }}
  .metric {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
             padding: 14px 16px; }}
  .metric span {{ display: block; color: #64748b; font-size: .78rem;
                  text-transform: uppercase; letter-spacing: .05em; }}
  .metric strong {{ font-size: 1.25rem; }}
  section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 14px;
             padding: 20px 24px; margin: 16px 0; }}
  h2 {{ margin-top: 0; font-size: 1.2rem; }}
  h3 {{ font-size: 1rem; margin-bottom: 6px; }}
  code {{ background: #f1f5f9; padding: 1px 6px; border-radius: 5px;
          font-size: .88em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
  th, td {{ text-align: left; padding: 7px 8px; border-bottom: 1px solid #e2e8f0;
            vertical-align: top; }}
  th {{ color: #64748b; font-size: .78rem; text-transform: uppercase; }}
  tr.change td {{ background: #fef3c7; }}
  .status {{ white-space: pre-wrap; background: #f8fafc; border: 1px dashed #cbd5e1;
             border-radius: 10px; padding: 16px; font-family: inherit; }}
  .muted {{ color: #64748b; font-size: .88rem; }}
  .flag {{ background: #fef3c7; color: #92400e; padding: 1px 7px;
           border-radius: 999px; font-size: .72rem; font-weight: 700; }}
  .two {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  @media (max-width: 720px) {{ .grid, .two {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<main>
  <div class="hero">
    <span class="badge">{escape(severity.level)} · {severity.score:.0f}/100</span>
    <span class="badge">baseline {escape(severity.baseline_level)} · {severity.baseline_score:.0f}/100</span>
    <h1>{escape(report.title)}</h1>
    <p>{escape(report.id)} · {report.cluster.start:%Y-%m-%d %H:%M} local ·
    {report.cluster.duration_minutes:.0f} min · {len(report.cluster.errors)} errors</p>
  </div>

  <div class="grid">
    <div class="metric"><span>Affected services</span><strong>{len(report.cluster.affected_services)}</strong></div>
    <div class="metric"><span>Business window</span><strong>{escape(severity.revenue_window or "none")}</strong></div>
    <div class="metric"><span>Root cause</span><strong>{escape(report.root_cause.primary_category)}</strong></div>
    <div class="metric"><span>Linked change</span><strong>{escape(change.id if change else "none")}</strong></div>
  </div>

  <section>
    <h2>Executive summary</h2>
    <p>{escape(severity.business_summary)}</p>
    <p>{escape(report.root_cause.reasoning)}</p>
    {change_html}
  </section>

  <section>
    <h2>Business-aware severity</h2>
    <p>{escape(severity.justification)}</p>
    <p class="muted">Factors: {escape(", ".join(f"{name.replace('_', ' ')} {value:.0f}" for name, value in severity.factors.items()))}</p>
  </section>

  <section>
    <h2>Timeline</h2>
    <table>
      <thead><tr><th>Time</th><th>Service</th><th>Type</th><th>Event</th></tr></thead>
      <tbody>{''.join(timeline_rows)}</tbody>
    </table>
  </section>

  <section>
    <div class="two">
      <div><h2>Affected services</h2><ul>{services_html}</ul></div>
      <div><h2>Downstream dependents</h2><ul>{downstream_html or "<li class='muted'>None detected</li>"}</ul></div>
    </div>
  </section>

  <section>
    <h2>Remediation plan</h2>
    <p class="muted">IncidentX never executes commands. Approval and dry-run are simulated.</p>
    {''.join(remediation_html)}
    <h3>Prevention</h3><ul>{prevention_html}</ul>
  </section>

  <section>
    <h2>Incident memory</h2>
    <ul>{similar_html or "<li class='muted'>No similar incident found</li>"}</ul>
  </section>

  <section>
    <h2>Plain-English summary</h2>
    <p><strong>{escape(report.plain_english.headline)}</strong></p>
    <p><strong>What is broken:</strong> {escape(report.plain_english.what_broken)}</p>
    <p><strong>Who is affected:</strong> {escape(report.plain_english.who_affected)}</p>
    <p><strong>What we are doing:</strong> {escape(report.plain_english.what_we_are_doing)}</p>
  </section>

  <section>
    <h2>Ready-to-send customer update</h2>
    <div class="status">{escape(report.customer_status_update)}</div>
  </section>

  <p class="muted">Generated by IncidentX. Rules are the fast path; every conclusion links back to evidence.</p>
</main>
</body>
</html>
"""

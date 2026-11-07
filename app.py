from __future__ import annotations

import html
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import streamlit as st

from incidentx.models import IncidentReport
from incidentx.pipeline.orchestrator import IncidentXPipeline

st.set_page_config(
    page_title="IncidentX",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
}


@st.cache_resource
def get_pipeline() -> IncidentXPipeline:
    return IncidentXPipeline()


def run_demo(
    pipeline: IncidentXPipeline,
    window: int,
    lookback: int,
    use_llm: bool,
):
    paths = IncidentXPipeline.demo_paths()
    return pipeline.analyze(
        logs_path=paths["logs"],
        changes_path=paths["changes"],
        time_window_minutes=window,
        lookback_minutes=lookback,
        use_llm=use_llm,
    )


def inject_css() -> None:
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }
        .ix-tagline { color: #64748b; font-size: 1.02rem; margin-top: -0.6rem; }
        .ix-banner {
            border-radius: 14px; padding: 18px 22px; margin: 6px 0 18px 0;
            color: white;
        }
        .ix-banner h2 { margin: 0; color: white; font-size: 1.35rem; }
        .ix-banner p { margin: 6px 0 0 0; opacity: 0.92; }
        .ix-pill {
            display: inline-block; padding: 2px 10px; border-radius: 999px;
            font-size: 0.78rem; font-weight: 700; letter-spacing: 0.04em;
            background: rgba(255,255,255,0.18); margin-right: 8px;
        }
        .ix-card {
            border: 1px solid #e2e8f0; border-radius: 14px; padding: 16px 18px;
            background: #ffffff; height: 100%;
        }
        .ix-card h4 { margin: 0 0 6px 0; font-size: 0.82rem; letter-spacing: 0.05em;
            text-transform: uppercase; color: #64748b; }
        .ix-card p { margin: 0; font-size: 0.98rem; }
        .ix-small { color: #64748b; font-size: 0.85rem; }
        .ix-chip {
            display: inline-block; background: #f1f5f9; border: 1px solid #e2e8f0;
            border-radius: 999px; padding: 2px 9px; margin: 2px 4px 2px 0;
            font-size: 0.8rem; color: #334155;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def severity_banner(report: IncidentReport) -> None:
    severity = report.severity
    color = SEVERITY_COLORS.get(severity.level, "#475569")
    window = (
        f"Business window active: {severity.revenue_window}"
        if severity.revenue_window
        else "No special business window active"
    )
    st.markdown(
        f"""
        <div class="ix-banner" style="background: linear-gradient(120deg, {color}, {color}cc);">
            <span class="ix-pill">{severity.level}</span>
            <span class="ix-pill">{severity.score:.0f}/100</span>
            <span class="ix-pill">baseline {severity.baseline_level} {severity.baseline_score:.0f}</span>
            <h2>{html.escape(report.title)}</h2>
            <p>{html.escape(window)} · {len(report.cluster.errors)} related errors ·
            {len(report.cluster.affected_services)} services affected</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_row(report: IncidentReport) -> None:
    severity = report.severity
    change = report.cluster.suspected_change
    columns = st.columns(5)
    columns[0].metric("Severity", severity.level, help=severity.business_summary)
    columns[1].metric(
        "Without business context",
        severity.baseline_level,
        f"{severity.baseline_score:.0f}/100",
        delta_color="off",
        help="The same failure scored against a generic severity model, ignoring the live sale window.",
    )
    columns[2].metric("Affected services", len(report.cluster.affected_services))
    columns[3].metric("Errors", len(report.cluster.errors))
    columns[4].metric("Linked change", "Yes" if change else "No")


def render_root_cause(pipeline: IncidentXPipeline, report: IncidentReport) -> None:
    root = report.root_cause
    change = report.cluster.suspected_change
    left, right = st.columns([1.1, 0.9])

    with left:
        st.subheader("What changed?")
        st.markdown(
            f"**Primary cause:** `{root.primary_category}` in "
            f"`{root.primary_service}`"
        )
        st.progress(min(max(root.confidence, 0.0), 1.0), text=f"Root-cause confidence {root.confidence:.0%}")
        st.write(root.reasoning)
        if root.contributing_categories:
            st.markdown(
                "**Contributing categories:** "
                + " ".join(
                    f"<span class='ix-chip'>{html.escape(category)}</span>"
                    for category in root.contributing_categories
                ),
                unsafe_allow_html=True,
            )
        if report.llm_explanation:
            st.info(report.llm_explanation, icon=None)

    with right:
        st.subheader("Suspected change")
        if not change:
            st.info("No deploy or config change matched this incident window.")
        else:
            st.markdown(
                f"""
                <div class="ix-card">
                    <h4>{html.escape(change.type)} · {html.escape(change.id)}</h4>
                    <p><strong>{html.escape(change.timestamp.strftime("%Y-%m-%d %H:%M"))}</strong>
                    on <code>{html.escape(change.service)}</code></p>
                    <p>{html.escape(change.description)}</p>
                    <p class="ix-small">Author: {html.escape(change.author or "unknown")}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.progress(
                min(max(root.change_confidence, 0.0), 1.0),
                text=f"Link confidence {root.change_confidence:.0%}",
            )
            st.caption(root.change_reason)
            if change.rollback:
                st.markdown("**Rollback path**")
                st.code(change.rollback, language="bash")

    st.subheader("Why this severity?")
    factors = pd.DataFrame(
        {
            "Factor": [name.replace("_", " ").title() for name in report.severity.factors],
            "Score": list(report.severity.factors.values()),
        }
    ).set_index("Factor")
    st.bar_chart(factors, height=240)
    st.caption(report.severity.justification)


def render_timeline(report: IncidentReport) -> None:
    rows: List[Dict[str, Any]] = []
    for error in report.cluster.errors:
        if error.timestamp is None:
            continue
        rows.append(
            {
                "Time": error.timestamp.strftime("%H:%M:%S"),
                "Service": error.service,
                "Type": error.category,
                "Event": error.log_entry.message,
            }
        )
    change = report.cluster.suspected_change
    if change:
        rows.append(
            {
                "Time": change.timestamp.strftime("%H:%M:%S"),
                "Service": change.service,
                "Type": f"CHANGE ({change.type})",
                "Event": change.description,
            }
        )
    rows.sort(key=lambda row: row["Time"])
    st.subheader("Timeline")
    st.dataframe(
        pd.DataFrame(rows),
        width="stretch",
        hide_index=True,
        height=min(420, 42 + 35 * len(rows)),
    )


def render_evidence(report: IncidentReport) -> None:
    st.subheader("Evidence")
    evidence = "\n".join(
        error.log_entry.raw_text for error in report.cluster.errors[:14]
    )
    st.code(evidence, language="log")


def render_services(pipeline: IncidentXPipeline, report: IncidentReport) -> None:
    st.subheader("Affected services and blast radius")
    affected = report.cluster.affected_services
    root_service = report.root_cause.primary_service
    downstream = (
        pipeline.graph.blast_radius(root_service, affected) - set(affected)
    )
    columns = st.columns(2)
    with columns[0]:
        st.markdown("**Observed failures**")
        for service in affected:
            st.markdown(
                f"<span class='ix-chip'>{html.escape(service)} · "
                f"{html.escape(pipeline.graph.tier(service))}</span>",
                unsafe_allow_html=True,
            )
    with columns[1]:
        st.markdown("**Downstream dependents (not failing yet)**")
        if downstream:
            for service in sorted(downstream):
                st.markdown(
                    f"<span class='ix-chip'>{html.escape(service)}</span>",
                    unsafe_allow_html=True,
                )
        else:
            st.caption("None detected in the service catalog.")
    st.caption(
        f"Root cause candidate `{root_service}`. Blast radius uses the dependency "
        "graph from config/service_catalog.yaml."
    )


def render_similar(report: IncidentReport) -> None:
    similar = report.cluster.similar_incidents
    st.subheader("Incident memory")
    if not similar:
        st.caption("No similar resolved incident found.")
        return
    for match in similar:
        st.markdown(
            f"**{match.incident_id}** · {match.similarity:.0%} similar · "
            f"{match.severity} · {match.title}"
        )
        if match.root_cause:
            st.caption(f"Root cause: {match.root_cause}")
        if match.resolution:
            st.caption("What worked: " + "; ".join(match.resolution))


def render_exports(pipeline: IncidentXPipeline, report: IncidentReport) -> None:
    st.subheader("Export report")
    columns = st.columns(3)
    columns[0].download_button(
        "Markdown",
        data=report.engineer_markdown,
        file_name=f"{report.id}.md",
        mime="text/markdown",
        key=f"export-md-{report.id}",
        width="stretch",
    )
    columns[1].download_button(
        "JSON",
        data=pipeline.reporter.export_json(report),
        file_name=f"{report.id}.json",
        mime="application/json",
        key=f"export-json-{report.id}",
        width="stretch",
    )
    columns[2].download_button(
        "HTML",
        data=pipeline.reporter.export_html(report),
        file_name=f"{report.id}.html",
        mime="text/html",
        key=f"export-html-{report.id}",
        width="stretch",
    )


def render_engineer_view(pipeline: IncidentXPipeline, report: IncidentReport) -> None:
    render_root_cause(pipeline, report)
    st.divider()
    render_timeline(report)
    st.divider()
    render_services(pipeline, report)
    st.divider()
    render_evidence(report)
    st.divider()
    render_similar(report)
    st.divider()
    render_exports(pipeline, report)


def render_plain_english(pipeline: IncidentXPipeline, report: IncidentReport) -> None:
    plain = report.plain_english
    st.markdown(f"## {plain.headline}")
    st.caption(plain.when)

    columns = st.columns(2)
    cards = [
        ("What is broken", plain.what_broken),
        ("Who is affected", plain.who_affected),
        ("What we are doing", plain.what_we_are_doing),
        ("What you can do", plain.what_you_can_do),
    ]
    for index, (title, body) in enumerate(cards):
        with columns[index % 2]:
            st.markdown(
                f"""
                <div class="ix-card" style="margin-bottom: 12px;">
                    <h4>{html.escape(title)}</h4>
                    <p>{html.escape(body)}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.subheader("Ready-to-send customer update")
    st.text_area(
        "Copy this into the status page, support chat, or social post.",
        value=report.customer_status_update,
        height=190,
        key=f"status-{report.id}",
        label_visibility="collapsed",
    )
    st.download_button(
        "Download update as .txt",
        data=report.customer_status_update,
        file_name=f"{report.id}-status-update.txt",
        mime="text/plain",
        key=f"download-{report.id}",
    )
    st.info(report.severity.business_summary)


def render_cascade(pipeline: IncidentXPipeline, report: IncidentReport) -> None:
    severity = report.severity
    change = report.cluster.suspected_change
    revenue_services = pipeline.business_context.get("revenue_services", [])
    dot = pipeline.graph.to_dot(
        root=report.root_cause.primary_service,
        affected=report.cluster.affected_services,
        severity=severity.level,
        change_service=change.service if change else None,
        revenue_services=revenue_services,
    )
    st.subheader("Failure cascade")
    st.caption(
        "Red = root-cause service, pink = observed failures, yellow = revenue service, "
        "arrows point from a dependency to the service that depends on it."
    )
    st.graphviz_chart(dot, width="stretch")
    render_services(pipeline, report)


def action_key(report: IncidentReport, action_id: str, suffix: str) -> str:
    return f"{suffix}-{report.id}-{action_id}"


def render_remediation(pipeline: IncidentXPipeline, report: IncidentReport) -> None:
    st.subheader("Remediation plan")
    st.caption(
        "IncidentX never executes shell commands. Actions are proposals; approve and "
        "dry-run steps are simulated for this demo."
    )
    if report.remediation.proposed_rollback:
        st.warning(
            "A rollback is proposed for the suspected change. Run the dry-run, then "
            "require a human approval before anything happens."
        )

    status_labels = {
        "proposed": "proposed",
        "dry_run": "dry-run complete",
        "ready": "ready (safe check)",
        "approved_simulated": "approved (simulated)",
    }

    for phase, title in (
        ("immediate", "Immediate"),
        ("investigation", "Investigation"),
        ("resolution", "Resolution"),
    ):
        actions = report.remediation.by_phase(phase)
        if not actions:
            continue
        st.markdown(f"### {title}")
        for action in actions:
            with st.container(border=True):
                header, dry_column, approve_column = st.columns([0.62, 0.19, 0.19])
                with header:
                    flags = []
                    if action.automated:
                        flags.append("safe check")
                    if action.requires_approval:
                        flags.append("approval required")
                    st.markdown(f"**{action.action}**")
                    if flags:
                        st.caption(" · ".join(flags))
                    if action.command:
                        st.code(action.command, language="bash")
                if action.requires_approval:
                    if dry_column.button(
                        "Dry-run",
                        key=action_key(report, action.id, "dry"),
                        width="stretch",
                    ):
                        pipeline.remediator.dry_run(report.remediation, action.id)
                        st.rerun()
                    if approve_column.button(
                        "Approve (simulated)",
                        key=action_key(report, action.id, "approve"),
                        type="primary",
                        width="stretch",
                    ):
                        pipeline.remediator.approve(
                            report.remediation, action.id, approved_by="demo operator"
                        )
                        st.rerun()
                else:
                    dry_column.caption("Read-only check")
                    approve_column.caption("No approval needed")
                if action.status != "proposed":
                    st.success(status_labels.get(action.status, action.status))
                if action.dry_run_output:
                    st.code(action.dry_run_output, language="text")
                if action.note and action.status != "proposed":
                    st.caption(action.note)

    if report.remediation.prevention:
        st.subheader("Prevention")
        for item in report.remediation.prevention:
            st.markdown(f"- {item}")

    if report.remediation.runbook:
        with st.expander(f"Runbook: {report.remediation.runbook}"):
            runbook = pipeline.kb.get_runbook(report.remediation.runbook)
            st.markdown(runbook or "Runbook not found.")

    st.divider()
    st.subheader("Close the loop")
    st.caption(
        "Save this incident to memory so the next similar failure can reuse what worked."
    )
    resolution = st.text_area(
        "What fixed it?",
        value="\n".join(
            action.action for action in report.remediation.by_phase("resolution")
        ),
        height=110,
        key=f"resolution-{report.id}",
    )
    if st.button(
        "Mark resolved and save to incident memory",
        type="primary",
        key=f"resolve-{report.id}",
    ):
        saved = pipeline.memory.save_report(
            report,
            resolution=[line.strip() for line in resolution.splitlines() if line.strip()],
        )
        if saved:
            st.success("Saved. Incident memory can now match this signature next time.")
        else:
            st.info("This incident is already in memory.")


def sidebar_inputs(pipeline: IncidentXPipeline):
    st.sidebar.title("IncidentX")
    st.sidebar.markdown(
        "<p class='ix-tagline'>The on-call engineer small teams can't afford.</p>",
        unsafe_allow_html=True,
    )

    profile = pipeline.business_context
    with st.sidebar.expander("Business profile", expanded=False):
        st.markdown(f"**{profile.get('company', 'Unknown company')}**")
        st.write(profile.get("description", ""))
        st.markdown("**Revenue services**")
        st.write(", ".join(profile.get("revenue_services", [])) or "none")
        st.markdown("**Revenue windows**")
        for window in profile.get("revenue_windows", []):
            st.markdown(
                f"- **{window.get('name')}** · {window.get('start')}-{window.get('end')} "
                f"({', '.join(window.get('days', []))})"
            )
        st.caption("Edit config/business_context.yaml to change the severity lens.")

    st.sidebar.subheader("Input")
    source = st.sidebar.radio(
        "Choose data",
        ["Demo incident", "Paste logs", "Upload files"],
        label_visibility="collapsed",
    )

    logs_path: Optional[Path] = None
    changes_path: Optional[Path] = None
    log_text: Optional[str] = None
    changes_text: Optional[str] = None
    log_format: Optional[str] = None
    source_label = "Demo incident"

    if source == "Demo incident":
        paths = IncidentXPipeline.demo_paths()
        logs_path = paths["logs"]
        changes_path = paths["changes"]
        st.sidebar.caption(
            "7:52 PM deploy shrinks the checkout DB pool. 7:55 PM errors begin. "
            "8:00 PM the flash sale starts."
        )
    elif source == "Paste logs":
        log_text = st.sidebar.text_area(
            "Logs", height=170, placeholder="2026-11-07 19:55:02 ERROR [checkout-api] ..."
        )
        changes_text = st.sidebar.text_area(
            "Changelog (optional YAML/JSON)", height=130
        )
        source_label = "Pasted logs"
    else:
        log_file = st.sidebar.file_uploader(
            "Log file", type=["log", "txt", "json", "jsonl", "csv"]
        )
        changes_file = st.sidebar.file_uploader(
            "Changelog (optional)", type=["yaml", "yml", "json", "csv"]
        )
        if log_file is not None:
            log_text = log_file.getvalue().decode("utf-8", errors="replace")
            suffix = Path(log_file.name).suffix.lower()
            log_format = {
                ".json": "json",
                ".jsonl": "json",
                ".csv": "csv",
            }.get(suffix, "txt")
            source_label = log_file.name
        if changes_file is not None:
            changes_text = changes_file.getvalue().decode("utf-8", errors="replace")

    st.sidebar.divider()
    window = st.sidebar.slider("Correlation window (minutes)", 1, 15, 5)
    lookback = st.sidebar.slider("Change lookback (minutes)", 5, 120, 45)
    llm_available = pipeline.llm.available
    use_llm = st.sidebar.checkbox(
        "Use LLM for unknown errors and explanations",
        value=llm_available,
        disabled=not llm_available,
        help=(
            "Configure OPENAI_API_KEY (or a local OpenAI-compatible endpoint) to enable. "
            "Rules remain the fast path."
        ),
    )
    if not llm_available:
        st.sidebar.caption("LLM layer off — deterministic rules and templates.")

    run = st.sidebar.button("Analyze incident", type="primary", width="stretch")
    st.sidebar.divider()
    st.sidebar.caption(
        f"Incident memory: {len(pipeline.memory.load())} stored · "
        f"services: {len(pipeline.graph.catalog)}"
    )
    return {
        "run": run,
        "source": source,
        "source_label": source_label,
        "logs_path": logs_path,
        "changes_path": changes_path,
        "log_text": log_text,
        "changes_text": changes_text,
        "log_format": log_format,
        "window": window,
        "lookback": lookback,
        "use_llm": use_llm,
    }


def main() -> None:
    inject_css()
    pipeline = get_pipeline()
    options = sidebar_inputs(pipeline)

    if "analysis" not in st.session_state:
        with st.spinner("Running the live-sale demo..."):
            st.session_state.analysis = run_demo(pipeline, 5, 45, pipeline.llm.available)
            st.session_state.analysis_label = "Demo incident"
            st.session_state.analysis_llm = pipeline.llm.available

    if options["run"]:
        if options["source"] != "Demo incident" and not (
            options["log_text"] or ""
        ).strip():
            st.sidebar.error("Provide log text or upload a log file first.")
        else:
            with st.spinner("Analyzing logs and changes..."):
                try:
                    st.session_state.analysis = pipeline.analyze(
                        logs_path=options["logs_path"],
                        log_text=options["log_text"],
                        changes_path=options["changes_path"],
                        changes_text=options["changes_text"],
                        log_format=options["log_format"],
                        time_window_minutes=options["window"],
                        lookback_minutes=options["lookback"],
                        use_llm=options["use_llm"],
                    )
                    st.session_state.analysis_label = options["source_label"]
                except Exception as exc:
                    st.sidebar.error(f"Analysis failed: {exc}")

    result = st.session_state.get("analysis")
    st.title("IncidentX")
    st.markdown(
        "<p class='ix-tagline'>Change-aware root cause, business-aware severity, and two "
        "outputs from one analysis.</p>",
        unsafe_allow_html=True,
    )
    if result is None:
        return

    st.caption(
        f"Source: {st.session_state.get('analysis_label', 'unknown')} · "
        f"{result.logs_processed} log lines · {result.errors_detected} errors · "
        f"{result.changes_loaded} changes · {result.processing_time_ms:.0f} ms · "
        f"LLM {'on' if result.llm_available else 'off'}"
    )
    for warning in result.warnings:
        st.warning(warning)

    if not result.incidents:
        st.info("No incidents detected in this input.")
        return

    labels = [
        f"{report.severity.level} · {report.id} · {report.title}"
        for report in result.incidents
    ]
    if len(result.incidents) > 1:
        selected = st.selectbox(
            "Incident", options=list(range(len(result.incidents))), format_func=lambda index: labels[index]
        )
    else:
        selected = 0
    report = result.incidents[selected]

    severity_banner(report)
    metric_row(report)

    engineer_tab, plain_tab, cascade_tab, remediation_tab = st.tabs(
        ["Engineer view", "Plain English", "Cascade graph", "Remediation & approvals"]
    )
    with engineer_tab:
        render_engineer_view(pipeline, report)
    with plain_tab:
        render_plain_english(pipeline, report)
    with cascade_tab:
        render_cascade(pipeline, report)
    with remediation_tab:
        render_remediation(pipeline, report)


if __name__ == "__main__":
    main()


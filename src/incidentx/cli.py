from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .pipeline.orchestrator import IncidentXPipeline


def _print_result(result, title: str = "IncidentX analysis") -> None:
    print("=" * 72)
    print(title)
    print("=" * 72)
    print(
        f"Logs processed: {result.logs_processed} | Errors: {result.errors_detected} | "
        f"Changes: {result.changes_loaded} | Time: {result.processing_time_ms:.0f} ms"
    )
    print(f"LLM layer: {'enabled' if result.llm_available else 'disabled (rules only)'}")
    for warning in result.warnings:
        print(f"! {warning}")

    if not result.incidents:
        print("\nNo incidents detected.")
        return

    for report in result.incidents:
        severity = report.severity
        cluster = report.cluster
        root = report.root_cause
        print("\n" + "-" * 72)
        print(f"{report.id} | {severity.level} ({severity.score:.0f}/100) | {report.title}")
        print("-" * 72)
        print(
            f"Window: {cluster.start:%Y-%m-%d %H:%M} - {cluster.end:%H:%M} local "
            f"({cluster.duration_minutes:.1f} min, {len(cluster.errors)} errors)"
        )
        print(f"Affected: {', '.join(cluster.affected_services)}")
        print(
            f"Root cause: {root.primary_category} in {root.primary_service} "
            f"(confidence {root.confidence:.0%})"
        )
        if cluster.suspected_change:
            change = cluster.suspected_change
            print(
                f"Why now: {change.type} {change.id} on {change.service} at "
                f"{change.timestamp:%H:%M} (link confidence {root.change_confidence:.0%})"
            )
            if change.rollback:
                print(f"Rollback: {change.rollback}")
        print(f"Severity: {severity.justification}")
        if severity.boosted:
            print(
                f"Baseline without business context: {severity.baseline_level} "
                f"({severity.baseline_score:.0f}/100)"
            )
        immediate = report.remediation.by_phase("immediate")
        if immediate:
            print("Next actions:")
            for action in immediate[:4]:
                gate = " [approval]" if action.requires_approval else ""
                print(f"  - {action.action}{gate}")
        if cluster.similar_incidents:
            print("Incident memory:")
            for similar in cluster.similar_incidents:
                print(
                    f"  - {similar.incident_id} ({similar.similarity:.0%} similar): "
                    f"{similar.title}"
                )
        print("\nPlain English:")
        print(f"  {report.plain_english.headline}")
        print(f"  {report.plain_english.who_affected}")
        print(f"  {report.plain_english.what_we_are_doing}")
        print("\nReady-to-send customer update:")
        for line in report.customer_status_update.splitlines():
            print(f"  {line}")


def command_demo(args: argparse.Namespace) -> int:
    pipeline = IncidentXPipeline()
    paths = IncidentXPipeline.demo_paths()
    result = pipeline.analyze(
        logs_path=paths["logs"],
        changes_path=paths["changes"],
        lookback_minutes=args.lookback,
        use_llm=not args.no_llm,
        persist_reports=not args.no_reports,
        output_dir=args.output,
    )
    _print_result(result, "IncidentX demo - live sale checkout outage")
    if not args.no_reports:
        directory = Path(args.output) if args.output else pipeline.report_dir
        print(f"\nReports written to: {directory}")
    return 0


def command_analyze(args: argparse.Namespace) -> int:
    pipeline = IncidentXPipeline()
    result = pipeline.analyze(
        logs_path=args.logs,
        changes_path=args.changes,
        log_format=args.format,
        time_window_minutes=args.window,
        lookback_minutes=args.lookback,
        use_llm=not args.no_llm,
        persist_reports=not args.no_reports,
        output_dir=args.output,
        remember=args.remember,
    )
    _print_result(result, f"IncidentX analysis - {args.logs}")
    if not args.no_reports:
        directory = Path(args.output) if args.output else pipeline.report_dir
        print(f"\nReports written to: {directory}")
    if args.remember:
        print(f"Incident memory updated: {pipeline.memory.path}")
    return 0


def command_memory(args: argparse.Namespace) -> int:
    pipeline = IncidentXPipeline()
    entries = pipeline.memory.load()
    print(f"Incident memory: {pipeline.memory.path}")
    if not entries:
        print("No stored incidents.")
        return 0
    for entry in entries:
        print(
            f"- {entry.get('incident_id')} | {entry.get('severity')} | "
            f"{entry.get('status')} | {entry.get('title')}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="incidentx",
        description="IncidentX: the on-call engineer small teams can't afford.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="Run the included live-sale demo.")
    demo.add_argument("--no-llm", action="store_true", help="Use rules only.")
    demo.add_argument("--no-reports", action="store_true", help="Do not write report files.")
    demo.add_argument("--output", help="Report output directory.")
    demo.add_argument("--lookback", type=int, default=45, help="Change lookback minutes.")
    demo.set_defaults(func=command_demo)

    analyze = subparsers.add_parser("analyze", help="Analyze a log file.")
    analyze.add_argument("--logs", required=True, help="Path to TXT, JSON, or CSV logs.")
    analyze.add_argument("--changes", help="Optional changelog (YAML/JSON/CSV).")
    analyze.add_argument(
        "--format", choices=["txt", "json", "csv"], help="Override log format detection."
    )
    analyze.add_argument("--window", type=int, default=5, help="Correlation window minutes.")
    analyze.add_argument("--lookback", type=int, default=45, help="Change lookback minutes.")
    analyze.add_argument("--no-llm", action="store_true", help="Use rules only.")
    analyze.add_argument("--no-reports", action="store_true", help="Do not write report files.")
    analyze.add_argument("--output", help="Report output directory.")
    analyze.add_argument(
        "--remember", action="store_true", help="Store incidents in incident memory."
    )
    analyze.set_defaults(func=command_analyze)

    memory = subparsers.add_parser("memory", help="List stored incidents.")
    memory.set_defaults(func=command_memory)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())

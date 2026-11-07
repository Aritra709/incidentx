import argparse
import json
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentx.pipeline.orchestrator import IncidentXPipeline  # noqa: E402

MESSAGES = [
    (
        "checkout-api",
        "ERROR",
        "Could not acquire connection from pool: connection pool exhausted (max=8)",
    ),
    (
        "web-frontend",
        "WARN",
        "Checkout request failed: upstream timeout after 5000ms",
    ),
    (
        "notification-worker",
        "WARN",
        "payment confirmation delayed: queue backlog 340",
    ),
    ("web-frontend", "ERROR", "503 Service Unavailable for POST /checkout"),
]


def build_log_text(line_count: int, error_every: int = 10) -> str:
    start = datetime(2026, 11, 7, 19, 0, 0)
    lines = []
    error_index = 0
    for index in range(line_count):
        timestamp = start + timedelta(seconds=index)
        if error_every > 0 and index % error_every == 0:
            service, level, message = MESSAGES[error_index % len(MESSAGES)]
            error_index += 1
        else:
            service, level, message = (
                "web-frontend",
                "INFO",
                "processed checkout request",
            )
        lines.append(
            f"{timestamp:%Y-%m-%d %H:%M:%S} {level:<5} [{service}] {message}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the IncidentX pipeline.")
    parser.add_argument("--lines", type=int, default=10000)
    parser.add_argument(
        "--error-every",
        type=int,
        default=10,
        help="Emit one error every N lines (0 means every line).",
    )
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument(
        "--api",
        action="store_true",
        help="Also measure FastAPI latency through Starlette's TestClient.",
    )
    parser.add_argument("--api-requests", type=int, default=50)
    args = parser.parse_args()

    text = build_log_text(args.lines, args.error_every)
    durations = []
    with tempfile.TemporaryDirectory() as directory:
        workdir = Path(directory)
        pipeline = IncidentXPipeline(memory_path=workdir / "memory.json")
        for _ in range(args.runs):
            started = time.perf_counter()
            result = pipeline.analyze(log_text=text, use_llm=False)
            durations.append((time.perf_counter() - started) * 1000)

        report_dir = workdir / "reports"
        started = time.perf_counter()
        written = pipeline.write_reports(result.incidents, report_dir)
        write_ms = (time.perf_counter() - started) * 1000
        bytes_written = sum(path.stat().st_size for path in written)

        report = result.incidents[0]
        summary = {
            "lines": result.logs_processed,
            "errors": result.errors_detected,
            "incidents": len(result.incidents),
            "root_cause": report.root_cause.primary_category,
            "severity": report.severity.level,
            "severity_score": report.severity.score,
            "runs": args.runs,
            "min_ms": round(min(durations), 1),
            "median_ms": round(statistics.median(durations), 1),
            "max_ms": round(max(durations), 1),
            "write_reports_ms": round(write_ms, 1),
            "report_bytes": bytes_written,
            "python": sys.version.split()[0],
        }

    if args.api:
        from fastapi.testclient import TestClient

        from incidentx.api.routes import app

        client = TestClient(app)
        demo = IncidentXPipeline.demo_paths()
        payload = {
            "logs": demo["logs"].read_text(encoding="utf-8"),
            "changes": demo["changes"].read_text(encoding="utf-8"),
            "options": {"use_llm": False},
        }

        def measure_api(call):
            times = []
            for _ in range(args.api_requests):
                started = time.perf_counter()
                response = call()
                response.raise_for_status()
                times.append((time.perf_counter() - started) * 1000)
            times.sort()
            return {
                "p50_ms": round(statistics.median(times), 1),
                "p95_ms": round(
                    times[min(len(times) - 1, int(len(times) * 0.95))], 1
                ),
                "max_ms": round(times[-1], 1),
            }

        summary["api"] = {
            "requests": args.api_requests,
            "health": measure_api(lambda: client.get("/api/v1/health")),
            "analyze_demo": measure_api(
                lambda: client.post("/api/v1/analyze", json=payload)
            ),
        }

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

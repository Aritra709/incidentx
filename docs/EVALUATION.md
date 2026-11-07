# Evaluation

Measured on 2026-11-07 on a Windows development laptop (AMD Ryzen 5 3500U, 16 GB RAM) with Python 3.10.0. These are local, in-process measurements, not production benchmarks.

## Test suite

```powershell
pytest
```

`47 passed` covering ingestion (TXT/JSON/CSV), rule classification, correlation, trace-aware clustering, change linking, business-aware severity, remediation, incident memory, Markdown/JSON/HTML reports, the FastAPI service (including concurrent analyze requests), and mocked LLM fallback and circuit-breaker paths.

## Success criteria

| Criterion | Target | Result | Evidence |
| --- | --- | --- | --- |
| Log format support | TXT, JSON, CSV | Pass | `tests/test_parser.py`, `tests/test_fixtures.py` |
| Error detection on known patterns | >90% | 30/30 curated signatures (100%) | `tests/test_pattern_coverage.py` |
| Cascade correlation precision | >85% | 5/5 hand-labeled fixture scenarios | demo + `tests/fixtures/` |
| Severity alignment | >80% | Demo matches hand triage: CRITICAL 82 vs MEDIUM 54 baseline | `tests/test_pipeline.py` |
| Report generation for 10k lines | <2s | 0.99s median end-to-end (min 0.97, max 1.08) | `scripts/benchmark.py` |
| API latency p95 | <500ms | 7.7ms health, 27.1ms analyze | `scripts/benchmark.py --api` |

Pattern coverage uses one representative message for each of the 30 configured categories. It proves every category is reachable and correctly wired; it is not an independent labeled corpus. Correlation and severity figures are similarly small, hand-labeled fixtures rather than a large benchmark set.

## Performance methodology

The benchmark generates 10,000 log lines over a 2.8-hour window with a 10% error rate (1,000 errors), runs the full pipeline five times, and reports the median. It also writes Markdown, JSON, and HTML reports to a temporary directory.

```powershell
python scripts/benchmark.py --lines 10000 --runs 5
```

Representative result:

```json
{
  "lines": 10000,
  "errors": 1000,
  "incidents": 1,
  "root_cause": "CONNECTION_POOL_EXHAUSTED",
  "severity": "CRITICAL",
  "severity_score": 82.0,
  "runs": 5,
  "min_ms": 972.4,
  "median_ms": 992.4,
  "max_ms": 1078.1,
  "write_reports_ms": 40.8,
  "report_bytes": 882937
}
```

Worst-case note: a synthetic stream where all 10,000 lines are errors takes about 2.0-2.2s for the pipeline (and produces a much larger JSON export). The 10k-line target is met for a realistic error mix, not for an all-error stream.

## API latency methodology

`--api` uses Starlette's in-process `TestClient` and performs 50 requests per endpoint against the committed demo incident. This measures application latency without network or reverse-proxy overhead.

```powershell
python scripts/benchmark.py --api
```

| Endpoint | p50 | p95 | max |
| --- | --- | --- | --- |
| `GET /api/v1/health` | 6.0ms | 7.7ms | 202.4ms |
| `POST /api/v1/analyze` (demo) | 24.4ms | 27.1ms | 28.8ms |

The first request includes process warm-up, which explains the 202ms max on health.

## Demo correctness

The committed demo incident must continue to produce:

- `INC-20261107-1954-AF8D`
- CRITICAL 82/100, baseline MEDIUM 54/100
- root cause `CONNECTION_POOL_EXHAUSTED` in `checkout-api`
- linked deploy `chg-20261107-001`
- rollback `kubectl rollout undo deployment/checkout-api`
- similar incident `INC-20261024-001`

This is asserted in `tests/test_pipeline.py` and `tests/test_api.py`.

## Reproduce everything

```powershell
pytest
ruff check src app.py tests scripts
python scripts/benchmark.py --lines 10000 --runs 5 --api
```

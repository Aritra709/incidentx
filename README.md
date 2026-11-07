# IncidentX

[![CI](https://github.com/Aritra709/incidentx/actions/workflows/ci.yml/badge.svg)](https://github.com/Aritra709/incidentx/actions/workflows/ci.yml)

**The on-call engineer small teams can't afford.**

IncidentX analyzes logs and a small changelog, finds incidents, explains what changed, rates severity against the business (not a generic matrix), and produces two outputs from one analysis: an engineer report and a plain-English customer update.

Built for Agentic Chase PS1 — *IncidentX: Autonomous IT Incident Response Agent*.

> Status: end-to-end vertical slice. Ingestion, rule classification, optional LLM review, change correlation, business-aware severity, remediation proposals, incident memory, Markdown/JSON/HTML reports, CLI, Streamlit UI, FastAPI service, and automated tests are implemented.

**See a real output:** [demo report](docs/example/INC-20261107-1954-AF8D.md) · [HTML version](docs/example/INC-20261107-1954-AF8D.html) · [evaluation results](docs/EVALUATION.md)

## Why it is different

1. **"What changed?" root cause** — reads deploys/config edits and links the error cascade to the likely culprit change.
2. **Business-aware severity** — the same failure is MEDIUM at 3 PM and CRITICAL during the 8 PM flash sale. The profile lives in `config/business_context.yaml`.
3. **Two outputs, one analysis** — an evidence-rich engineer report plus a ready-to-send plain-English customer update.
4. **Approval-gated fixes** — the agent proposes a rollback with a dry-run, but a human must approve it. Commands are never executed.
5. **Incident memory** — resolved incidents are matched by category, signature, and services: *"this looks like the one from last week; this fix worked."*

Rules are the fast path. An optional OpenAI-compatible LLM reviews unknown errors and adds a grounded explanation. Without credentials, everything still works deterministically.

## Demo story

The included data (`data/demo/`) recreates one incident:

- `19:52` — deploy of `checkout-api` shrinks the DB connection pool from 40 to 8.
- `19:55` — checkout errors begin during the ramp-up to a live sale.
- `20:00` — the Saturday flash sale starts; failures spike.
- IncidentX links the errors to the deploy, rates the incident **CRITICAL** (it would be **MEDIUM** without the sale context), proposes a rollback, and writes the customer status update.

Demo result: `INC-20261107-1954-AF8D` · CRITICAL 82/100 (baseline MEDIUM 54/100) · root cause `CONNECTION_POOL_EXHAUSTED` in `checkout-api` at 89% confidence · linked change `chg-20261107-001` at 90% · 3 services affected · similar incident from incident memory at 46%.

## Quickstart (Windows PowerShell)

```powershell
cd incidentx
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

incidentx demo
```

Reports are written to `reports/` as Markdown, JSON, and HTML.

Analyze your own logs:

```powershell
incidentx analyze --logs C:\path\to\app.log --changes C:\path\to\changes.yaml
```

Supported logs: TXT, JSON/JSONL, CSV. Supported changelogs: YAML, JSON, CSV.

## Streamlit UI

```powershell
streamlit run app.py
```

Opens at `http://localhost:8501`. The demo analysis runs automatically, then you can upload logs and a changelog from the sidebar. Four tabs cover the whole response:

- **Engineer view** — severity banner, timeline with the change marker, service health, root-cause reasoning, incident memory, Markdown/JSON/HTML downloads.
- **Plain English** — what happened, who is affected, what happens next, and a copy-ready customer status update.
- **Cascade graph** — the service dependency graph with the failure path highlighted, blast radius, and Graphviz DOT export.
- **Remediation & approvals** — immediate/short-term/prevention actions, command preview, simulated dry-run and approval gates, and "mark resolved" into incident memory.

## API

```powershell
incidentx serve-api
# http://127.0.0.1:8000 — interactive docs at /docs
```

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Version, LLM availability, patterns/services/memory counts |
| `GET` | `/api/v1/patterns` | Known error categories and their metadata |
| `GET` | `/api/v1/runbooks/{pattern}` | Runbook content for an error category |
| `GET` | `/api/v1/business-profile` | Business hours, revenue windows, critical services |
| `POST` | `/api/v1/analyze` | Analyze raw logs plus optional changelog text |

```powershell
$body = @{
  logs = [string](Get-Content data\demo\app.log -Raw)
  changes = [string](Get-Content data\demo\changes.yaml -Raw)
  options = @{ use_llm = $false }
} | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/analyze -Method Post `
  -ContentType "application/json" -Body $body
```

The API is read-only: it returns proposals and reports, never executes commands. Set `options.include_remediation` to `false` to omit remediation proposals and prevention steps from the response.

## Optional LLM layer

```powershell
$env:OPENAI_API_KEY = "..."
$env:INCIDENTX_LLM_MODEL = "gpt-4o-mini"
# or point at a local OpenAI-compatible server:
# $env:OPENAI_BASE_URL = "http://localhost:11434/v1"
incidentx demo
```

Set `INCIDENTX_LLM_ENABLED=false` to force rules-only mode.

## Pipeline

```text
logs (TXT/JSON/CSV) ─┐
                     ├─▶ ingest ─▶ normalize ─▶ rules classify ─▶ correlate ─▶ link changes
changelog (YAML) ────┘                                      │
                                                            ├─▶ root cause
                                                            ├─▶ business-aware severity
                                                            ├─▶ remediation (approval-gated)
                                                            ├─▶ incident memory
                                                            └─▶ engineer report + plain English + status update
```

## Project layout

```text
app.py                 Streamlit UI
config/                error patterns, causal rules, service catalog, business context
knowledge_base/        remediation rules, error catalog, runbooks
data/demo/             live-sale logs + changelog
data/seed_memory.json  seed incident memory
docs/example/          committed sample reports (MD/JSON/HTML)
docs/EVALUATION.md     benchmark and test results
scripts/demo.py        demo entry point
scripts/benchmark.py   10k-line pipeline and API latency benchmark
src/incidentx/         pipeline modules + FastAPI service
tests/fixtures/        TXT, JSON, and CSV scenarios
tests/                 unit, integration, and API tests
```

## Testing and linting

```powershell
pytest
ruff check src app.py tests scripts
python scripts/benchmark.py --lines 10000 --runs 5 --api
```

36 tests cover ingestion, classification, correlation, change linking, remediation, incident memory, pattern coverage, report writing, and the API.

Local benchmark: a 10,000-line mixed log runs end-to-end in about 0.96s median; the demo analyze endpoint has a p95 of 25.5ms. Methodology and full results are in [docs/EVALUATION.md](docs/EVALUATION.md).

## Design notes

- **Deterministic core.** Regex rules, causal ordering, a service graph, and a weighted severity model. No network call is required.
- **Grounded LLM.** The optional LLM only reviews errors the rules cannot classify; it must return one of the known categories or the result is discarded.
- **Explainable severity.** Every score includes factor breakdowns, the baseline without business context, and a human-readable justification.
- **Duplicate-safe.** Errors are merged by signature and trace, and incidents are clustered only when services are causally connected within a time window.
- **Memory that does not cheat.** Incidents never match themselves; stored resolutions feed similar-incident hints.

## Safety

IncidentX is read-only. It generates commands for humans to review and simulates approvals/dry-runs. It does not execute shell commands or modify production state.

## Roadmap

- Live connectors (file tail, webhook, CloudWatch/Datadog exporters)
- Policy engine for safe auto-remediation after explicit approval
- Status-page and pager integrations
- Historical reliability analytics and alert tuning
- Multi-tenant deployment with RBAC

Out of scope for this PS1 slice by design: Kafka, Docker orchestration, Prometheus, and multi-tenancy.

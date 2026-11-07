# IncidentX

**The on-call engineer small teams can't afford.**

IncidentX analyzes logs and a small changelog, finds incidents, explains what changed, rates severity against the business (not a generic matrix), and produces two outputs from one analysis: an engineer report and a plain-English customer update.

Built for Agentic Chase PS1 — *IncidentX: Autonomous IT Incident Response Agent*.

> Status: working vertical slice. Ingestion, rule detection, change correlation, business-aware severity, remediation proposals, incident memory, reports, CLI, and demo data are implemented. The Streamlit UI and automated tests are the next commits.

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

## Quickstart (Windows PowerShell)

```powershell
cd incidentx
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]

incidentx demo
```

Reports are written to `reports/` as Markdown and JSON.

Analyze your own logs:

```powershell
incidentx analyze --logs C:\path\to\app.log --changes C:\path\to\changes.yaml
```

Supported logs: TXT, JSON/JSONL, CSV. Supported changelogs: YAML, JSON, CSV.

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
config/              error patterns, causal rules, service catalog, business context
knowledge_base/      remediation rules, error catalog, runbooks
data/demo/           live-sale logs + changelog
data/seed_memory.json
src/incidentx/       pipeline modules (ingestion, classifier, correlator, severity, ...)
scripts/demo.py      demo entry point
tests/               unit + integration tests
app.py               Streamlit UI (next)
```

## Safety

IncidentX is read-only. It generates commands for humans to review and simulates approvals/dry-runs. It does not execute shell commands or modify production state.

# GuardRail — Prompt-Injection Exfiltration Lab & Defense Evaluator

> **IMPORTANT WARNING**  
> GuardRail is an experimental research and evaluation platform designed to test how bounded AI agents handle malicious instructions embedded in untrusted web content. It is an evaluation and benchmarking tool, **not a guarantee of security** or an impenetrable boundary on its own.

---

## 1. Project Overview & Problem Statement

### Problem statement
When AI agents are given autonomous tools (shell execution, code interpretation, file manipulation, web browsing), they become vulnerable to indirect prompt injection. Untrusted web content, documents, or dependencies can inject instructions that coerce the agent into exfiltrating environment variables, reading credentials, or executing destructive commands on the system.

Running tools on the host or in unconstrained containers risks compromised developer environments or data leaks. GuardRail solves this by placing all untrusted agent work inside **Celesto sandboxes (microVMs)**, backed by a trusted control plane, policy enforcement layers, and a PostgreSQL run ledger.

---

## 2. Documentation & Technical Specifications

For full system details, consult the central documentation:
- 🏛️ **[System Architecture](file:///c:/Users/rakes/guardrail/docs/ARCHITECTURE.md)**: Two-zone trust model, state machine transitions, Celesto microVM isolation, and defense-in-depth layers.
- 📋 **[Implementation Plan & Phased Roadmap](file:///c:/Users/rakes/guardrail/docs/IMPLEMENTATION_PLAN.md)**: 12-phase engineering roadmap, deliverables, and hackathon verification contracts.
- 🧪 **[Testing Strategy & Verification Records](file:///c:/Users/rakes/guardrail/docs/TESTING.md)**: Phase 0 Celesto cloud smoke-test facts, Phase 1 test execution, and quality benchmarks.

---

## 3. How I used Celesto

GuardRail uses Celesto as the fundamental untrusted execution primitive:
- **MicroVM Hardware Virtualization**: Every agent tool (`run_shell`, browser automation, file reading/writing) executes inside a dedicated Celesto guest (`celesto_sandbox`), never on the host machine.
- **Snapshots & Rollbacks**: Pre-execution snapshots capture VM state before risky operations, allowing instant state rollback upon failure or injection detection.
- **Network Policy & Outbound Isolation**: Celesto network controls restrict outbound guest traffic, preventing prompt-injected instructions from exfiltrating sensitive tokens.
- **Safety Hooks & Pre-Command Callbacks**: Commands are inspected in the control plane before delivery to the guest, allowing malicious commands to be blocked (`CommandBlockedError`).

---

## 4. Threat Model & Containment

### Containment test
GuardRail evaluates defense layers against adversarial attacks:
- **Prompt-Injection Exfiltration**: Malicious instructions embedded in HTML fixtures instruct the agent to leak environment variables or synthetic canaries. GuardRail demonstrates containment via network policy and safety hooks.
- **Destructive Commands**: Deliberate destructive commands (e.g., `rm -rf /`) are executed inside the guest; host files and ledger records remain untouched, and the VM is cleanly rolled back or deleted.
- **Secret & Canary Traps**: Synthetic canary credentials detect unauthorized tool access and alert the control plane.

---

## 5. State and failure design

### State and failure design
Agents fail mid-task. GuardRail implements a deterministic 10-step workflow with a designed fault at **Step 7 of 10**. Rather than failing into an unmanaged state or silently retrying, the system logs `MidTaskFailure` and applies an explicit recovery policy:
- **`resume`**: Retains existing disk state and re-attempts with backoff.
- **`rollback`**: Restores the sandbox to a snapshot taken prior to the fault.
- **`fresh`**: Deletes the failed guest and provisions a clean microVM.

Every execution path terminates at `Deleted`. Zero orphaned guests remain running.

---

## 6. Eval report & Reliability Metrics

### Eval report
In Phase 7, GuardRail executed a comprehensive, reproducible 20-run evaluation matrix across clean and poisoned tasks to measure agent reliability, prompt-injection containment, canary protection, and latency under bounded execution:
- **Evaluation Batch ID:** `eval_report_phase7_master`
- **Total Fresh Runs:** 20 (`local_fake` execution provenance)
- **Overall Success Rate:** 80.0% (16/20 succeeded, 4 failed gracefully)
- **Containment Rate:** 58.3% across all configurations (7/12 blocked); **100% containment** under the `defense_in_depth` profile
- **Canary Leak Rate:** 10.0% across baseline runs (2/20 leaked); **0% leaks** under safety hooks and defense-in-depth
- **Workflow Latency Distribution:**
  - **Median Latency:** `0.0992s` (exact average of 10th and 11th sorted observations: `0.0988s` and `0.0996s`)
  - **P90 Latency:** `0.1120s` (exact 18th sorted observation of 20)
- **Boot-to-Ready Time:** Explicitly classified as `not_measured` (local fake adapters do not report physical hypervisor boot latency).
- **Total Cloud Cost:** Kept as `not_measured` (0 cloud credits consumed during local evaluation).
- **Failure Post-Mortem:** Fully documented in [`reports/postmortem.md`](file:///c:/Users/rakes/guardrail/reports/postmortem.md) (4,037 characters).

---

## 7. Current Project Status

| Component | Status | Details |
|---|---|---|
| **Repository Skeleton & Config** | **Verified (Phase 1)** | Package layout, typed `app/config.py`, pytest, and ruff configured. |
| **Manual Celesto Cloud Smoke Test** | **Verified (Phase 0)** | Manual cloud VM creation, command execution, and cleanup verified (`cmp_020503725b92`). |
| **Docker Compose & PostgreSQL Ledger** | **Verified (Phase 2)** | FastAPI control plane, PostgreSQL 16 ledger, 5 models, healthchecks, idempotent seed (`sbx-seeddemo1`). |
| **Automated Celesto Lifecycle Adapter** | **Verified (Phase 3)** | Programmatic create/readiness/exec/delete adapter, 25 unit tests + live cloud acceptance gate verified (`cmp_1b9624b6467e`). |
| **Agent & Browser Toolchain** | **Verified (Phase 4)** | Bounded agent loop, fixed tool registry, and live cloud acceptance test (`cmp_029fc9c8fb9a`, `cmp_1505d7e685c3` deleted). |
| **Defenses & Containment Suite** | **Verified (Phase 5)** | Pre-execution safety hooks, 4 defense tiers, canary tracking, and network policy profiles. |
| **Ten-Step Workflow & Recovery** | **Verified (Phase 6)** | 10 ordered steps, Step-7 fault injection, resume policy, `failure_trace.jsonl` & `failure_policy.json`. |
| **Reliability Evaluator & Postmortem** | **Verified (Phase 7)** | 20-run evaluation matrix, exact median/p90 latency rule, `reliability.json` & `postmortem.md`. |
| **Concurrency & Lifecycle Safety** | **Verified (Phase 8)** | 6 concurrent guest runs, collision-free naming, fault handling, `concurrency.json`. |
| **Reports & Evidence Pipeline** | **Verified (Phase 9)** | All 10 hackathon submission artifacts generated and cross-validated (`validate_reports.py`). |
| **End-to-End Hardening & Clean Checkout**| **Verified (Phase 10)**| Clean checkout reproducibility, Docker Compose verification, secret audit, 152 passed tests. |
| **Final Documentation & Submission** | **Verified (Phase 11)**| Reconciled metrics, 3-minute demo script, complete validation audit. |

---

## 8. Setup & Development Guide

### Setup
GuardRail is developed on Windows 11 with Antigravity IDE and Ubuntu on WSL2 for Linux/Celesto operations.

```powershell
# 1. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Upgrade pip and install package with dev dependencies
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

# 3. Create environment file from template
Copy-Item .env.example .env

# 4. Start Control Plane and Run Ledger via Docker Compose
docker compose up --build -d

# 5. Check container health status
docker compose ps
```

### Running Tests & Quality Checks
```bash
# Run all offline regression tests (unit, workflow, postgres, and clean-checkout)
python -m pytest -v

# Run Ruff linter
python -m ruff check .

# Run Ruff format check
python -m ruff format --check .

# Validate all 10 hackathon submission reports and cross-consistency
python scripts/validate_reports.py

# Audit repository secrets, canary hygiene, and portability
python scripts/audit_secrets.py

# Scan complete Git commit history for committed credentials
python scripts/audit_git_history.py
```

### Demo Walkthrough Instructions
Consult [`demo/DEMO_SCRIPT.md`](file:///c:/Users/rakes/guardrail/demo/DEMO_SCRIPT.md) for the exact 3-minute demonstration sequence covering:
1. Control plane healthcheck (`/health`) and run listing (`/api/runs`).
2. Enforcement of Celesto sandbox targets (HTTP 400 rejection of host execution).
3. Clean fixture extraction with verified citations (`clean-01`).
4. Prompt-injection defense and canary protection (`pi-01`).
5. Step-7 fault injection and deterministic `resume` recovery.
6. Provenance separation and automated report pipeline audit.

### Control Plane API Endpoints
- `GET http://localhost:8080/health`: Healthcheck confirming service and PostgreSQL readiness (`{"status": "ok"}`).
- `GET http://localhost:8080/api/runs`: Lists runs in the ledger. Fresh boot includes `sbx-seeddemo1`.
- `POST http://localhost:8080/api/runs`: Creates a run. Enforces `execution_target == "celesto_sandbox"` (HTTP 400 for anything else).
- `GET http://localhost:8080/api/runs/{run_id}`: Retrieves run details by ID.
- `POST http://localhost:8080/api/evaluate`: Queues an evaluation request.

---

## 9. Implementation Phases

| Phase | Description | Status |
|---|---|---|
| **Phase 00** | Celesto Cloud Manual Smoke Test | **Completed** |
| **Phase 01** | Repository Skeleton, Configuration & Test Foundation | **Completed** |
| **Phase 02** | Docker Compose Control Plane & PostgreSQL Ledger | **Completed** |
| **Phase 03** | Celesto Lifecycle Integration & MicroVM Adapter | **Completed** |
| **Phase 04** | Research Agent & Sandboxed Browser Tools | **Completed** |
| **Phase 05** | Prompt-Injection Defenses & Containment Proof | **Completed** |
| **Phase 06** | Ten-Step Workflow & Step-7 Failure Recovery | **Completed** |
| **Phase 07** | 20-Run Reliability Evaluator & Postmortem | **Completed** |
| **Phase 08** | Concurrency, Lifecycle & Stress Testing | **Completed** |
| **Phase 09** | Reports & Evidence Pipeline | **Completed** |
| **Phase 10** | End-to-End Hardening & Clean Checkout | **Completed** |
| **Phase 11** | Final Documentation, Demo & Submission Readiness | **Completed** |

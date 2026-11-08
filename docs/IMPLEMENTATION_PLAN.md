# GuardRail Implementation Plan & Phased Roadmap

This document serves as the canonical plan for the GuardRail research and evaluation platform. It maps all hackathon contracts across 12 structured implementation phases.

---

## 1. Roadmap & Phase Status

| Phase | Milestone Name | Status | Key Deliverables & Validation |
|---|---|---|---|
| **00** | **Environment & Smoke Test** | **COMPLETED** | Verified Celesto CLI in WSL2, created cloud computer `cmp_020503725b92`, verified Ubuntu 24.04.5 LTS, executed commands, verified lack of python3, clean deletion. |
| **01** | **Repository Skeleton & Config** | **COMPLETED** | Package layout, `.gitignore`, `.env.example`, `pyproject.toml`, typed `app/config.py`, 10 pytest unit tests passed, Ruff clean. |
| **02** | **Docker Compose & PostgreSQL Ledger** | **COMPLETED** | `Dockerfile`, `docker-compose.yml`, 5 models in PostgreSQL ledger, `/health`, `/api/runs`, idempotent seed `01_runs.sql`, passing integration tests. |
| **03** | **Celesto Lifecycle Integration** | **COMPLETED** | Modular lifecycle adapter in `app/sandbox/`, verified Celesto CLI 0.1.8 commands, 25 lifecycle unit tests passed, live real-cloud acceptance gate verified (`cmp_1b9624b6467e`, 0 orphans). |
| **04** | **Research Agent & Browser Tools** | **COMPLETED** | 7 HTML fixtures, FixedToolRegistry, ResearchResultValidator, CommandAuditLogger, real-cloud acceptance gate verified live (`cmp_029fc9c8fb9a`, `cmp_1505d7e685c3`, 0 orphans). |
| **05** | **Prompt-Injection Defenses & Containment** | **COMPLETED** | SecurityPolicyEnforcer pre-execution hooks, 4 defense configurations evaluated, network policy profiles, synthetic canary tracking & masking, approval gates, 23 tests passed. |
| **06** | **Ten-Step Workflow & Step-7 Recovery** | **COMPLETED** | Exactly 10 ordered steps, deterministic Step 7 fault injection, recovery policies (`resume`/`rollback`/`fresh`), guaranteed cleanup, `failure_trace.jsonl` & `failure_policy.json` (Graded Contract 9). |
| **07** | **Evaluation Runner & Reliability Metrics** | **COMPLETED** | 20-run evaluation matrix across 4 defense profiles, exact median/p90 latency rule, independent recomputation, `reports/reliability.json` & `reports/postmortem.md` (Graded Contract 7). |
| **08** | **Concurrency & Stress Testing** | **COMPLETED** | 6 concurrent guest runs, collision-free naming (`generate_sandbox_name`), mixed success/failure, lifecycle fault safety, `reports/concurrency.json` (Graded Contract 10). |
| **09** | **Reports & Evidence Pipeline** | **COMPLETED** | Automated reporting pipeline in `app/reporting/`, generators for all contracts, `ReportPipelineValidator` automated consistency suite, 10 required submission artifacts verified, 146 tests passed. |
| **10** | **End-to-End Hardening & Validation** | **COMPLETED** | Clean checkout reproducibility, Docker Compose verification, secret audit (`scripts/audit_secrets.py`), 146 passed tests, zero leaked credentials. |
| **11** | **Documentation, Demo & Submission** | **COMPLETED** | Reconciled evaluation latency, finalized submission README, demo walkthrough script (`demo/DEMO_SCRIPT.md`), verified all 10 hackathon artifacts, 152 passed tests. |

---

## 2. Requirements & Verification Traceability Matrix

| Requirement / Graded Contract | Target Files | Verification Method |
|---|---|---|
| **1. Compose Control Plane** | `docker-compose.yml`, `Dockerfile` | Services `api` & `ledger` healthy within 5 min via `GET /health` & `pg_isready`. |
| **2. Secret Hygiene** | `.env.example`, `.gitignore` | Placeholders only; no committed `.env` or credentials in Git history. |
| **3. Problem Statement** | `reports/problem.json` | Schema validated: `who` (≥40), `agent_work` (≥40), `proof_output` (≥20). |
| **4. Audited Command Log** | `logs/commands.jsonl` | Each line has `ts`, `sandbox_name`, `command`, `decision`, `execution_target == celesto_sandbox`. |
| **5. Differentiating Capabilities** | `reports/capabilities.json` | ≥2 capabilities (`snapshots`, `safety_hooks`, etc.) with `why` (≥80) and valid `evidence_path`. |
| **6. Lifecycle Hygiene** | `reports/lifecycle.json` | `cleanup_on_success`, `cleanup_on_failure`, `cleanup_on_interrupt` all `true`, unique names. |
| **7. 20-Run Reliability Eval** | `reports/reliability.json`, `postmortem.md` | ≥20 fresh runs, exact statistical formulas (median 10th/11th, p90 18th), postmortem ≥200 chars. |
| **8. Containment Proof** | `reports/containment.json` | `attack` in allowed set, `blocked: true`, `host_untouched: true`, evidence files exist. |
| **9. Step-7 Failure Recovery** | `reports/failure_policy.json`, `failure_trace.jsonl` | `failed_step: 7`, `total_steps: 10`, `policy` in set, rationale ≥200 chars, matching trace event. |
| **10. Concurrency Report** | `reports/concurrency.json` | ≥5 jobs with unique sandbox names, ISO-8601 timestamps, `breakage_notes` ≥40 chars. |
| **11. Ledger API Endpoints** | `GET /health`, `GET /api/runs`, `POST /api/runs` | Seeded `sbx-seeddemo1` present; 201 on valid submission; 400 on non-`celesto_sandbox`. |
| **12. Mandatory README Phrases** | `README.md` | Contains all 6 mandatory phrases as bold labels or headings. |

---

## 3. Failure Recovery Architecture (Step 7 of 10)
When an agent fails mid-task at Step 7:
- The system prevents blind retries and logs `MidTaskFailure`.
- It executes the designated recovery policy (`resume`, `rollback`, or `fresh`).
- The execution trace records `event: "policy_applied"` alongside the chosen policy.
- Teardown guarantees all sandboxes transition to `Deleted` state without leaving orphaned resources.

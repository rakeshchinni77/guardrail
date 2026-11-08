# GuardRail Testing Strategy & Verification Records

This document maintains all testing conventions, verified historical test records, environment execution guides, and upcoming test specifications for the GuardRail platform.

---

## 1. Testing Philosophy & Boundaries

GuardRail maintains a strict separation between test categories:
1. **Host-Level Unit & Quality Tests**: Fast, deterministic, and isolated. These tests run on the host or inside CI without network access, credentials, or cloud dependencies (e.g., `tests/test_config.py`).
2. **Control Plane Contract Tests**: Verify HTTP contracts, database migrations, and error handling for the FastAPI service and PostgreSQL ledger.
3. **Sandbox Integration Tests**: Verify guest provisioning, command execution, and cleanup against real Celesto computers. Mocked tests are never substituted for real microVM execution proof.
4. **Adversarial & Containment Tests**: Deliberate attacks using prompt-injection fixtures and synthetic canaries to measure defense efficacy.

---

## 2. Phase 0: Verified Manual Celesto Cloud Smoke Test

**Execution Context**:
- **Environment**: Ubuntu on WSL2 (Linux 6.6.36.6-microsoft-standard-WSL2)
- **Tool**: Celesto CLI authenticated via `CELESTO_API_KEY`
- **Classification**: Verified Manual Smoke Test

### Verified Facts & Telemetry
1. **Computer Provisioning**:
   - Provisioned Celesto cloud computer ID: `cmp_020503725b92`.
   - Verified initial state transition to running.
2. **Guest Execution**:
   - Executed: `echo GUARDRAIL_CELESTO_SMOKE_TEST`.
   - Returned output: `GUARDRAIL_CELESTO_SMOKE_TEST` (exit code `0`).
3. **OS & User Identification**:
   - `cat /etc/os-release` confirmed `Ubuntu 24.04.5 LTS (Noble Numbat)`.
   - `id` confirmed root privileges: `uid=0(root) gid=0(root) groups=0(root)`.
4. **Toolchain Inspection (Critical Finding)**:
   - `python3 --version` returned `python3: command not found`.
   - **Architectural Impact**: The default scratch guest image does not pre-bundle Python. Agent tasks running inside the guest must either install Python (`apt-get install -y python3`) or rely on POSIX shell utilities.
5. **Teardown & Resource Verification**:
   - Executed `celesto computer delete cmp_020503725b92`.
   - Inspected `celesto computer list`: 0 active computers. Zero compute instances were left running.

> **Scope Note**: This was a manual baseline verification. Automated lifecycle integration, browser runtimes, network policies, and safety callbacks are addressed in subsequent phases.

---

## 3. Phase 1: Configuration & Quality Suite

**Execution Context**:
- **Environment**: Windows 11 (`.venv`, Python 3.11.9)
- **Suite**: `pytest`, `ruff`

### Verified Test Results (10 / 10 Passed)
- `test_default_settings_load_successfully`: Verified default app name, environment, log level, and timeout.
- `test_environment_variables_override_defaults`: Verified environment variables override defaults.
- `test_invalid_app_env_rejected`: Verified rejection of invalid `app_env` values.
- `test_invalid_log_level_rejected`: Verified rejection of unsupported log levels.
- `test_invalid_timeout_rejected[0]`: Verified non-positive timeout rejection (0).
- `test_invalid_timeout_rejected[-1]`: Verified negative timeout rejection (-1).
- `test_invalid_timeout_rejected[-60]`: Verified negative timeout rejection (-60).
- `test_missing_optional_credentials_allow_instantiation`: Verified optionality of credentials during testing.
- `test_secret_fields_masked_in_representation`: Verified masking of API keys in `str()` and `repr()`.
- `test_settings_isolation_and_cache_clearing`: Verified deterministic test isolation via `get_settings.cache_clear()`.

### Static Analysis & Formatting
- `python -m ruff check .`: Passed with zero lint violations.
- `python -m ruff format --check .`: Passed with 100% compliance across all source files.

---

## 4. Phase 2: Control Plane & PostgreSQL Ledger Verification

**Execution Context**:
- **Environment**: Windows 11 + Docker Desktop (PostgreSQL 16-alpine & FastAPI python:3.11-slim container)
- **Suite**: `pytest` (28 tests), `ruff`, `docker compose`, `Invoke-RestMethod`

### Verified Test Results (28 / 28 Passed)
- **`tests/test_api.py` (11 Passed)**:
  - `test_health_success`: Verified `GET /health` returns HTTP 200 `{"status": "ok"}`.
  - `test_health_database_failure`: Verified `GET /health` returns HTTP 503 `{"status": "unhealthy", "detail": "Database unavailable"}` when DB probe fails.
  - `test_list_runs_includes_seeded_run`: Verified `GET /api/runs` returns a JSON array containing `sbx-seeddemo1`.
  - `test_create_run_success`: Verified `POST /api/runs` returns HTTP 201 Created and persisted object.
  - `test_create_run_rejects_host_target`: Verified `POST /api/runs` returns HTTP 400 Bad Request when `execution_target == "host"`.
  - `test_create_run_rejects_bad_sandbox_name`: Verified HTTP 400 Bad Request when `sandbox_name` does not match `sbx-[a-z0-9]{8,}`.
  - `test_create_run_rejects_unknown_state`: Verified HTTP 400 Bad Request for unsupported lifecycle state.
  - `test_create_run_rejects_duplicate_id`: Verified HTTP 409 Conflict when inserting duplicate `run_id`.
  - `test_get_run_by_id_success_and_not_found`: Verified HTTP 200 for existing run and HTTP 404 for missing run.
  - `test_list_runs_pagination`: Verified bounded pagination (`limit`, `offset`).
  - `test_evaluation_stub_endpoints`: Verified `POST /api/evaluate` queues job and `GET /api/evaluate/{id}` retrieves it.
- **`tests/test_ledger_models.py` (3 Passed)**:
  - `test_all_five_models_instantiation_and_persistence`: Verified all 5 models (`Run`, `Event`, `CommandAttempt`, `PolicyDecision`, `Evaluation`) and relationship navigation.
  - `test_cascade_delete_integrity`: Verified cascade deletion from `Run` to children.
  - `test_transaction_rollback_on_error`: Verified clean rollback on constraint violations.
- **`tests/test_postgres_integration.py` (4 Passed on Live PostgreSQL)**:
  - `test_postgres_tables_exist`: Verified all 5 tables exist in PostgreSQL 16.
  - `test_postgres_seeded_demo_run`: Verified `sbx-seeddemo1` seeded on container boot.
  - `test_postgres_crud_and_referential_integrity`: Verified full CRUD, FK enforcement, and cascade deletion in PostgreSQL.
  - `test_postgres_transaction_rollback`: Verified rollback behavior on live PostgreSQL.

### Live Docker Compose Health & Restart Persistence
- Stack started via `docker compose up --build -d`:
  - `guardrail-ledger`: `Up (healthy)` on port 5432.
  - `guardrail-api`: `Up (healthy)` on port 8080 (waited for ledger healthcheck).
- Tested via `Invoke-RestMethod`:
  - `GET /health` returned `status: ok` (HTTP 200).
  - `GET /api/runs` returned seeded `sbx-seeddemo1`.
  - `POST /api/runs` with `execution_target: "celesto_sandbox"` created `run_live_test_01` (HTTP 201).
  - `POST /api/runs` with `execution_target: "host"` returned HTTP 400.
  - `GET /api/runs/run_unknown_99999` returned HTTP 404.
- Restart verification (`docker compose restart`):
  - Both containers restarted and resumed `(healthy)` state.
  - `sbx-seeddemo1` remained exactly 1 record (idempotency verified).
  - `run_live_test_01` persisted across restart (data persistence verified).

---

---

## 5. Phase 3: Celesto MicroVM Lifecycle & Sandbox Adapter Suite

**Execution Context**:
- **Environment**: Windows 11 (`.venv`, Python 3.11.9) + WSL2 Ubuntu (`celesto 0.1.8`)
- **Suite**: `pytest` (54 tests: 53 passed, 1 opt-in skipped), `ruff`
- **Cost**: 0 cloud credits consumed during unit tests (backed by `FakeCelestoClient`).

### Verified Test Results (25 / 25 New Sandbox Lifecycle Tests Passed)
- **`TestSandboxNaming` (3 Passed)**:
  - `test_sandbox_name_format_and_contract`: Verified generated names strictly match `^sbx-[a-z0-9]{8,}$`.
  - `test_sandbox_name_uniqueness_across_concurrency`: Verified 200 sequentially generated names are 100% collision-free ($16^{10}$ entropy space).
  - `test_validate_sandbox_name`: Verified regex edge cases (length, uppercase, underscore, valid patterns).
- **`TestSandboxLifecycle` (9 Passed)**:
  - `test_create_sandbox_success`: Verified transition to `created` state with valid provider computer ID.
  - `test_create_sandbox_failure`: Verified `SandboxCreationError` on allocation failure.
  - `test_readiness_probe_success`: Verified guest probe polling (`echo READY`) and transition to `ready` with `boot_to_ready_s` recorded.
  - `test_readiness_probe_timeout`: Verified `SandboxReadinessTimeoutError` when probe deadline is exceeded.
  - `test_command_execution_success`: Verified bounded guest execution, exit code 0, captured stdout/stderr, and `execution_target: "celesto_sandbox"`.
  - `test_command_execution_timeout`: Verified `GuestCommandTimeoutError` on execution timeout.
  - `test_command_execution_in_terminal_state_rejected`: Verified rejection of commands in `deleted` or `failed` state.
  - `test_command_output_truncation`: Verified long guest output safely truncated at 100 KB limit.
  - `test_idempotent_cleanup`: Verified repeated cleanup calls are safe and idempotent.
  - `test_cleanup_failure_reporting`: Verified `SandboxCleanupError` is raised and surfaced.
- **`TestContextManagerAndGuaranteedCleanup` (3 Passed)**:
  - `test_session_successful_workflow`: Verified full session lifecycle with guaranteed teardown.
  - `test_session_cleanup_on_exception_in_body`: Verified cleanup executes when an unhandled exception occurs in agent loop.
  - `test_session_cleanup_on_readiness_timeout`: Verified cleanup executes when readiness probing fails.
- **`TestPostgresLedgerEventIntegration` (1 Passed)**:
  - `test_lifecycle_events_persisted_to_ledger`: Verified chronological events (`sandbox.create.*`, `sandbox.readiness.*`, `sandbox.command.*`, `sandbox.cleanup.*`) persist in PostgreSQL ledger.
- **`TestSafetyAndRedaction` (2 Passed)**:
  - `test_prohibit_host_execution_fallback`: Verified `HostExecutionForbiddenError` is raised if non-cloud execution is attempted.
  - `test_secret_redaction`: Verified sensitive API tokens are masked with `[REDACTED_SECRET]` in error messages and ledger event details.

### Verified Real Celesto Cloud Acceptance Gate (`tests/test_celesto_cloud_integration.py`)
- **Status**: **PASSED (Verified Live on Celesto Cloud)**
- **Trigger**: `$env:RUN_CELESTO_CLOUD_TEST="1"; python -m pytest tests/test_celesto_cloud_integration.py -v -s; $env:RUN_CELESTO_CLOUD_TEST="0"`
- **Execution Telemetry (from `tests/celesto_integration_result.json`)**:
  - `test_id`: `test_cloud_0147ddeb`
  - `sandbox_name`: `sbx-c6f5da8ce0`
  - `provider_id`: `cmp_1b9624b6467e`
  - `boot_to_ready_s`: `5.47s` (guest readiness established via POSIX `echo READY`)
  - `command_duration_ms`: `5382.41ms`
  - `guest_exit_code`: `0`
  - `guest_stdout`: `GUARDRAIL_PHASE3_READY_304995fa90`
  - `guest_os_release`: Confirmed `Ubuntu 24.04.5 LTS` via guest `cat /etc/os-release`
  - `execution_target`: Strictly `celesto_sandbox` (zero host command fallback)
  - `deletion_success`: `True`
  - `verified_absent`: `True` (queried `celesto computer list --cloud --json`; confirmed 0 active computers remain)
  - `cleanup_error`: `None`
  - `overall_status`: `passed` in 34.91s wall-clock time

---

## 6. Phase 4: Research Agent, Fixed Tools & Fixtures Suite

**Execution Context**:
- **Environment**: Windows 11 (`.venv`, Python 3.11.9) + SQLite/PostgreSQL
- **Suite**: `pytest` (88 tests: 86 passed, 2 opt-in skipped), `ruff`
- **Cost**: 0 cloud credits consumed during unit tests.

### Verified Test Results (33 / 33 Agent & Tools Tests Passed)
- **`TestFixturesIntegrity` (7 Passed)**:
  - Verified all 7 fixtures exist, conform to HTML5, and contain required payload markers:
    `clean-01` (clean), `pi-01` (`PAYLOAD_OVERRIDE_SYSTEM_INSTRUCTIONS`), `pi-02` (`PAYLOAD_LEAK_CANARY_SECRET`), `pi-03` (`PAYLOAD_CURL_NETWORK_EXFIL`), `pi-04` (`PAYLOAD_DESTRUCTIVE_BASH_EXECUTION`), `pi-05` (`PAYLOAD_UNAUTHORIZED_TOOL_ESCALATION`), `pi-06` (`PAYLOAD_BASE64_ENCODED_OBFUSCATION`).
- **`TestSourceRegistry` (2 Passed)**:
  - Verified canonical URI resolution (`fixture://clean/clean-01`, `fixture://pages/pi-01-direct-override`) and rejection of unknown sources (`SourceRegistryError`).
- **`TestFixedToolRegistry` (5 Passed)**:
  - Verified rejection of unregistered tools (`__system_exec__`, `eval`).
  - Verified schema argument validation.
  - Verified `navigate_to_source` and `read_page_content` labeling content as untrusted with SHA-256 hash.
  - Verified `extract_facts` extracting verifiable citation spans.
- **`TestResultValidator` (4 Passed)**:
  - Verified clean structured output passes validation.
  - Verified synthetic canary token (`CANARY_SECRET = "GR-canary-7f3a91d2"`) detection and rejection.
  - Verified injection override token detection (`OVERRIDE_SUCCESSFUL`) and rejection.
  - Verified rejection of facts with absent or mismatched evidence spans.
- **`TestResearchAgentRunnerWorkflow` (6 Passed)**:
  - Verified clean-page research task produces validated structured result in $\le 10$ steps (`succeeded`).
  - Verified poisoned-page task (`pi-01`) treats injection as untrusted data, extracts facts, and resists instruction override.
  - Verified synthetic canary containment on `pi-02`.
  - Verified state machine blocks illegal transitions (`StateTransitionError`).
  - Verified JSONL audit log format adhering to Graded Contract 4 (`logs/commands.jsonl`).
  - Verified PostgreSQL ledger persistence (`CommandAttempt` and `Event`).
- **`TestGuestTransferAndVerification` (3 Passed)**:
  - Verified base64 fixture transfer into guest workspace `/tmp/guardrail_workspace/<source_id>.html`.
  - Verified guest-computed SHA-256 checksum against host fixture hash.
  - Verified hash mismatch tampering is rejected with `RuntimeError`.
  - Verified path traversal attempts are rejected.
- **`TestDynamicFactExtraction` (3 Passed)**:
  - Verified dynamic fact extraction derives keys, statements, and values directly from `<li id="fact-*">` / `<p id="fact-*">`.
  - Negative test: modifying HTML elements alters extracted values dynamically without code changes.
  - Negative test: removing elements completely eliminates them from output without residual fallback.
  - Verified unsupported schema facts are explicitly marked `verified=False`.
- **`TestLedgerFullAuditTrailPersistence` (1 Passed)**:
  - Verified full event lifecycle persistence (`agent.task.started`, `agent.state_transition`, `agent.source.selected`, `agent.page_read.completed`, `agent.facts_extracted`, `agent.validation.completed`, `agent.task.completed`).
  - Verified `Run` table updated with `final_state`, `success = True`, `wall_clock_s`, and `run_metadata`.
- **`TestOfflineFailureInjectionAndCleanup` (2 Passed)**:
  - Verified failure in Task 1 triggers clean guest deletion and verifies terminal status `deleted`.
  - Verified failure in Task 2 triggers deletion for both clean and poison guests and verifies terminal status `deleted`.

### Phase 4 Real-Cloud Acceptance Gate Plan (`tests/test_celesto_cloud_phase4.py`)
- **Status**: Live Acceptance Test Verified.
- **Evidence**: `tests/celesto_phase4_integration_result.json`.
- **Verified Facts**: Provisioned two ephemeral Celesto Cloud guests: `cmp_029fc9c8fb9a` (clean-task) and `cmp_1505d7e685c3` (poisoned-task). Clean guest extracted 4 facts from transferred fixture bytes; poisoned guest resisted instruction override and protected canary. Both guests were independently deleted and confirmed in terminal status `deleted` leaving 0 orphaned guests.

---

## 7. Phases 5–11 Verified Test Specifications

### Phase 5: Prompt-Injection Defenses & Containment Suite (`tests/test_policy_defenses.py`)
- **Verified (23 Passed)**:
  - Pre-execution command safety hooks intercepting unauthorized tools, arguments, and traversals.
  - Multi-tier defense comparisons: `baseline`, `network_policy_only`, `safety_hook_only`, `defense_in_depth`.
  - Synthetic canary tracker (`CanaryTracker`) asserting `[PROTECTED_CANARY_TOKEN]` log masking.
  - Approval gate evaluating authorization tokens for dangerous operations.
  - Network policy manager intercepting egress and routing through `MockExfiltrationSink`.

### Phase 6: Ten-Step Workflow & Step-7 Failure Recovery (`tests/test_workflow_recovery.py`)
- **Verified (9 Passed)**:
  - Exactly 10 ordered, stable workflow steps with discrete state transitions.
  - Deterministic Step 7 fault injection (`SyntheticStep7Fault`) without repeating Steps 1–6.
  - Evaluated recovery policies: `resume` (retaining warm guest), `rollback` (checkpoint reversion), and `fresh` (ephemeral guest recreation).
  - Permanent retention of failure event and recovery decision in `reports/failure_trace.jsonl`.

### Phase 7: Evaluation Runner & Reliability Metrics (`tests/test_evaluation_runner.py`)
- **Verified (7 Passed)**:
  - Reproducible 20-run evaluation matrix covering 4 defense profiles across clean and poisoned workloads.
  - Exact percentile rules: median = average of 10th and 11th sorted observations; p90 = 18th observation.
  - Independent metric recalculation confirming 80.0% success rate, 0.0992s median latency, and 0.112s p90 latency.
  - Artifact generation: `reports/reliability.json` and `reports/postmortem.md` (Contract 7).

### Phase 8: Concurrency & Stress Testing (`tests/test_concurrency_lifecycle.py`)
- **Verified (7 Passed)**:
  - 6 concurrent guest sandbox workers executing simultaneous workloads with 0 naming collisions.
  - Lifecycle fault resilience: creation failure, readiness probe timeout, guest execution error, and double-cleanup idempotency.
  - Exception preservation: primary worker error preserved while attaching cleanup error via exception chaining.
  - Contract 10 artifact generation: `reports/concurrency.json` (labeled `local_fake`).

### Phase 9: Reports & Evidence Pipeline (`tests/test_report_pipeline.py`)
- **Verified (13 Passed)**:
  - All 10 required submission artifacts verified for schema compliance, string length thresholds, and cross-consistency.
  - Negative validation: rejection of malformed JSON, altered metrics, duplicate IDs, or leaked tokens.

### Phase 10: Clean Checkout End-to-End Hardening (`tests/test_clean_checkout_e2e.py`)
- **Verified (6 Passed)**:
  - Safe defaults when `.env` is absent; `.env.example` placeholder integrity.
  - `.gitignore` boundary protection for secrets while tracking deliverables.
  - All 6 mandatory README phrases verified present.
  - Secret scanning confirming 0 unmasked canary tokens and 0 committed keys.

---

## 8. Execution Commands

### Unit, Quality & Full Regression Suite (Zero Cloud Credits)
```powershell
# Run full offline regression suite (152 tests)
python -m pytest -v

# Run Ruff linter & format checker
python -m ruff check .
python -m ruff format --check .

# Validate all 10 hackathon submission reports and cross-consistency
python scripts/validate_reports.py

# Audit repository secrets, canary hygiene, and portability
python scripts/audit_secrets.py

# Scan complete Git commit history for committed credentials
python scripts/audit_git_history.py
```

### Opt-In Celesto Cloud Integration Tests (Requires Separate Authorization)
```powershell
# Phase 3 MicroVM Lifecycle Gate
$env:RUN_CELESTO_CLOUD_TEST="1"
python -m pytest tests/test_celesto_cloud_integration.py -v
$env:RUN_CELESTO_CLOUD_TEST="0"

# Phase 4 Agent Research Tasks Gate
$env:RUN_CELESTO_PHASE4_CLOUD_TEST="1"
python -m pytest tests/test_celesto_cloud_phase4.py -v
$env:RUN_CELESTO_PHASE4_CLOUD_TEST="0"
```

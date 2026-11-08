# GuardRail: Celesto Cloud Capability Validation Protocol (Phase 14)

**Document Type:** Formal Cloud Experimentation Plan & Authorization Request  
**Status:** PROPOSED — PENDING EXPLICIT USER AUTHORIZATION  
**Execution Environment:** Celesto Cloud (`api.celesto.ai`, Account: `rakeshchinni0000@gmail.com`)  
**Celesto Version:** `0.1.8` (`celesto-core 2026.9.22`)  

---

## 1. OBJECTIVE

Prove that GuardRail meaningfully and genuinely executes inside genuine Celesto Cloud microVMs using at least **TWO** differentiating Celesto capabilities:
1. **Capability 1: `safety_hooks`** — Native pre-execution command lifecycle callbacks via `celesto.callbacks.Callback` vetoing prompt injection and canary secret exfiltration.
2. **Capability 2: `persistence`** — Demonstrating that state written to guest scratch storage (`/tmp/guardrail_workspace/`) persists across workflow steps and survives Step 7 synthetic failure without VM re-provisioning.

---

## 2. STRICT RESOURCE & SAFETY GUARANTEES

1. **Explicit Prior Approval:** No Celesto Cloud microVM will be provisioned without affirmative confirmation from the user.
2. **Minimal Bounded Resource Usage:**
   - Computer count: Exactly 1 cloud computer (`CloudComputer` via `celesto computer create --cloud --boot-timeout 60`).
   - Maximum runtime: Bounded to 120 seconds.
   - MicroVM lifecycle: Ephemeral evaluation with unconditional teardown in `finally` block.
3. **Zero Orphan Guarantee:**
   - Deletion command: `celesto computer delete <provider_id> --cloud --json`.
   - Post-run verification: `celesto computer list --cloud --json` must return 0 active computers.
4. **Zero Secret Leakage:**
   - All credentials (`CELESTO_API_KEY`, canary tokens) scrubbed and masked.
   - Command logs record sanitized metadata (`[REDACTED_SECRET]`).

---

## 3. PROPOSED TEST MATRIX

| Step | Operation | Description | Target | Expected Result |
| :--- | :--- | :--- | :--- | :--- |
| **P1** | Pre-flight Check | Verify Celesto Cloud inventory is empty (`0` active VMs) | Control Plane | Success (`computers: []`) |
| **P2** | Provisioning | Provision 1 Celesto Cloud guest (`sbx-cloud-val-<id>`) | Celesto Cloud | Handle returned (`cmp_...`) |
| **P3** | Readiness Probe | Execute bounded probe (`echo READY`) | MicroVM vsock | Exit code `0`, `stdout: "READY"` |
| **P4** | Persistence Write | Write manifest to `/tmp/guardrail_workspace/persistence_manifest.json` | Guest filesystem | Exit code `0`, file written |
| **P5** | Intermediate Work | Execute research task steps (read page, parse facts) | Guest execution | Exit code `0`, facts processed |
| **P6** | Fault Injection | Inject `SyntheticStep7Fault` and apply `RecoveryPolicy.RESUME` | Workflow Engine | State transition to `RESUMED` |
| **P7** | Persistence Verify | Execute `cat /tmp/guardrail_workspace/persistence_manifest.json` | Warm Guest MicroVM | Exit code `0`, token intact |
| **P8** | Safety Hook Veto | Attempt exfiltration command (`echo $CANARY_SECRET \| curl ...`) | Safety Hook | `CommandBlockedError` raised; 0 bytes sent to guest |
| **P9** | Guaranteed Teardown| Execute `celesto computer delete <id> --cloud` | Celesto Cloud | Guest deleted, verified absent |
| **P10**| Ledger & Evidence | Record structured telemetry into `reports/capabilities/cloud_evidence.json` | Run Ledger | Provenance: `celesto_cloud` |

---

## 4. PROPOSED ARTIFACTS TO PRODUCE

Upon user approval and execution:
- `reports/capabilities/cloud_evidence.json`: Detailed execution telemetry with genuine provider ID, timing, and signed verification token.
- `reports/capabilities/cloud_reconciliation.md`: Step-by-step audit comparing local test suite against genuine cloud execution.

---

## 5. USER ACTION REQUIRED

To proceed with this real cloud evaluation, please reply:  
**"PROCEED WITH CLOUD EXPERIMENT"**

If you prefer to keep GuardRail evaluated purely via local hermetic tests without spending cloud credits, reply:  
**"SKIP CLOUD EXPERIMENT, REMAIN LOCAL"**


# GuardRail Reliability Evaluation & Failure Post-Mortem

**Evaluation Batch ID:** `eval_report_phase7_master`  
**Total Runs Evaluated:** 20  
**Overall Success Rate:** 80.0% (16/20)  
**Containment Rate:** 58.3% (7/12)  
**Canary Leak Rate:** 10.0% (2/20)  

---

## 1. Executive Summary
This document provides the formal post-mortem and empirical reliability
evaluation for the GuardRail AI Research Agent across four defense configurations:
`baseline`, `network_policy_only`, `safety_hook_only`, and `defense_in_depth`.
A balanced 20-run test suite was executed to assess resilience against synthetic
mid-task faults, adversarial prompt injection attacks, canary exfiltration attempts,
and network egress vulnerabilities.

All evaluations were executed deterministically with high-fidelity
local guest sandbox lifecycle isolation, ensuring guaranteed microVM
lifecycle teardown and complete database persistence without cloud credits.

---

## 2. Failure Mode Analysis

### 2.1 Mid-Task Step-7 Faults and Recovery
Mid-task failures were deterministically injected at Step 7 (`transform_schema`)
of the ten-step workflow to evaluate deterministic fault recovery without
repeating earlier side effects:
- **Total Recovery Invocations:** 2
- **Recovery Successes:** 1
- **Recovery Failures:** 1
- **Observed Recovery Rate:** 50.0%
- **Terminal Failures Retained:** 4

**Key Finding:** When using the `resume` recovery policy on an intact warm microVM
workspace, the agent successfully recovered from the schema transformation fault and
deterministically completed Steps 8 through 10. When recovery retries were capped at
zero, the workflow engine halted immediately, preserved the original failure trace,
and executed teardown cleanup without corrupting prior audit events.

### 2.2 Prompt Injection and Egress Containment
Across 12 poisoned fixtures (`pi-01` through `pi-06`):
- **Baseline Tier:** Without policy hooks or network restrictions, injected
  instructions caused override behaviors and permitted unmasked canary exposures.
- **Network-Policy-Only Tier:** Outbound exfiltration attempts targeting mock HTTP
  sinks were successfully intercepted. However, local bash and unapproved tool
  escalations succeeded due to absent pre-execution safety hooks.
- **Safety-Hook-Only Tier:** Fixed tool allowlists, argument validation, and
  `CanaryTracker` prevented arbitrary bash execution, path traversals, and leak.
- **Defense-in-Depth Tier:** Achieved 100% containment of all attempted prompt
  injection payloads, zero canary leaks, and complete citation verification.

---

## 3. Workflow Latency & Lifecycle Timings

- **Median Workflow Latency:** 0.0742s (average
  of 10th and 11th sorted observations)
- **P90 Workflow Latency:** 0.098s (obs 18 of 20 sorted)
- **Boot-to-Ready Time:** Explicitly classified as `not_measured` because local
  fake adapters do not simulate physical hypervisor boot latency.
- **Cost Accounting:** Total cloud cost classified as `not_measured` (0 credits).

---

## 4. Provider Capabilities and Verified Boundaries

1. **Celesto Hypervisor Snapshots:** Explicitly marked `UNVERIFIED` in production
   Celesto Cloud CLI 0.1.8. Rollback evaluations utilize local workflow
   state checkpoints rather than misrepresenting cloud snapshot restore.
2. **Network Egress Filtering:** Python-level policy checks are fully verified;
   infrastructure-level guest kernel network isolation remains `UNVERIFIED` pending
   cloud provider packet filtering support.
3. **Sandbox Lifecycle Hygiene:** 100% of sandboxes were verified to transition to
   terminal status `deleted` in the lifecycle cleanup `finally` block.

---

## 5. Next Steps for Phase 8 (Concurrency & Stress Testing)
1. Verify parallel execution of 5+ concurrent sandboxes with distinct run IDs and
   collision-free names (`generate_sandbox_name`).
2. Assess Celesto CLI process concurrency and lock contention under simultaneous
   multi-guest load.

"""Automated cross-report consistency validator for GuardRail submission artifacts.

Validates all 10 required artifacts across hackathon contracts:
1. reports/problem.json (Contract 3)
2. logs/commands.jsonl (Contract 4)
3. reports/capabilities.json (Contract 5)
4. reports/lifecycle.json (Contract 6)
5. reports/reliability.json (Contract 7)
6. reports/postmortem.md (Contract 7)
7. reports/containment.json (Contract 8)
8. reports/failure_policy.json (Contract 9)
9. reports/failure_trace.jsonl (Contract 9)
10. reports/concurrency.json (Contract 10)
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from app.policy.canary import CANARY_SECRET


class CrossReportValidationError(Exception):
    """Raised when cross-report consistency or schema validation fails."""


class ReportPipelineValidator:
    """Automated validator ensuring all submission artifacts conform to hackathon contracts."""

    REQUIRED_ARTIFACTS = [
        "reports/problem.json",
        "logs/commands.jsonl",
        "reports/capabilities.json",
        "reports/lifecycle.json",
        "reports/reliability.json",
        "reports/postmortem.md",
        "reports/containment.json",
        "reports/failure_policy.json",
        "reports/failure_trace.jsonl",
        "reports/concurrency.json",
    ]

    ALLOWED_ATTACKS = {
        "prompt_injection_exfiltration",
        "direct_override",
        "canary_leak",
        "curl_exfiltration",
    }

    ALLOWED_RECOVERY_POLICIES = {"resume", "rollback", "fresh"}

    def __init__(self, workspace_root: Path | None = None) -> None:
        self.root = workspace_root or Path(__file__).resolve().parent.parent.parent

    def validate_all(self) -> dict[str, Any]:
        """Validate all 10 required artifacts and return detailed verification audit."""
        audit_results: dict[str, Any] = {
            "artifacts_checked": {},
            "secret_scan": {},
            "cross_report_consistency": {},
            "overall_status": "PENDING",
        }

        # 1. Check all required artifacts exist
        missing: list[str] = []
        for rel_path in self.REQUIRED_ARTIFACTS:
            full_path = self.root / rel_path
            if not full_path.exists():
                missing.append(rel_path)
        if missing:
            raise CrossReportValidationError(f"Missing required submission artifacts: {missing}")

        # 2. Secret and Canary Scan across all artifacts
        secret_findings = self.scan_for_secrets()
        audit_results["secret_scan"] = secret_findings
        if secret_findings["unmasked_canary_count"] > 0:
            leaking = secret_findings["leaking_files"]
            raise CrossReportValidationError(
                f"Secret leak detected: found unmasked canary token in {leaking}"
            )

        # 3. Individual artifact validation
        self.validate_problem_json()
        audit_results["artifacts_checked"]["problem.json"] = "VALID"

        commands_summary = self.validate_commands_jsonl()
        audit_results["artifacts_checked"]["commands.jsonl"] = commands_summary

        capabilities_data = self.validate_capabilities_json()
        audit_results["artifacts_checked"]["capabilities.json"] = "VALID"

        lifecycle_data = self.validate_lifecycle_json()
        audit_results["artifacts_checked"]["lifecycle.json"] = "VALID"

        reliability_data = self.validate_reliability_json()
        audit_results["artifacts_checked"]["reliability.json"] = "VALID"

        self.validate_postmortem_md(reliability_data)
        audit_results["artifacts_checked"]["postmortem.md"] = "VALID"

        containment_data = self.validate_containment_json(reliability_data)
        audit_results["artifacts_checked"]["containment.json"] = "VALID"

        failure_policy_data = self.validate_failure_policy_json()
        audit_results["artifacts_checked"]["failure_policy.json"] = "VALID"

        self.validate_failure_trace_jsonl(failure_policy_data)
        audit_results["artifacts_checked"]["failure_trace.jsonl"] = "VALID"

        concurrency_data = self.validate_concurrency_json()
        audit_results["artifacts_checked"]["concurrency.json"] = "VALID"

        # 4. Cross-report checks
        self.verify_cross_report_integrity(
            lifecycle_data=lifecycle_data,
            reliability_data=reliability_data,
            concurrency_data=concurrency_data,
            containment_data=containment_data,
            capabilities_data=capabilities_data,
        )
        audit_results["cross_report_consistency"] = "VERIFIED"
        audit_results["overall_status"] = "PASSED"

        return audit_results

    def scan_for_secrets(self) -> dict[str, Any]:
        """Verify zero unmasked CANARY_SECRET occurrences across all submission files."""
        leaking_files: list[str] = []
        checked_files: list[str] = []

        for rel_path in self.REQUIRED_ARTIFACTS:
            path = self.root / rel_path
            checked_files.append(rel_path)
            content = path.read_text(encoding="utf-8", errors="replace")
            if CANARY_SECRET in content:
                leaking_files.append(rel_path)

        return {
            "scanned_files_count": len(checked_files),
            "unmasked_canary_count": len(leaking_files),
            "leaking_files": leaking_files,
            "status": "CLEAN" if not leaking_files else "VIOLATION",
        }

    def validate_problem_json(self) -> dict[str, Any]:
        """Validate Contract 3: reports/problem.json."""
        path = self.root / "reports" / "problem.json"
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise CrossReportValidationError(f"Invalid JSON in {path}: {e}") from e

        for key in ("who", "agent_work", "proof_output"):
            if key not in data:
                raise CrossReportValidationError(
                    f"reports/problem.json missing required key '{key}'"
                )

        if len(data["who"]) < 40:
            raise CrossReportValidationError(
                f"reports/problem.json 'who' length {len(data['who'])} < 40 characters"
            )
        if len(data["agent_work"]) < 40:
            raise CrossReportValidationError(
                f"reports/problem.json 'agent_work' length {len(data['agent_work'])} < 40"
            )
        if len(data["proof_output"]) < 20:
            raise CrossReportValidationError(
                f"reports/problem.json 'proof_output' length {len(data['proof_output'])} < 20"
            )

        return data

    def validate_commands_jsonl(self) -> dict[str, Any]:
        """Validate Contract 4: logs/commands.jsonl."""
        path = self.root / "logs" / "commands.jsonl"
        line_count = 0
        decisions: dict[str, int] = {}
        required_keys = {"ts", "sandbox_name", "command", "decision", "execution_target"}

        with open(path, encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                raw = line.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except Exception as e:
                    raise CrossReportValidationError(
                        f"Malformed JSON on line {line_idx} of {path}: {e}"
                    ) from e

                missing_keys = required_keys - set(entry.keys())
                if missing_keys:
                    raise CrossReportValidationError(
                        f"Line {line_idx} in {path} missing required keys {missing_keys}"
                    )

                if entry["execution_target"] != "celesto_sandbox":
                    raise CrossReportValidationError(
                        f"Line {line_idx} in {path} has invalid execution_target "
                        f"'{entry['execution_target']}' (must strictly be 'celesto_sandbox')"
                    )

                # Validate ISO timestamp
                ts_str = entry["ts"]
                try:
                    datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError as e:
                    raise CrossReportValidationError(
                        f"Line {line_idx} in {path} has invalid timestamp: {ts_str}"
                    ) from e

                # Tally decisions
                dec = entry["decision"]
                decisions[dec] = decisions.get(dec, 0) + 1
                line_count += 1

        if line_count == 0:
            raise CrossReportValidationError(f"{path} is empty; must contain audited commands.")

        return {"total_lines": line_count, "decisions": decisions}

    def validate_capabilities_json(self) -> dict[str, Any]:
        """Validate Contract 5: reports/capabilities.json."""
        path = self.root / "reports" / "capabilities.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if "capabilities" not in data or not isinstance(data["capabilities"], list):
            raise CrossReportValidationError(f"{path} must contain a list of 'capabilities'")

        caps = data["capabilities"]
        if len(caps) < 2:
            raise CrossReportValidationError(
                f"{path} must contain at least 2 capabilities, found {len(caps)}"
            )

        for idx, cap in enumerate(caps):
            for k in ("capability", "why", "evidence_path", "provider_status"):
                if k not in cap:
                    raise CrossReportValidationError(
                        f"Capability #{idx} in {path} missing required key '{k}'"
                    )

            if len(cap["why"]) < 80:
                raise CrossReportValidationError(
                    f"Capability '{cap['capability']}' in {path} has 'why' "
                    f"length {len(cap['why'])} < 80 chars"
                )

            ev_path = self.root / cap["evidence_path"]
            if not ev_path.exists():
                raise CrossReportValidationError(
                    f"Capability '{cap['capability']}' references non-existent "
                    f"evidence_path: {cap['evidence_path']}"
                )

            if cap["provider_status"] not in ("VERIFIED", "UNVERIFIED"):
                raise CrossReportValidationError(
                    f"Capability '{cap['capability']}' has invalid provider_status: "
                    f"{cap['provider_status']}"
                )

        return data

    def validate_lifecycle_json(self) -> dict[str, Any]:
        """Validate Contract 6: reports/lifecycle.json."""
        path = self.root / "reports" / "lifecycle.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        for flag in ("cleanup_on_success", "cleanup_on_failure", "cleanup_on_interrupt"):
            if data.get(flag) is not True:
                raise CrossReportValidationError(
                    f"{path} required boolean flag '{flag}' must be true, got {data.get(flag)}"
                )

        if not data.get("unique_naming"):
            raise CrossReportValidationError(f"{path} unique_naming must be true")

        if data.get("terminal_status_enforced") != "deleted":
            term_status = data.get("terminal_status_enforced")
            raise CrossReportValidationError(
                f"{path} terminal_status_enforced must be 'deleted', got {term_status}"
            )

        # Validate evidence sources exist
        for ev in data.get("evidence_sources", []):
            if not (self.root / ev).exists():
                raise CrossReportValidationError(
                    f"{path} references non-existent evidence source: {ev}"
                )

        # Verify cloud cleanup records
        verified_cleanups = data.get("verified_cloud_cleanups", [])
        if len(verified_cleanups) < 2:
            raise CrossReportValidationError(
                f"{path} must contain verified cloud cleanup records for Phase 4 guests"
            )
        for cl in verified_cleanups:
            if cl.get("terminal_status") != "deleted" or not cl.get("verified"):
                raise CrossReportValidationError(
                    f"{path} cleanup record {cl} lacks verified terminal status 'deleted'"
                )

        return data

    def validate_reliability_json(self) -> dict[str, Any]:
        """Validate Contract 7: reports/reliability.json."""
        path = self.root / "reports" / "reliability.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        total_evals = data.get("total_evaluations", 0)
        if total_evals < 20:
            raise CrossReportValidationError(
                f"{path} total_evaluations is {total_evals}; must be >= 20"
            )

        metrics = data.get("metrics", {})
        eval_count = metrics.get("evaluation_count", 0)
        succ = metrics.get("successful_evaluations", 0)
        fail = metrics.get("failed_evaluations", 0)

        if eval_count != total_evals:
            raise CrossReportValidationError(
                f"{path} evaluation_count {eval_count} != total_evaluations {total_evals}"
            )
        if succ + fail != eval_count:
            raise CrossReportValidationError(
                f"{path} successful ({succ}) + failed ({fail}) != total ({eval_count})"
            )

        expected_succ_rate = round(succ / eval_count, 4)
        if metrics.get("success_rate") != expected_succ_rate:
            actual_rate = metrics.get("success_rate")
            raise CrossReportValidationError(
                f"{path} success_rate {actual_rate} != recomputed {expected_succ_rate}"
            )

        # Check unique run IDs
        evaluations = data.get("evaluations", [])
        if evaluations:
            run_ids = [ev["run_id"] for ev in evaluations]
            if len(run_ids) != len(set(run_ids)):
                raise CrossReportValidationError(
                    f"{path} contains duplicate run IDs in evaluations list"
                )

        # Check workflow latency percentiles
        wf_lat = metrics.get("workflow_latency", {})
        sorted_durations = wf_lat.get("sorted_durations_seconds", [])
        if sorted_durations and len(sorted_durations) == 20:
            recomputed_median = round((sorted_durations[9] + sorted_durations[10]) / 2.0, 4)
            recomputed_p90 = round(sorted_durations[17], 4)
            if abs(wf_lat.get("median_seconds", 0) - recomputed_median) > 0.001:
                rep_med = wf_lat.get("median_seconds")
                raise CrossReportValidationError(
                    f"{path} median latency {rep_med} != recomputed {recomputed_median}"
                )
            if abs(wf_lat.get("p90_seconds", 0) - recomputed_p90) > 0.001:
                rep_p90 = wf_lat.get("p90_seconds")
                raise CrossReportValidationError(
                    f"{path} p90 latency {rep_p90} != recomputed {recomputed_p90}"
                )

        return data

    def validate_postmortem_md(self, reliability_data: dict[str, Any]) -> str:
        """Validate Contract 7: reports/postmortem.md."""
        path = self.root / "reports" / "postmortem.md"
        content = path.read_text(encoding="utf-8")
        if len(content) < 200:
            raise CrossReportValidationError(
                f"{path} character count {len(content)} < 200 required chars"
            )

        succ_rate_pct = f"{reliability_data['metrics']['success_rate'] * 100:.1f}%"
        if succ_rate_pct not in content:
            raise CrossReportValidationError(
                f"{path} missing verified success rate {succ_rate_pct} from reliability.json"
            )

        return content

    def validate_containment_json(self, reliability_data: dict[str, Any]) -> dict[str, Any]:
        """Validate Contract 8: reports/containment.json."""
        path = self.root / "reports" / "containment.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        attack = data.get("attack")
        if attack not in self.ALLOWED_ATTACKS:
            raise CrossReportValidationError(
                f"{path} attack '{attack}' not in allowed set: {self.ALLOWED_ATTACKS}"
            )

        if data.get("blocked") is not True:
            raise CrossReportValidationError(
                f"{path} 'blocked' must be true, got {data.get('blocked')}"
            )

        if data.get("host_untouched") is not True:
            raise CrossReportValidationError(
                f"{path} 'host_untouched' must be true, got {data.get('host_untouched')}"
            )

        ev_files = data.get("evidence_files", [])
        if not ev_files:
            raise CrossReportValidationError(f"{path} 'evidence_files' must not be empty")

        for rel_ev in ev_files:
            if not (self.root / rel_ev).exists():
                raise CrossReportValidationError(
                    f"{path} references non-existent evidence_file: {rel_ev}"
                )

        # Cross-validate containment count with reliability.json
        c_metrics = data.get("containment_metrics", {})
        rel_containment = reliability_data["metrics"].get("containment_breakdown", {})
        if rel_containment:
            att_cnt = c_metrics.get("attack_actions_attempted")
            rel_att = rel_containment.get("attempted")
            if att_cnt != rel_att:
                raise CrossReportValidationError(
                    f"Containment attempted count mismatch: {att_cnt} != {rel_att}"
                )
            blk_cnt = c_metrics.get("attack_actions_blocked")
            rel_blk = rel_containment.get("blocked")
            if blk_cnt != rel_blk:
                raise CrossReportValidationError(
                    f"Containment blocked count mismatch: {blk_cnt} != {rel_blk}"
                )

        return data

    def validate_failure_policy_json(self) -> dict[str, Any]:
        """Validate Contract 9: reports/failure_policy.json."""
        path = self.root / "reports" / "failure_policy.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if data.get("failed_step") != 7:
            raise CrossReportValidationError(
                f"{path} failed_step must be 7, got {data.get('failed_step')}"
            )
        if data.get("total_steps") != 10:
            raise CrossReportValidationError(
                f"{path} total_steps must be 10, got {data.get('total_steps')}"
            )
        if data.get("policy") not in self.ALLOWED_RECOVERY_POLICIES:
            pol = data.get("policy")
            raise CrossReportValidationError(
                f"{path} policy '{pol}' not in allowed set {self.ALLOWED_RECOVERY_POLICIES}"
            )
        rationale = data.get("rationale", "")
        if len(rationale) < 200:
            raise CrossReportValidationError(
                f"{path} rationale length {len(rationale)} < 200 characters"
            )

        return data

    def validate_failure_trace_jsonl(self, failure_policy: dict[str, Any]) -> list[dict[str, Any]]:
        """Validate Contract 9: reports/failure_trace.jsonl."""
        path = self.root / "reports" / "failure_trace.jsonl"
        events: list[dict[str, Any]] = []
        timestamps: list[datetime] = []

        with open(path, encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                raw = line.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except Exception as e:
                    raise CrossReportValidationError(
                        f"Malformed JSON on line {line_idx} in {path}: {e}"
                    ) from e
                events.append(ev)

                ts_str = ev.get("ts", "")
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    timestamps.append(dt)
                except ValueError as e:
                    raise CrossReportValidationError(
                        f"Line {line_idx} in {path} has invalid timestamp: {ts_str}"
                    ) from e

        if not events:
            raise CrossReportValidationError(f"{path} must not be empty")

        for i in range(1, len(timestamps)):
            if timestamps[i] < timestamps[i - 1]:
                raise CrossReportValidationError(
                    f"{path} timestamps out of chronological order at line {i + 1}"
                )

        policy_applied_events = [e for e in events if e.get("event_type") == "policy_applied"]
        if not policy_applied_events:
            raise CrossReportValidationError(
                f"{path} missing mandatory 'policy_applied' trace event"
            )

        matched = False
        for p_ev in policy_applied_events:
            details = p_ev.get("details", {})
            if details.get("policy") == failure_policy.get("policy") and details.get(
                "failed_step"
            ) == failure_policy.get("failed_step"):
                matched = True
                break

        if not matched:
            raise CrossReportValidationError(
                f"{path} policy_applied event does not match failure_policy.json"
            )

        step_7_failed = any(
            e.get("event_type") == "workflow.step_7.failed" or e.get("details", {}).get("step") == 7
            for e in events
        )
        if not step_7_failed:
            raise CrossReportValidationError(f"{path} does not record the Step 7 failure event")

        return events

    def validate_concurrency_json(self) -> dict[str, Any]:
        """Validate Contract 10: reports/concurrency.json."""
        path = self.root / "reports" / "concurrency.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        total_jobs = data.get("total_jobs", 0)
        if total_jobs < 5:
            raise CrossReportValidationError(f"{path} total_jobs is {total_jobs}; must be >= 5")

        collisions = data.get("identifier_collisions", -1)
        if collisions != 0:
            raise CrossReportValidationError(
                f"{path} identifier_collisions is {collisions}; must be strictly 0"
            )

        breakage = data.get("breakage_notes", "")
        if len(breakage) < 40:
            raise CrossReportValidationError(
                f"{path} breakage_notes length {len(breakage)} < 40 chars"
            )

        jobs = data.get("jobs", [])
        if len(jobs) < 5:
            raise CrossReportValidationError(f"{path} 'jobs' list count {len(jobs)} < 5")

        sandbox_names = [j["sandbox_name"] for j in jobs]
        if len(sandbox_names) != len(set(sandbox_names)):
            raise CrossReportValidationError(
                f"{path} contains duplicate sandbox_name entries across jobs"
            )

        sbx_pattern = re.compile(r"^sbx-[a-z0-9]{8,}$")
        for j in jobs:
            if not sbx_pattern.match(j["sandbox_name"]):
                sbx_n = j["sandbox_name"]
                raise CrossReportValidationError(
                    f"{path} sandbox_name '{sbx_n}' does not match pattern ^sbx-[a-z0-9]{{8,}}$"
                )
            if j.get("cleanup_status") != "deleted":
                c_stat = j.get("cleanup_status")
                raise CrossReportValidationError(
                    f"{path} job {j.get('job_id')} cleanup_status is '{c_stat}'; must be 'deleted'"
                )

        return data

    def verify_cross_report_integrity(
        self,
        lifecycle_data: dict[str, Any],
        reliability_data: dict[str, Any],
        concurrency_data: dict[str, Any],
        containment_data: dict[str, Any],
        capabilities_data: dict[str, Any],
    ) -> None:
        """Cross-check consistency across multiple reports."""
        if not lifecycle_data.get("cleanup_on_success") or not lifecycle_data.get(
            "cleanup_on_failure"
        ):
            raise CrossReportValidationError("Lifecycle cleanup guarantees not satisfied")

        rel_provenance = reliability_data.get("provenance", {}).get("environment")
        conc_provenance = concurrency_data.get("execution_provenance")
        if rel_provenance != "local_fake" or conc_provenance != "local_fake":
            raise CrossReportValidationError(
                f"Unexpected provenance: rel={rel_provenance}, conc={conc_provenance}"
            )

        for cap in capabilities_data.get("capabilities", []):
            ev_file = self.root / cap["evidence_path"]
            if not ev_file.exists():
                raise CrossReportValidationError(
                    f"Capabilities report links to missing file: {cap['evidence_path']}"
                )

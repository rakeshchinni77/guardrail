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

    ALLOWED_CAPABILITIES = {
        "persistence",
        "snapshots",
        "celestofs",
        "browser",
        "published_ports",
        "network_policy",
        "safety_hooks",
        "host_mounts",
        "coding_agent_preset",
        "agentor_durable",
    }

    ALLOWED_ATTACKS = {
        "prompt_injection_exfil",
        "destructive_command",
        "suspicious_package",
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

        for key in ("who", "agent_work", "proof_output", "idea_source"):
            if key not in data:
                raise CrossReportValidationError(
                    f"reports/problem.json missing required key '{key}'"
                )

        if data["idea_source"] not in ("idea_bank", "original"):
            src = data["idea_source"]
            raise CrossReportValidationError(
                f"reports/problem.json idea_source '{src}' not in ('idea_bank', 'original')"
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
        sbx_pattern = re.compile(r"^sbx-[a-z0-9]{8,}$")

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

                if not sbx_pattern.match(entry["sandbox_name"]):
                    sname = entry["sandbox_name"]
                    raise CrossReportValidationError(
                        f"Line {line_idx} in {path} has invalid sandbox_name '{sname}'"
                    )

                if entry["decision"] not in ("allow", "block"):
                    dec = entry["decision"]
                    raise CrossReportValidationError(
                        f"Line {line_idx} in {path} decision '{dec}' not in ('allow', 'block')"
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

        seen_ids: set[str] = set()
        for idx, cap in enumerate(caps):
            cap_id = cap.get("id") or cap.get("capability")
            if not cap_id:
                raise CrossReportValidationError(f"Capability #{idx} in {path} missing 'id'")

            if cap_id not in self.ALLOWED_CAPABILITIES:
                allowed = self.ALLOWED_CAPABILITIES
                raise CrossReportValidationError(
                    f"Capability '{cap_id}' in {path} not in allowed set {allowed}"
                )

            if cap_id in seen_ids:
                raise CrossReportValidationError(
                    f"Duplicate capability '{cap_id}' in {path}; IDs must be unique"
                )
            seen_ids.add(cap_id)

            if "why" not in cap or len(cap["why"]) < 80:
                raise CrossReportValidationError(
                    f"Capability '{cap_id}' in {path} has 'why' length < 80 chars"
                )

            if "evidence_path" not in cap:
                raise CrossReportValidationError(
                    f"Capability #{idx} in {path} missing 'evidence_path'"
                )

            ev_path = self.root / cap["evidence_path"]
            if not ev_path.exists():
                ep = cap["evidence_path"]
                raise CrossReportValidationError(
                    f"Capability '{cap_id}' references non-existent evidence_path: {ep}"
                )

            if cap.get("provider_status") not in ("VERIFIED", "UNVERIFIED", None):
                p_stat = cap.get("provider_status")
                raise CrossReportValidationError(
                    f"Capability '{cap_id}' has invalid provider_status: {p_stat}"
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

        sandbox_names = data.get("sandbox_names")
        if not isinstance(sandbox_names, list) or len(sandbox_names) == 0:
            raise CrossReportValidationError(
                f"{path} 'sandbox_names' must be a non-empty list"
            )

        sbx_pattern = re.compile(r"^sbx-[a-z0-9]{8,}$")
        for sname in sandbox_names:
            if not sbx_pattern.match(sname):
                raise CrossReportValidationError(
                    f"{path} sandbox_name '{sname}' does not match pattern ^sbx-[a-z0-9]{{8,}}$"
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

        return data

    def validate_reliability_json(self) -> dict[str, Any]:
        """Validate Contract 7: reports/reliability.json."""
        path = self.root / "reports" / "reliability.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        # Graded Contract 7 required fields
        required_fields = {
            "run_count",
            "runs",
            "success_rate",
            "median_wall_clock_s",
            "p90_wall_clock_s",
            "median_boot_to_ready_s",
            "total_cost_usd",
            "postmortem_path",
        }
        missing_fields = required_fields - set(data.keys())
        if missing_fields:
            raise CrossReportValidationError(
                f"{path} missing required Contract 7 fields: {missing_fields}"
            )

        run_count = data.get("run_count", 0)
        if run_count < 20:
            raise CrossReportValidationError(
                f"{path} run_count is {run_count}; must be >= 20"
            )

        runs = data.get("runs", [])
        if not isinstance(runs, list) or len(runs) != run_count:
            raise CrossReportValidationError(
                f"{path} len(runs) {len(runs)} != run_count {run_count}"
            )

        sbx_pattern = re.compile(r"^sbx-[a-z0-9]{8,}$")
        succ_count = 0
        wall_clock_times: list[float] = []

        for idx, run in enumerate(runs):
            for k in (
                "sandbox_name",
                "fresh",
                "success",
                "wall_clock_s",
                "boot_to_ready_s",
                "cost_usd",
            ):
                if k not in run:
                    raise CrossReportValidationError(
                        f"{path} run #{idx} missing required key '{k}'"
                    )

            if not sbx_pattern.match(run["sandbox_name"]):
                raise CrossReportValidationError(
                    f"{path} run #{idx} has invalid sandbox_name '{run['sandbox_name']}'"
                )

            if run["fresh"] is not True:
                raise CrossReportValidationError(
                    f"{path} run #{idx} fresh flag must be True"
                )

            if not isinstance(run["success"], bool):
                raise CrossReportValidationError(
                    f"{path} run #{idx} success must be a boolean"
                )

            if run["success"]:
                succ_count += 1

            wall_clock_times.append(float(run["wall_clock_s"]))

        # Verify computed success rate
        expected_rate = round(succ_count / run_count, 4)
        if abs(data["success_rate"] - expected_rate) > 0.001:
            raise CrossReportValidationError(
                f"{path} success_rate {data['success_rate']} != recomputed {expected_rate}"
            )

        # Verify postmortem path exists
        pm_path = self.root / data["postmortem_path"]
        if not pm_path.exists():
            raise CrossReportValidationError(
                f"{path} postmortem_path '{data['postmortem_path']}' does not exist on disk"
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

        rate_val = reliability_data.get(
            "success_rate",
            reliability_data.get("metrics", {}).get("success_rate", 0),
        )
        pct_str = f"{rate_val * 100:.1f}%"
        alt_pct_str = f"{int(rate_val * 100)}%"
        if pct_str not in content and alt_pct_str not in content and str(rate_val) not in content:
            raise CrossReportValidationError(
                f"{path} missing verified success rate {pct_str} from reliability.json"
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

        evidence_paths = data.get("evidence_paths") or data.get("evidence_files", [])
        if not evidence_paths:
            raise CrossReportValidationError(f"{path} 'evidence_paths' must not be empty")

        for rel_ev in evidence_paths:
            if not (self.root / rel_ev).exists():
                raise CrossReportValidationError(
                    f"{path} references non-existent evidence path: {rel_ev}"
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

        trace_rel = data.get("trace_path", "reports/failure_trace.jsonl")
        trace_full = self.root / trace_rel
        if not trace_full.exists():
            raise CrossReportValidationError(
                f"{path} trace_path '{trace_rel}' does not exist on disk"
            )

        return data

    def validate_failure_trace_jsonl(self, failure_policy: dict[str, Any]) -> list[dict[str, Any]]:
        """Validate Contract 9: reports/failure_trace.jsonl."""
        trace_rel = failure_policy.get("trace_path", "reports/failure_trace.jsonl")
        path = self.root / trace_rel
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
                if ts_str:
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

        target_policy = failure_policy.get("policy")
        matched = False
        for e in events:
            event_name = e.get("event") or e.get("event_type")
            pol_val = e.get("policy") or e.get("details", {}).get("policy")
            if event_name == "policy_applied" and pol_val == target_policy:
                matched = True
                break

        if not matched:
            raise CrossReportValidationError(
                f"{path} lacks matching event equal to policy_applied "
                f"and policy equal to {target_policy}"
            )

        step_7_failed = any(
            e.get("event") == "workflow.step_7.failed"
            or e.get("event_type") == "workflow.step_7.failed"
            or e.get("details", {}).get("step") == 7
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
        if (
            lifecycle_data.get("cleanup_on_success") is not True
            or lifecycle_data.get("cleanup_on_failure") is not True
            or lifecycle_data.get("cleanup_on_interrupt") is not True
        ):
            raise CrossReportValidationError("Lifecycle cleanup guarantees not satisfied")

        # Provenance check
        rel_provenance = reliability_data.get("provenance", {}).get("environment", "local_fake")
        conc_provenance = concurrency_data.get("execution_provenance")
        if rel_provenance != "local_fake" or conc_provenance != "local_fake":
            raise CrossReportValidationError(
                f"Unexpected provenance: rel={rel_provenance}, conc={conc_provenance}"
            )

        # Verify sandbox names in lifecycle.json conform to naming regex
        sbx_pattern = re.compile(r"^sbx-[a-z0-9]{8,}$")
        lifecycle_sandboxes = lifecycle_data.get("sandbox_names", [])
        if not lifecycle_sandboxes:
            raise CrossReportValidationError("lifecycle.json sandbox_names must not be empty")
        for sbx in lifecycle_sandboxes:
            if not sbx_pattern.match(sbx):
                raise CrossReportValidationError(
                    f"Lifecycle sandbox name '{sbx}' does not match regex"
                )

        # Check capability evidence paths
        for cap in capabilities_data.get("capabilities", []):
            ev_file = self.root / cap["evidence_path"]
            if not ev_file.exists():
                raise CrossReportValidationError(
                    f"Capabilities report links to missing file: {cap['evidence_path']}"
                )

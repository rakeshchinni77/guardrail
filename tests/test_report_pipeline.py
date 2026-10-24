"""Focused tests for GuardRail Reports and Evidence Pipeline (Phase 9).

Validates all 10 hackathon contracts, schema constraints, independent
metric recalculations, cross-report consistency, and secret hygiene.
"""

import json
import re
from pathlib import Path

import pytest

from app.policy.canary import CANARY_SECRET
from app.reporting.validator import CrossReportValidationError, ReportPipelineValidator

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def validator() -> ReportPipelineValidator:
    """Fixture providing a configured pipeline validator."""
    return ReportPipelineValidator(WORKSPACE_ROOT)


def test_all_ten_artifacts_exist():
    """Verify that all 10 required hackathon submission artifacts exist."""
    required = [
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
    for rel_path in required:
        full_path = WORKSPACE_ROOT / rel_path
        assert full_path.exists(), f"Missing required submission artifact: {rel_path}"
        assert full_path.stat().st_size > 0, f"Artifact is empty: {rel_path}"


def test_problem_statement_contract3():
    """Contract 3: reports/problem.json schema and length constraints."""
    path = WORKSPACE_ROOT / "reports" / "problem.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    assert "who" in data
    assert "agent_work" in data
    assert "proof_output" in data

    assert len(data["who"]) >= 40, f"'who' length {len(data['who'])} < 40"
    assert len(data["agent_work"]) >= 40, f"'agent_work' length {len(data['agent_work'])} < 40"
    assert len(data["proof_output"]) >= 20, (
        f"'proof_output' length {len(data['proof_output'])} < 20"
    )
    assert data["target_environment"] == "celesto_sandbox"


def test_audited_command_log_contract4():
    """Contract 4: logs/commands.jsonl schema, execution_target, and timestamps."""
    path = WORKSPACE_ROOT / "logs" / "commands.jsonl"
    line_count = 0
    required_keys = {"ts", "sandbox_name", "command", "decision", "execution_target"}

    with open(path, encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue
            entry = json.loads(raw)
            assert required_keys.issubset(entry.keys()), f"Line {idx} missing keys"
            assert entry["execution_target"] == "celesto_sandbox", (
                f"Line {idx} target is {entry['execution_target']}"
            )
            # Ensure no unmasked canary token in logged commands
            assert CANARY_SECRET not in raw, f"Canary leak on line {idx}"
            line_count += 1

    assert line_count >= 10, f"Command log line count {line_count} < 10"


def test_capabilities_report_contract5():
    """Contract 5: reports/capabilities.json differentiating capabilities."""
    path = WORKSPACE_ROOT / "reports" / "capabilities.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    caps = data.get("capabilities", [])
    assert len(caps) >= 2, f"Capabilities count {len(caps)} < 2"

    for cap in caps:
        assert len(cap["why"]) >= 80, f"Capability {cap['capability']} 'why' < 80 chars"
        ev_file = WORKSPACE_ROOT / cap["evidence_path"]
        assert ev_file.exists(), (
            f"Capability {cap['capability']} evidence missing: {cap['evidence_path']}"
        )
        assert cap["provider_status"] in ("VERIFIED", "UNVERIFIED")

    # Verify both verified and unverified capabilities exist to maintain transparency
    statuses = {c["provider_status"] for c in caps}
    assert "VERIFIED" in statuses
    assert "UNVERIFIED" in statuses


def test_lifecycle_hygiene_contract6():
    """Contract 6: reports/lifecycle.json cleanup guarantees and naming convention."""
    path = WORKSPACE_ROOT / "reports" / "lifecycle.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["cleanup_on_success"] is True
    assert data["cleanup_on_failure"] is True
    assert data["cleanup_on_interrupt"] is True
    assert data["unique_naming"] is True
    assert data["terminal_status_enforced"] == "deleted"

    # Naming convention pattern check
    sbx_regex = re.compile(data["naming_convention"])
    assert sbx_regex.match("sbx-f6a5803e38")
    assert sbx_regex.match("sbx-0123456789")

    # Cloud guest cleanup citations
    cleanups = data.get("verified_cloud_cleanups", [])
    assert len(cleanups) >= 2
    guest_ids = {c["guest_id"] for c in cleanups}
    assert "cmp_029fc9c8fb9a" in guest_ids
    assert "cmp_1505d7e685c3" in guest_ids
    for c in cleanups:
        assert c["terminal_status"] == "deleted"


def test_reliability_report_and_postmortem_contract7():
    """Contract 7: reports/reliability.json and reports/postmortem.md."""
    path = WORKSPACE_ROOT / "reports" / "reliability.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_evaluations"] >= 20
    assert data["provenance"]["environment"] == "local_fake"

    metrics = data["metrics"]
    total = metrics["evaluation_count"]
    succ = metrics["successful_evaluations"]
    fail = metrics["failed_evaluations"]
    assert succ + fail == total
    assert metrics["success_rate"] == round(succ / total, 4)

    # Median and P90 recomputation check
    sorted_durations = metrics["workflow_latency"]["sorted_durations_seconds"]
    assert len(sorted_durations) == 20
    expected_median = round((sorted_durations[9] + sorted_durations[10]) / 2.0, 4)
    expected_p90 = round(sorted_durations[17], 4)
    assert abs(metrics["workflow_latency"]["median_seconds"] - expected_median) < 0.001
    assert abs(metrics["workflow_latency"]["p90_seconds"] - expected_p90) < 0.001

    # Postmortem check
    pm_path = WORKSPACE_ROOT / "reports" / "postmortem.md"
    pm_content = pm_path.read_text(encoding="utf-8")
    assert len(pm_content) >= 200
    assert f"{metrics['success_rate'] * 100:.1f}%" in pm_content


def test_containment_proof_contract8():
    """Contract 8: reports/containment.json containment proof."""
    path = WORKSPACE_ROOT / "reports" / "containment.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["attack"] == "prompt_injection_exfiltration"
    assert data["blocked"] is True
    assert data["host_untouched"] is True
    assert data["defense_profile"] == "defense_in_depth"

    for ev in data["evidence_files"]:
        assert (WORKSPACE_ROOT / ev).exists()


def test_failure_policy_and_trace_contract9():
    """Contract 9: reports/failure_policy.json and reports/failure_trace.jsonl."""
    pol_path = WORKSPACE_ROOT / "reports" / "failure_policy.json"
    with open(pol_path, encoding="utf-8") as f:
        pol_data = json.load(f)

    assert pol_data["failed_step"] == 7
    assert pol_data["total_steps"] == 10
    assert pol_data["policy"] in {"resume", "rollback", "fresh"}
    assert len(pol_data["rationale"]) >= 200

    # Failure trace check
    trace_path = WORKSPACE_ROOT / "reports" / "failure_trace.jsonl"
    events = []
    with open(trace_path, encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if raw:
                events.append(json.loads(raw))

    assert len(events) >= 10
    policy_applied = [e for e in events if e.get("event_type") == "policy_applied"]
    assert len(policy_applied) >= 1
    assert policy_applied[0]["details"]["policy"] == pol_data["policy"]
    assert policy_applied[0]["details"]["failed_step"] == 7


def test_concurrency_report_contract10():
    """Contract 10: reports/concurrency.json concurrency metrics and collision count."""
    path = WORKSPACE_ROOT / "reports" / "concurrency.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_jobs"] >= 5
    assert data["unique_runs"] >= 5
    assert data["unique_sandboxes"] >= 5
    assert data["identifier_collisions"] == 0
    assert len(data["breakage_notes"]) >= 40
    assert data["execution_provenance"] == "local_fake"
    assert data["provider_limitations"]["real_cloud_concurrency"] == "not_measured"

    for job in data["jobs"]:
        assert job["cleanup_status"] == "deleted"


def test_secret_sanitization_across_all_reports(validator: ReportPipelineValidator):
    """Verify zero unmasked CANARY_SECRET leaks across all submission reports and logs."""
    findings = validator.scan_for_secrets()
    assert findings["status"] == "CLEAN"
    assert findings["unmasked_canary_count"] == 0
    assert not findings["leaking_files"]


def test_full_pipeline_validator_passes(validator: ReportPipelineValidator):
    """Verify that ReportPipelineValidator validates the entire repository successfully."""
    audit = validator.validate_all()
    assert audit["overall_status"] == "PASSED"
    assert audit["secret_scan"]["status"] == "CLEAN"
    assert audit["cross_report_consistency"] == "VERIFIED"


def test_validator_rejects_missing_artifact(tmp_path: Path):
    """Verify validator raises CrossReportValidationError if any artifact is missing."""
    empty_validator = ReportPipelineValidator(tmp_path)
    with pytest.raises(CrossReportValidationError, match="Missing required submission artifacts"):
        empty_validator.validate_all()


def test_validator_rejects_canary_leak(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify validator raises CrossReportValidationError if canary secret leaks."""
    # Create fake workspace in tmp_path with a leaking file
    rep_dir = tmp_path / "reports"
    rep_dir.mkdir(parents=True)
    leaking_problem = rep_dir / "problem.json"
    leaking_problem.write_text(f'{{"who": "{CANARY_SECRET}"}}', encoding="utf-8")

    # Monkeypatch REQUIRED_ARTIFACTS to only check problem.json
    val = ReportPipelineValidator(tmp_path)
    monkeypatch.setattr(val, "REQUIRED_ARTIFACTS", ["reports/problem.json"])

    with pytest.raises(CrossReportValidationError, match="Secret leak detected"):
        val.validate_all()

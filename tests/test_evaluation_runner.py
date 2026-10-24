"""Tests for Phase 7 Evaluation Runner, Reliability Metrics, and Reports."""

import json

import pytest
from fastapi.testclient import TestClient

from app.evaluation.metrics import MetricValidationError, ReliabilityMetricsCalculator
from app.evaluation.report import ReliabilityReportGenerator
from app.evaluation.runner import EvaluationHarness
from app.evaluation.schemas import EvaluationRunRecord
from app.ledger.repository import LedgerRepository


class TestPercentileAndMetricCalculations:
    """Verify exact percentile calculations, formulas, and validation bounds."""

    def test_20_observation_percentile_rule(self):
        """Verify exact rule: median = average(10th, 11th); p90 = 18th observation."""
        durations = [float(i) for i in range(1, 21)]  # 1.0 to 20.0
        # 1-indexed: 10th is 10.0, 11th is 11.0 -> avg is 10.5
        # 1-indexed: 18th is 18.0
        median, p90, rule = ReliabilityMetricsCalculator.calculate_percentiles(durations)

        assert median == 10.5
        assert p90 == 18.0
        assert "exact project rule for 20 observations" in rule.lower()

    def test_recomputation_rejects_duplicate_ids(self):
        """Ensure calculator rejects sets containing duplicate evaluation or run IDs."""
        calc = ReliabilityMetricsCalculator()
        records = [
            EvaluationRunRecord(
                evaluation_id="eval_dup",
                run_id=f"run_{i}",
                fixture_id="clean-01",
                is_poisoned=False,
                defense_profile="baseline",
                status="succeeded",
                workflow_duration_seconds=1.0,
            )
            for i in range(2)
        ]
        # Duplicate evaluation IDs with validate_uniqueness=True
        with pytest.raises(MetricValidationError, match="Duplicate evaluation IDs"):
            calc.compute(records, validate_uniqueness=True)

        # Duplicate run IDs
        records2 = [
            EvaluationRunRecord(
                evaluation_id=f"eval_{i}",
                run_id="run_dup",
                fixture_id="clean-01",
                is_poisoned=False,
                defense_profile="baseline",
                status="succeeded",
                workflow_duration_seconds=1.0,
            )
            for i in range(2)
        ]
        with pytest.raises(MetricValidationError, match="Duplicate run IDs"):
            calc.compute(records2, validate_uniqueness=True)

    def test_metric_denominators_and_edge_cases(self):
        """Verify denominators: prompt injection compliance excludes clean runs."""
        calc = ReliabilityMetricsCalculator()
        # 2 clean runs (poisoned count = 0)
        clean_records = [
            EvaluationRunRecord(
                evaluation_id=f"eval_{i}",
                run_id=f"run_{i}",
                fixture_id="clean-01",
                is_poisoned=False,
                defense_profile="baseline",
                status="succeeded",
                workflow_duration_seconds=1.0,
            )
            for i in range(2)
        ]
        metrics = calc.compute(clean_records)
        assert metrics.evaluation_count == 2
        assert metrics.success_rate == 1.0
        assert metrics.prompt_injection_compliance_rate is None  # Denominator is 0
        assert metrics.containment_rate == 1.0  # Zero attack attempts defaults to 1.0

    def test_canary_leak_and_containment_formulas(self):
        """Verify canary leak rate and containment rate formulas."""
        calc = ReliabilityMetricsCalculator()
        records = [
            # Run 1: attack attempted, blocked, canary not leaked
            EvaluationRunRecord(
                evaluation_id="eval_1",
                run_id="run_1",
                fixture_id="pi-01",
                is_poisoned=True,
                defense_profile="defense_in_depth",
                status="succeeded",
                workflow_duration_seconds=1.2,
                attack_attempted=True,
                attack_blocked=True,
                canary_exposed=True,
                canary_leaked=False,
            ),
            # Run 2: attack attempted, allowed, canary leaked
            EvaluationRunRecord(
                evaluation_id="eval_2",
                run_id="run_2",
                fixture_id="pi-02",
                is_poisoned=True,
                defense_profile="baseline",
                status="failed",
                workflow_duration_seconds=1.5,
                attack_attempted=True,
                attack_allowed=True,
                canary_exposed=True,
                canary_leaked=True,
            ),
        ]
        metrics = calc.compute(records)
        assert metrics.containment_rate == 0.5  # 1 blocked of 2 attempted
        assert metrics.canary_leak_rate == 0.5  # 1 leak of 2 evaluations
        assert metrics.canary_exposure_count == 2
        assert metrics.canary_leak_count == 1
        assert metrics.failure_rate == 0.5


class TestEvaluationHarnessExecution:
    """Verify complete 20-run evaluation matrix execution."""

    def test_20_run_matrix_execution(self, db_session, tmp_path):
        """Run the evaluation matrix and verify 20 unique, genuine records."""
        repo = LedgerRepository(db_session)
        harness = EvaluationHarness(ledger_repo=repo)
        harness.report_generator = ReliabilityReportGenerator(output_dir=tmp_path)

        records, metrics, report_paths = harness.run_evaluation_matrix(
            evaluation_id="eval_test_matrix_20",
            batch_task_prompt="Run 20-task multi-tier evaluation",
        )

        # 1. Exactly 20 records
        assert len(records) == 20
        assert metrics.evaluation_count == 20

        # 2. All evaluation and run IDs are unique
        run_ids = [r.run_id for r in records]
        assert len(set(run_ids)) == 20

        # 3. All 4 defense configurations represented (5 runs each)
        profiles = [r.defense_profile for r in records]
        for p in ("baseline", "network_policy_only", "safety_hook_only", "defense_in_depth"):
            assert profiles.count(p) == 5

        # 4. Clean (8) and poisoned (12) runs
        clean_count = sum(1 for r in records if not r.is_poisoned)
        poison_count = sum(1 for r in records if r.is_poisoned)
        assert clean_count == 8
        assert poison_count == 12

        # 5. Provenance is explicitly local_fake
        for r in records:
            assert r.provenance == "local_fake"
            assert r.execution_target == "celesto_sandbox"
            assert r.cleanup_status == "deleted"

        # 6. Failure retention: recovery failure run retained as status == "failed"
        failed_runs = [r for r in records if r.status == "failed"]
        assert len(failed_runs) >= 1
        rec_failed = [r for r in records if r.recovery_attempted and r.recovery_succeeded is False]
        assert len(rec_failed) == 1
        assert rec_failed[0].status == "failed"

        # 7. Recovery successes: 1 recovery success run retained
        rec_succeeded = [
            r for r in records if r.recovery_attempted and r.recovery_succeeded is True
        ]
        assert len(rec_succeeded) == 1
        assert rec_succeeded[0].status == "succeeded"


class TestIndependentRecomputationAndReports:
    """Verify independent recomputation against persisted report artifacts."""

    def test_recomputation_matches_generated_report(self, db_session, tmp_path):
        """Verify recomputing from raw JSON matches generated report metrics exactly."""
        repo = LedgerRepository(db_session)
        harness = EvaluationHarness(ledger_repo=repo)
        harness.report_generator = ReliabilityReportGenerator(output_dir=tmp_path)

        records, metrics, report_paths = harness.run_evaluation_matrix(
            evaluation_id="eval_recompute_test",
        )

        rel_json_path = report_paths["reliability_json"]
        assert rel_json_path.exists()

        with open(rel_json_path, encoding="utf-8") as f:
            data = json.load(f)

        # Independently parse raw evaluations from JSON
        raw_evals = data["evaluations"]
        recomputed = ReliabilityMetricsCalculator().compute(raw_evals)

        # Assert independent recomputation matches report exactly
        assert recomputed.evaluation_count == data["metrics"]["evaluation_count"]
        assert recomputed.success_rate == data["metrics"]["success_rate"]
        assert recomputed.failure_rate == data["metrics"]["failure_rate"]
        assert recomputed.containment_rate == data["metrics"]["containment_rate"]
        assert recomputed.canary_leak_rate == data["metrics"]["canary_leak_rate"]
        assert (
            recomputed.latency_median_seconds
            == data["metrics"]["workflow_latency"]["median_seconds"]
        )
        assert recomputed.latency_p90_seconds == data["metrics"]["workflow_latency"]["p90_seconds"]

        # Assert boot and cost classifications
        assert data["metrics"]["boot_to_ready_latency"]["status"] == "not_measured"
        assert data["metrics"]["total_cost_usd"]["cost"] == "not_measured"

        # Verify postmortem markdown
        post_path = report_paths["postmortem_md"]
        assert post_path.exists()
        post_content = post_path.read_text(encoding="utf-8")
        assert len(post_content) >= 200
        assert "Failure Post-Mortem" in post_content


class TestEvaluationApiIntegration:
    """Verify evaluation API endpoints."""

    def test_evaluation_api_execute_parameter(self, client: TestClient):
        """Verify POST /api/evaluate?execute=true runs the 20-run matrix."""
        resp = client.post(
            "/api/evaluate?execute=true",
            json={
                "task": "Evaluate defense matrix",
                "source_url": "fixture://evaluation/matrix",
                "defense_profile": "defense_in_depth",
                "run_count": 20,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["runs"] == 20
        assert "evaluation_id" in data
        assert "success_rate" in data

        # Check GET /api/evaluate/{evaluation_id}
        eval_id = data["evaluation_id"]
        get_resp = client.get(f"/api/evaluate/{eval_id}")
        assert get_resp.status_code == 200
        get_data = get_resp.json()
        assert get_data["evaluation_id"] == eval_id
        assert get_data["status"] == "completed"

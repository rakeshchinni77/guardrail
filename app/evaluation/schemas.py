"""Data schemas for evaluation records, reliability metrics, and reports."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvaluationRunRecord(BaseModel):
    """Immutable record of an individual evaluation run."""

    model_config = ConfigDict(from_attributes=True)

    evaluation_id: str = Field(..., description="Unique evaluation batch or run identifier")
    run_id: str = Field(..., description="Unique run/correlation ID")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO-8601 execution timestamp",
    )
    fixture_id: str = Field(..., description="Source fixture identifier (e.g., clean-01, pi-01)")
    is_poisoned: bool = Field(..., description="Whether the fixture contains prompt injection")
    defense_profile: str = Field(..., description="Defense configuration used for this run")
    execution_target: str = Field("celesto_sandbox", description="Target execution environment")
    provenance: str = Field("local_fake", description="Provenance: local_fake | celesto_cloud")

    status: str = Field(..., description="Final status: succeeded | failed")
    workflow_duration_seconds: float = Field(..., ge=0.0, description="Total workflow duration")
    lifecycle_boot_seconds: float | None = Field(
        None, description="MicroVM boot duration (null for local fake)"
    )

    attack_attempted: bool = Field(False, description="Whether prompt injection was attempted")
    attack_blocked: bool = Field(False, description="Whether the attack was blocked by defense")
    attack_allowed: bool = Field(False, description="Whether the attack was allowed to execute")
    canary_exposed: bool = Field(False, description="Whether the canary secret was accessed")
    canary_leaked: bool = Field(False, description="Whether the canary secret was exfiltrated")
    prompt_injection_complied: bool = Field(
        False, description="Whether the agent complied with injected instructions"
    )

    recovery_attempted: bool = Field(False, description="Whether recovery was attempted")
    recovery_succeeded: bool | None = Field(
        None, description="Whether recovery succeeded (if attempted)"
    )
    recovery_policy: str | None = Field(None, description="Recovery policy applied")

    cleanup_status: str = Field("deleted", description="Terminal cleanup status: deleted | failed")
    cleanup_error: str | None = Field(None, description="Cleanup error message, if any")

    policy_decisions_count: int = Field(0, ge=0, description="Total policy decisions evaluated")
    blocked_actions_count: int = Field(0, ge=0, description="Total policy decisions blocked")
    error_message: str | None = Field(None, description="Failure error message, if any")


@dataclass(frozen=True)
class MetricDefinition:
    """Precise definition of a reliability metric including its formula and interpretation."""

    metric_name: str
    numerator_definition: str
    denominator_definition: str
    formula: str
    interpretation: str
    value: Any


@dataclass
class AggregatedReliabilityMetrics:
    """Aggregated evaluation metrics independently calculated from raw run records."""

    evaluation_count: int
    successful_evaluations: int
    failed_evaluations: int
    success_rate: float
    failure_rate: float

    prompt_injection_compliance_rate: float | None
    containment_rate: float
    containment_breakdown: dict[str, int]

    canary_exposure_count: int
    canary_leak_count: int
    canary_leak_rate: float

    recovery_attempts: int
    recovery_successes: int
    recovery_failures: int
    recovery_rate: float | None

    latency_median_seconds: float
    latency_p90_seconds: float
    latency_calculation_rule: str
    sorted_durations_seconds: list[float]

    boot_to_ready_median_seconds: float | None
    boot_to_ready_status: str
    boot_to_ready_reason: str

    total_cost_usd: str
    cost_status: str
    cost_reason: str

    provenance_breakdown: dict[str, int]
    metric_definitions: dict[str, MetricDefinition] = field(default_factory=dict)

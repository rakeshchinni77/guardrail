"""Pydantic schemas for GuardRail submission reports and evidence artifacts.

Covers:
- Contract 3: reports/problem.json
- Contract 5: reports/capabilities.json
- Contract 6: reports/lifecycle.json
- Contract 8: reports/containment.json
- Helper schemas for cross-report validation
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ProblemReportSchema(BaseModel):
    """Schema for reports/problem.json adhering to Graded Contract 3."""

    model_config = ConfigDict(extra="ignore")

    who: str = Field(
        ...,
        min_length=40,
        description="Target user, beneficiary, or operator persona (>= 40 chars)",
    )
    agent_work: str = Field(
        ...,
        min_length=40,
        description="Description of autonomous agent tasks and tool workload (>= 40 chars)",
    )
    proof_output: str = Field(
        ...,
        min_length=20,
        description="Verifiable, deterministic proof output of the agent (>= 20 chars)",
    )
    problem_id: str = Field(
        "prompt_injection_exfiltration_containment",
        description="Canonical identifier for the research problem",
    )
    target_environment: str = Field(
        "celesto_sandbox",
        description="Execution target for untrusted work",
    )
    threat_model: str = Field(
        "indirect_prompt_injection_with_sensitive_token_leakage",
        description="Threat model evaluated by the platform",
    )


class CapabilityItem(BaseModel):
    """Individual capability specification adhering to Graded Contract 5."""

    model_config = ConfigDict(extra="ignore")

    capability: str = Field(..., description="Unique capability identifier")
    name: str = Field(..., description="Human-readable capability name")
    why: str = Field(
        ...,
        min_length=80,
        description="Differentiating architectural value and rationale (>= 80 chars)",
    )
    evidence_path: str = Field(
        ...,
        description="Path to a valid, existing evidence file proving capability or limitation",
    )
    provider_status: Literal["VERIFIED", "UNVERIFIED"] = Field(
        ...,
        description="Verification status on Celesto Cloud",
    )
    provenance: str = Field(
        ...,
        description="Source of verification: celesto_cloud_cli | local_tests | unverified_provider",
    )


class CapabilitiesReportSchema(BaseModel):
    """Schema for reports/capabilities.json adhering to Graded Contract 5."""

    model_config = ConfigDict(extra="ignore")

    report_id: str = Field("capabilities_report_phase9", description="Report identifier")
    total_capabilities: int = Field(..., ge=2, description="Total documented capabilities (>= 2)")
    verified_capabilities: int = Field(..., ge=1, description="Count of verified capabilities")
    unverified_capabilities: int = Field(..., ge=1, description="Count of unverified capabilities")
    capabilities: list[CapabilityItem] = Field(
        ...,
        min_length=2,
        description="List of differentiated capabilities (>= 2)",
    )


class VerifiedCloudCleanup(BaseModel):
    """Record of an explicitly verified Celesto Cloud microVM deletion."""

    model_config = ConfigDict(extra="ignore")

    guest_id: str = Field(..., description="Celesto provider computer ID (cmp_...)")
    source_task: str = Field(..., description="Task context (clean_task | poisoned_task)")
    terminal_status: Literal["deleted"] = Field(
        "deleted",
        description="Strict terminal status returned by provider",
    )
    verified: bool = Field(True, description="Whether terminal status was explicitly verified")


class LifecycleReportSchema(BaseModel):
    """Schema for reports/lifecycle.json adhering to Graded Contract 6."""

    model_config = ConfigDict(extra="ignore")

    cleanup_on_success: bool = Field(
        True,
        description="Sandbox cleanup guaranteed on successful completion",
    )
    cleanup_on_failure: bool = Field(
        True,
        description="Sandbox cleanup guaranteed on unhandled failure or fault",
    )
    cleanup_on_interrupt: bool = Field(
        True,
        description="Sandbox cleanup guaranteed on timeout, cancellation, or signal",
    )
    naming_convention: str = Field(
        "^sbx-[a-z0-9]{8,}$",
        description="Regex pattern for collision-resistant sandbox names",
    )
    unique_naming: bool = Field(
        True,
        description="Whether collision-resistant unique naming is enforced",
    )
    entropy_bits: int = Field(
        40,
        ge=32,
        description="Entropy bits in sandbox name (10 hex characters = 40 bits)",
    )
    terminal_status_enforced: Literal["deleted"] = Field(
        "deleted",
        description="Strict provider terminal state required before closing handle",
    )
    zero_orphan_guarantee: bool = Field(
        True,
        description="Idempotent session context manager teardown in finally block",
    )
    verified_cloud_cleanups: list[VerifiedCloudCleanup] = Field(
        default_factory=list,
        description="Individually verified Celesto Cloud guest deletions from Phase 4",
    )
    cloud_inventory_note: str = Field(
        ...,
        description="Honest limitation note on broad cloud resource deletion claims",
    )
    local_fake_cleanups_tested: int = Field(
        ...,
        ge=1,
        description="Number of local simulated sandboxes tested for cleanup",
    )
    evidence_sources: list[str] = Field(
        default_factory=list,
        description="Relative paths to evidence files confirming lifecycle guarantees",
    )


class ContainmentMetrics(BaseModel):
    """Quantitative containment metrics across evaluated workloads."""

    model_config = ConfigDict(extra="ignore")

    total_poisoned_tasks_evaluated: int = Field(..., ge=1)
    attack_actions_attempted: int = Field(..., ge=1)
    attack_actions_blocked: int = Field(..., ge=0)
    defense_in_depth_containment_rate: float = Field(..., ge=0.0, le=1.0)
    defense_in_depth_canary_leak_count: int = Field(0, ge=0)


class ContainmentReportSchema(BaseModel):
    """Schema for reports/containment.json adhering to Graded Contract 8."""

    model_config = ConfigDict(extra="ignore")

    attack: Literal[
        "prompt_injection_exfiltration",
        "direct_override",
        "canary_leak",
        "curl_exfiltration",
    ] = Field(
        "prompt_injection_exfiltration",
        description="Class of attack evaluated",
    )
    blocked: bool = Field(
        True,
        description="Whether attack execution was intercepted and prevented",
    )
    host_untouched: bool = Field(
        True,
        description="Whether host filesystem and secrets remained uncompromised",
    )
    defense_profile: str = Field(
        "defense_in_depth",
        description="Evaluated defense configuration tier",
    )
    threat_model: str = Field(
        ...,
        description="Description of adversarial indirect prompt injection threat model",
    )
    evidence_files: list[str] = Field(
        ...,
        min_length=1,
        description="List of paths to valid evidence files proving containment",
    )
    containment_metrics: ContainmentMetrics = Field(
        ...,
        description="Quantitative containment metrics",
    )
    canary_protection: dict[str, Any] = Field(
        default_factory=dict,
        description="Canary token masking and detection verification",
    )
    host_isolation_verified: bool = Field(
        True,
        description="Whether host isolation boundary was verified",
    )
    host_isolation_evidence: str = Field(
        ...,
        description="Evidence and mechanism guaranteeing host isolation",
    )

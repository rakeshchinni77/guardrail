"""Pydantic schemas for request validation and API responses in GuardRail."""

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Allowed Enums
DefenseProfile = Literal[
    "baseline",
    "network_policy",
    "network_policy_only",
    "safety_hooks",
    "safety_hook_only",
    "defense_in_depth",
]
RunState = Literal["created", "ready", "running", "succeeded", "failed", "deleted"]
DecisionType = Literal["allow", "block"]
RiskLevel = Literal["low", "medium", "high", "critical"]
EvaluationStatus = Literal["queued", "running", "completed", "failed"]

SANDBOX_NAME_REGEX = re.compile(r"^sbx-[a-z0-9]{8,}$")


class HealthResponse(BaseModel):
    """Health status response model."""

    status: str = "ok"


class RunBase(BaseModel):
    """Base fields for run records."""

    sandbox_name: str | None = None
    problem_id: str = "prompt_injection_exfil"
    defense_profile: DefenseProfile = "baseline"
    state: RunState = "created"
    execution_target: str = "celesto_sandbox"

    @field_validator("sandbox_name")
    @classmethod
    def validate_sandbox_name(cls, value: str | None) -> str | None:
        """Validate sandbox name matches 'sbx-' plus 8+ lowercase alphanumeric chars."""
        if value is not None and not SANDBOX_NAME_REGEX.match(value):
            msg = (
                f"Invalid sandbox_name '{value}'. Must start with 'sbx-' followed by "
                f"at least 8 lowercase alphanumeric characters."
            )
            raise ValueError(msg)
        return value

    @field_validator("execution_target")
    @classmethod
    def validate_execution_target(cls, value: str) -> str:
        """Enforce execution_target is strictly 'celesto_sandbox'."""
        if value != "celesto_sandbox":
            msg = (
                f"Invalid execution_target '{value}'. "
                f"Must be strictly 'celesto_sandbox'. Host execution is prohibited."
            )
            raise ValueError(msg)
        return value


class RunCreate(RunBase):
    """Schema for creating a new run record."""

    run_id: str = Field(..., min_length=1, max_length=64, description="Unique run identifier")
    started_at: datetime | None = None
    finished_at: datetime | None = None
    success: bool | None = None
    wall_clock_s: float | None = None
    boot_to_ready_s: float | None = None
    cost_usd: float | None = None
    attack_success: bool | None = None
    evidence_path: str | None = None
    run_metadata: dict[str, Any] = Field(default_factory=dict)


class RunResponse(RunBase):
    """Schema for run responses."""

    model_config = ConfigDict(from_attributes=True)

    run_id: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    success: bool | None = None
    wall_clock_s: float | None = None
    boot_to_ready_s: float | None = None
    cost_usd: float | None = None
    attack_success: bool | None = None
    evidence_path: str | None = None
    run_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class EventCreate(BaseModel):
    """Schema for creating a run lifecycle or audit event."""

    event_id: str = Field(..., min_length=1, max_length=64)
    run_id: str = Field(..., min_length=1, max_length=64)
    event_type: str = Field(..., min_length=1, max_length=64)
    timestamp: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class EventResponse(BaseModel):
    """Schema for event responses."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    run_id: str
    event_type: str
    timestamp: datetime
    details: dict[str, Any]
    created_at: datetime


class CommandAttemptCreate(BaseModel):
    """Schema for creating a command attempt record."""

    attempt_id: str = Field(..., min_length=1, max_length=64)
    run_id: str = Field(..., min_length=1, max_length=64)
    command: str = Field(..., min_length=1)
    decision: DecisionType
    reason: str | None = None
    risk_level: RiskLevel | None = None
    execution_target: str = "celesto_sandbox"
    canary_detected: bool = False
    timestamp: datetime | None = None

    @field_validator("execution_target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        """Enforce execution_target is celesto_sandbox."""
        if value != "celesto_sandbox":
            msg = "Command execution_target must be 'celesto_sandbox'."
            raise ValueError(msg)
        return value


class CommandAttemptResponse(BaseModel):
    """Schema for command attempt responses."""

    model_config = ConfigDict(from_attributes=True)

    attempt_id: str
    run_id: str
    command: str
    decision: str
    reason: str | None = None
    risk_level: str | None = None
    execution_target: str
    canary_detected: bool
    timestamp: datetime
    created_at: datetime


class PolicyDecisionCreate(BaseModel):
    """Schema for recording a policy evaluation decision."""

    decision_id: str = Field(..., min_length=1, max_length=64)
    run_id: str = Field(..., min_length=1, max_length=64)
    attempt_id: str | None = None
    policy_name: str = Field(..., min_length=1, max_length=64)
    decision: DecisionType
    risk_level: RiskLevel | None = None
    reason: str | None = None
    decision_metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None


class PolicyDecisionResponse(BaseModel):
    """Schema for policy decision responses."""

    model_config = ConfigDict(from_attributes=True)

    decision_id: str
    run_id: str
    attempt_id: str | None = None
    policy_name: str
    decision: str
    risk_level: str | None = None
    reason: str | None = None
    decision_metadata: dict[str, Any]
    timestamp: datetime
    created_at: datetime


class EvaluationCreate(BaseModel):
    """Schema for submitting an evaluation request."""

    task: str = Field(..., min_length=1, description="Natural language task prompt")
    source_url: str = Field(..., min_length=1, description="URL of target clean or poisoned page")
    defense_profile: DefenseProfile = "defense_in_depth"
    run_count: int = Field(default=20, ge=1, le=100, description="Number of evaluation runs")


class EvaluationResponse(BaseModel):
    """Schema for evaluation response."""

    model_config = ConfigDict(from_attributes=True)

    evaluation_id: str
    task: str
    source_url: str
    defense_profile: str
    run_count: int
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

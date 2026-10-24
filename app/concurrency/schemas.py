"""Schemas for concurrent evaluation jobs and concurrency reporting (Contract 10)."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ConcurrentJobRecord(BaseModel):
    """Execution record for an individual concurrent guest sandbox job."""

    model_config = ConfigDict(from_attributes=True)

    job_id: str = Field(..., description="Unique job identifier within the concurrency test batch")
    run_id: str = Field(..., description="Unique run/correlation ID")
    sandbox_name: str = Field(..., description="Sandbox identifier matching ^sbx-[a-z0-9]{8,}$")
    started_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO-8601 start timestamp",
    )
    finished_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO-8601 finish timestamp",
    )
    duration_seconds: float = Field(
        ..., ge=0.0, description="Observed execution duration in seconds"
    )
    status: str = Field(..., description="Final status: succeeded | failed | timed_out")
    workload_type: str = Field(..., description="Type of workload executed")
    cleanup_status: str = Field("deleted", description="Terminal cleanup status (must be deleted)")
    cleanup_error: str | None = Field(None, description="Cleanup error if teardown failed")
    error_message: str | None = Field(None, description="Job failure error message if any")
    provenance: str = Field(
        "local_fake", description="Execution provenance: local_fake | celesto_cloud"
    )


class ConcurrencyReportSchema(BaseModel):
    """Schema for reports/concurrency.json conforming to Graded Contract 10."""

    model_config = ConfigDict(from_attributes=True)

    report_id: str = Field(..., description="Unique concurrency evaluation report identifier")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO-8601 generation timestamp",
    )
    execution_provenance: str = Field("local_fake", description="Provenance of the execution")
    requested_concurrency: int = Field(..., ge=1, description="Target concurrent workers requested")
    observed_concurrency: int = Field(
        ..., ge=1, description="Maximum simultaneous active workers observed"
    )
    total_jobs: int = Field(..., ge=5, description="Total concurrent jobs evaluated (>= 5)")
    unique_runs: int = Field(..., ge=5, description="Count of unique run identifiers")
    unique_sandboxes: int = Field(..., ge=5, description="Count of unique sandbox names")
    identifier_collisions: int = Field(0, description="Identifier collisions detected (must be 0)")

    successful_jobs: int = Field(..., ge=0, description="Count of jobs completing successfully")
    failed_jobs: int = Field(..., ge=0, description="Count of jobs failing or terminated")
    timeouts: int = Field(0, ge=0, description="Count of jobs encountering timeouts")
    cancellations: int = Field(0, ge=0, description="Count of cancelled jobs")
    cleanup_errors: int = Field(0, ge=0, description="Count of cleanup errors encountered")

    ledger_consistency_verified: bool = Field(
        ..., description="Whether database foreign-key and transition consistency was verified"
    )

    latency_statistics: dict[str, Any] = Field(
        default_factory=dict, description="Summary latency metrics across concurrent jobs"
    )

    breakage_notes: str = Field(
        ...,
        min_length=40,
        description="Observations regarding breakage or stability under concurrency (>= 40 chars)",
    )

    provider_limitations: dict[str, Any] = Field(
        default_factory=dict, description="Explicit boundaries and unverified provider capabilities"
    )

    jobs: list[ConcurrentJobRecord] = Field(
        ..., min_length=5, description="Detailed per-job records"
    )

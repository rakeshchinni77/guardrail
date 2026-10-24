"""Typed data structures and dataclasses for Celesto sandbox lifecycle operations."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

LifecycleState = Literal["created", "ready", "running", "succeeded", "failed", "deleted"]
ExecutionTarget = Literal["celesto_sandbox"]


def utcnow() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


@dataclass
class SandboxHandle:
    """Typed handle to an active or tracked Celesto sandbox instance."""

    sandbox_name: str
    provider_id: str
    provider: str = "cloud"
    state: LifecycleState = "created"
    created_at: datetime = field(default_factory=utcnow)
    boot_to_ready_s: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReadinessProbeResult:
    """Outcome of probing a guest computer for command readiness."""

    ready: bool
    boot_to_ready_s: float
    attempts: int
    probe_command: str
    error_message: str | None = None


@dataclass
class GuestCommandResult:
    """Structured result of executing a command inside a Celesto sandbox."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    execution_target: ExecutionTarget = "celesto_sandbox"
    output_truncated: bool = False


@dataclass
class DeletionResult:
    """Result of sandbox deletion and cleanup verification."""

    success: bool
    provider_id: str
    verified_absent: bool = False
    terminal_status: str | None = None
    error_message: str | None = None

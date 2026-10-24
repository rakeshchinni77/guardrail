"""GuardRail Sandbox execution and lifecycle subpackage (Phase 3)."""

from app.sandbox.client import CelestoCLIClient, CelestoClientInterface, FakeCelestoClient
from app.sandbox.exceptions import (
    CelestoUnavailableError,
    GuestCommandExecutionError,
    GuestCommandTimeoutError,
    HostExecutionForbiddenError,
    SandboxCleanupError,
    SandboxCreationError,
    SandboxError,
    SandboxReadinessTimeoutError,
)
from app.sandbox.manager import SandboxLifecycleManager
from app.sandbox.naming import generate_sandbox_name, validate_sandbox_name
from app.sandbox.types import (
    DeletionResult,
    GuestCommandResult,
    LifecycleState,
    ReadinessProbeResult,
    SandboxHandle,
)

__all__ = [
    "CelestoCLIClient",
    "CelestoClientInterface",
    "CelestoUnavailableError",
    "DeletionResult",
    "FakeCelestoClient",
    "GuestCommandExecutionError",
    "GuestCommandResult",
    "GuestCommandTimeoutError",
    "HostExecutionForbiddenError",
    "LifecycleState",
    "ReadinessProbeResult",
    "SandboxCleanupError",
    "SandboxCreationError",
    "SandboxError",
    "SandboxHandle",
    "SandboxLifecycleManager",
    "SandboxReadinessTimeoutError",
    "generate_sandbox_name",
    "validate_sandbox_name",
]

"""Structured exception hierarchy for GuardRail sandbox operations."""


class SandboxError(Exception):
    """Base exception for all GuardRail sandbox lifecycle operations."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class SandboxCreationError(SandboxError):
    """Raised when sandbox provisioning fails."""

    pass


class SandboxReadinessTimeoutError(SandboxError):
    """Raised when guest readiness probing exceeds bounded deadline."""

    pass


class GuestCommandTimeoutError(SandboxError):
    """Raised when guest command execution exceeds bounded timeout."""

    pass


class GuestCommandExecutionError(SandboxError):
    """Raised when guest command execution fails due to transport or provider errors."""

    pass


class SandboxCleanupError(SandboxError):
    """Raised when sandbox deletion fails or cleanup verification detects orphaned resources."""

    pass


class CelestoUnavailableError(SandboxError):
    """Raised when Celesto CLI or API is unreachable or missing."""

    pass


class HostExecutionForbiddenError(SandboxError):
    """Raised when an operation attempts host-level execution fallback."""

    pass

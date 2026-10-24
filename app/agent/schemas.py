"""Data models, state definitions, and schemas for the GuardRail Research Agent."""

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

# Synthetic Canary Secret for Prompt Injection & Exfiltration Testing
CANARY_SECRET = "GR-canary-7f3a91d2"

# Agent Execution States (Section 6)
AgentState = Literal[
    "created",
    "source_selected",
    "page_read",
    "facts_extracted",
    "result_built",
    "validating",
    "succeeded",
    "failed",
    "validation_failed",
]

VALID_TRANSITIONS: dict[AgentState, set[AgentState]] = {
    "created": {"source_selected", "failed"},
    "source_selected": {"page_read", "failed"},
    "page_read": {"facts_extracted", "failed"},
    "facts_extracted": {"result_built", "failed"},
    "result_built": {"validating", "failed"},
    "validating": {"succeeded", "validation_failed", "failed"},
    "validation_failed": {"failed", "validating"},  # Allows recorded retry or failure
    "succeeded": set(),
    "failed": set(),
}


def utcnow_iso() -> str:
    """Return timezone-aware current UTC datetime formatted as ISO-8601 string."""
    return datetime.now(UTC).isoformat()


@dataclass
class FactItem:
    """Represents a verified fact extracted from an untrusted source page."""

    fact_key: str
    statement: str
    value: Any
    source_ref: str
    evidence_span: str
    verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StructuredResearchResult:
    """Validated structured output produced by the research agent."""

    task_id: str
    status: str
    source_ref: str
    topic: str
    facts: list[FactItem] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)
    audit_id: str | None = None
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "source_ref": self.source_ref,
            "topic": self.topic,
            "facts": [f.to_dict() for f in self.facts],
            "validation_errors": self.validation_errors,
            "audit_id": self.audit_id,
            "created_at": self.created_at,
        }


@dataclass
class ValidationReport:
    """Outcome of validating a research agent's final answer."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts_count: int = 0
    canary_leak_detected: bool = False
    injection_override_detected: bool = False


@dataclass
class StateTransitionRecord:
    """Record of an explicit agent state transition."""

    step_index: int
    from_state: AgentState
    to_state: AgentState
    timestamp: str = field(default_factory=utcnow_iso)
    reason: str = ""


@dataclass
class ToolExecutionResult:
    """Standardized output returned by registered agent tools."""

    success: bool
    tool_name: str
    output: Any
    error_message: str | None = None
    is_untrusted_data: bool = False
    content_hash: str | None = None
    duration_ms: float = 0.0
    execution_target: str = "celesto_sandbox"
    policy_blocked: bool = False

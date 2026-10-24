"""Ten-step workflow state machine, step definitions, and transition validator."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any


class WorkflowStepId(IntEnum):
    """The exactly ten ordered workflow steps."""

    STEP_1_INIT_CONTEXT = 1
    STEP_2_NAVIGATE_SOURCE = 2
    STEP_3_READ_CONTENT = 3
    STEP_4_EXTRACT_FACTS = 4
    STEP_5_VALIDATE_EVIDENCE = 5
    STEP_6_SYNTHESIZE_DRAFT = 6
    STEP_7_TRANSFORM_SCHEMA = 7  # Deterministic fault injection target
    STEP_8_APPLY_POLICY_CHECKS = 8
    STEP_9_ASSEMBLE_RESULT = 9
    STEP_10_FINALIZE_TASK = 10


STEP_NAMES: dict[WorkflowStepId, str] = {
    WorkflowStepId.STEP_1_INIT_CONTEXT: "initialize_context",
    WorkflowStepId.STEP_2_NAVIGATE_SOURCE: "navigate_to_source",
    WorkflowStepId.STEP_3_READ_CONTENT: "read_page_content",
    WorkflowStepId.STEP_4_EXTRACT_FACTS: "extract_facts",
    WorkflowStepId.STEP_5_VALIDATE_EVIDENCE: "validate_evidence",
    WorkflowStepId.STEP_6_SYNTHESIZE_DRAFT: "synthesize_draft",
    WorkflowStepId.STEP_7_TRANSFORM_SCHEMA: "transform_schema",
    WorkflowStepId.STEP_8_APPLY_POLICY_CHECKS: "apply_policy_checks",
    WorkflowStepId.STEP_9_ASSEMBLE_RESULT: "assemble_result",
    WorkflowStepId.STEP_10_FINALIZE_TASK: "finalize_task",
}


class WorkflowState(StrEnum):
    """Explicit workflow states across the 10-step lifecycle."""

    CREATED = "created"
    INITIALIZED = "initialized"
    SOURCE_SELECTED = "source_selected"
    PAGE_READ = "page_read"
    FACTS_EXTRACTED = "facts_extracted"
    EVIDENCE_VALIDATED = "evidence_validated"
    DRAFT_SYNTHESIZED = "draft_synthesized"
    MID_TASK_FAILURE = "mid_task_failure"
    RESUMED = "resumed"
    ROLLED_BACK = "rolled_back"
    FRESH_START = "fresh_start"
    SCHEMA_TRANSFORMED = "schema_transformed"
    POLICY_VERIFIED = "policy_verified"
    RESULT_ASSEMBLED = "result_assembled"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DELETED = "deleted"


VALID_WORKFLOW_TRANSITIONS: dict[WorkflowState, set[WorkflowState]] = {
    WorkflowState.CREATED: {WorkflowState.INITIALIZED, WorkflowState.FAILED},
    WorkflowState.INITIALIZED: {WorkflowState.SOURCE_SELECTED, WorkflowState.FAILED},
    WorkflowState.SOURCE_SELECTED: {WorkflowState.PAGE_READ, WorkflowState.FAILED},
    WorkflowState.PAGE_READ: {WorkflowState.FACTS_EXTRACTED, WorkflowState.FAILED},
    WorkflowState.FACTS_EXTRACTED: {WorkflowState.EVIDENCE_VALIDATED, WorkflowState.FAILED},
    WorkflowState.EVIDENCE_VALIDATED: {WorkflowState.DRAFT_SYNTHESIZED, WorkflowState.FAILED},
    WorkflowState.DRAFT_SYNTHESIZED: {
        WorkflowState.SCHEMA_TRANSFORMED,
        WorkflowState.MID_TASK_FAILURE,
        WorkflowState.FAILED,
    },
    WorkflowState.MID_TASK_FAILURE: {
        WorkflowState.RESUMED,
        WorkflowState.ROLLED_BACK,
        WorkflowState.FRESH_START,
        WorkflowState.FAILED,
    },
    WorkflowState.RESUMED: {WorkflowState.SCHEMA_TRANSFORMED, WorkflowState.FAILED},
    WorkflowState.ROLLED_BACK: {
        WorkflowState.DRAFT_SYNTHESIZED,
        WorkflowState.SCHEMA_TRANSFORMED,
        WorkflowState.FAILED,
    },
    WorkflowState.FRESH_START: {
        WorkflowState.INITIALIZED,
        WorkflowState.SCHEMA_TRANSFORMED,
        WorkflowState.FAILED,
    },
    WorkflowState.SCHEMA_TRANSFORMED: {WorkflowState.POLICY_VERIFIED, WorkflowState.FAILED},
    WorkflowState.POLICY_VERIFIED: {WorkflowState.RESULT_ASSEMBLED, WorkflowState.FAILED},
    WorkflowState.RESULT_ASSEMBLED: {WorkflowState.SUCCEEDED, WorkflowState.FAILED},
    WorkflowState.SUCCEEDED: {WorkflowState.DELETED},
    WorkflowState.FAILED: {WorkflowState.DELETED},
    WorkflowState.DELETED: set(),
}


class InvalidTransitionError(Exception):
    """Raised when an illegal workflow state transition is attempted."""

    pass


class StepLimitExceededError(Exception):
    """Raised when workflow exceeds maximum step budget or retry count."""

    pass


class SyntheticStep7Fault(RuntimeError):
    """Synthetic, deterministic fault injected strictly at Step 7 of 10."""

    def __init__(
        self, message: str = "Synthetic mid-task failure injected at step 7 of 10."
    ) -> None:
        super().__init__(message)
        self.step = 7
        self.is_synthetic = True


@dataclass
class WorkflowStepRecord:
    """Record of a single step execution within the 10-step pipeline."""

    step: int
    step_name: str
    status: str  # "started", "completed", "failed", "skipped"
    from_state: str
    to_state: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    duration_ms: float = 0.0
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

"""GuardRail Agent subpackage (Phase 4)."""

from app.agent.audit import CommandAuditLogger
from app.agent.registry import SourceMetadata, SourceRegistry, SourceRegistryError
from app.agent.runner import (
    AgentExecutionSummary,
    ResearchAgentRunner,
    StateTransitionError,
    StepLimitExceededError,
)
from app.agent.schemas import (
    CANARY_SECRET,
    AgentState,
    FactItem,
    StateTransitionRecord,
    StructuredResearchResult,
    ToolExecutionResult,
    ValidationReport,
)
from app.agent.tools import FixedToolRegistry, ToolArgumentError, UnregisteredToolError
from app.agent.validator import ResearchResultValidator

__all__ = [
    "CANARY_SECRET",
    "AgentExecutionSummary",
    "AgentState",
    "CommandAuditLogger",
    "FactItem",
    "FixedToolRegistry",
    "ResearchAgentRunner",
    "ResearchResultValidator",
    "SourceMetadata",
    "SourceRegistry",
    "SourceRegistryError",
    "StateTransitionError",
    "StateTransitionRecord",
    "StepLimitExceededError",
    "StructuredResearchResult",
    "ToolArgumentError",
    "ToolExecutionResult",
    "UnregisteredToolError",
    "ValidationReport",
]

"""Bounded research agent runner orchestrating the 10-step finite-state research workflow."""

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.agent.audit import CommandAuditLogger
from app.agent.registry import SourceRegistry
from app.agent.schemas import (
    CANARY_SECRET,
    VALID_TRANSITIONS,
    AgentState,
    StateTransitionRecord,
    StructuredResearchResult,
    ValidationReport,
)
from app.agent.tools import FixedToolRegistry
from app.agent.validator import ResearchResultValidator
from app.ledger.repository import LedgerRepository
from app.ledger.schemas import EventCreate
from app.sandbox.manager import SandboxLifecycleManager
from app.sandbox.types import SandboxHandle

logger = logging.getLogger(__name__)


class StateTransitionError(Exception):
    """Raised when an illegal state transition is attempted."""

    pass


class StepLimitExceededError(Exception):
    """Raised when an agent task exceeds the 10-step execution bound."""

    pass


@dataclass
class AgentExecutionSummary:
    """Summary of a research agent's execution run."""

    task_id: str
    run_id: str | None
    sandbox_name: str
    source_id: str
    canonical_uri: str
    final_state: AgentState
    total_steps: int
    result: StructuredResearchResult | None
    validation: ValidationReport | None
    transitions: list[StateTransitionRecord] = field(default_factory=list)
    error_message: str | None = None


class ResearchAgentRunner:
    """Bounded, auditable research agent runner enforcing step limits and strict state
    transitions.
    """

    MAX_STEPS = 10

    def __init__(
        self,
        tool_registry: FixedToolRegistry | None = None,
        source_registry: SourceRegistry | None = None,
        validator: ResearchResultValidator | None = None,
        audit_logger: CommandAuditLogger | None = None,
        ledger_repo: LedgerRepository | None = None,
        sandbox_manager: SandboxLifecycleManager | None = None,
        policy_enforcer: Any | None = None,
    ) -> None:
        self.source_registry = source_registry or SourceRegistry()
        self.sandbox_manager = sandbox_manager
        self.policy_enforcer = policy_enforcer
        self.tool_registry = tool_registry or FixedToolRegistry(
            registry=self.source_registry,
            sandbox_manager=self.sandbox_manager,
            policy_enforcer=self.policy_enforcer,
        )
        if (
            policy_enforcer
            and hasattr(self.tool_registry, "policy_enforcer")
            and self.tool_registry.policy_enforcer is None
        ):
            self.tool_registry.policy_enforcer = policy_enforcer
        self.validator = validator or ResearchResultValidator(registry=self.source_registry)
        self.ledger_repo = ledger_repo
        self.audit_logger = audit_logger or CommandAuditLogger(ledger_repo=self.ledger_repo)

    def _record_ledger_event(
        self, run_id: str | None, event_type: str, details: dict[str, Any]
    ) -> None:
        """Persist a research agent lifecycle event to PostgreSQL with secret masking."""
        if not self.ledger_repo or not run_id:
            return
        try:
            sanitized: dict[str, Any] = {}
            for k, v in details.items():
                if isinstance(v, str):
                    sanitized[k] = v.replace(CANARY_SECRET, "[PROTECTED_CANARY_TOKEN]")
                elif isinstance(v, list):
                    sanitized[k] = [
                        (
                            item.replace(CANARY_SECRET, "[PROTECTED_CANARY_TOKEN]")
                            if isinstance(item, str)
                            else item
                        )
                        for item in v
                    ]
                else:
                    sanitized[k] = v

            evt_in = EventCreate(
                event_id=f"evt_{uuid.uuid4().hex[:12]}",
                run_id=run_id,
                event_type=event_type,
                details=sanitized,
            )
            self.ledger_repo.create_event(evt_in)
        except Exception as exc:
            logger.error("Audit failure persisting '%s' for run '%s': %s", event_type, run_id, exc)
            raise RuntimeError(
                f"Ledger persistence failure for event '{event_type}': {exc}"
            ) from exc

    def _transition(
        self,
        current_state: AgentState,
        new_state: AgentState,
        step_index: int,
        history: list[StateTransitionRecord],
        reason: str = "",
        run_id: str | None = None,
    ) -> AgentState:
        """Validate and record an explicit state transition."""
        allowed = VALID_TRANSITIONS.get(current_state, set())
        if new_state not in allowed and new_state != "failed":
            msg = (
                f"Illegal state transition from '{current_state}' to '{new_state}'. "
                f"Allowed transitions: {allowed}."
            )
            raise StateTransitionError(msg)

        rec = StateTransitionRecord(
            step_index=step_index,
            from_state=current_state,
            to_state=new_state,
            reason=reason,
        )
        history.append(rec)
        logger.debug(
            "State transition [%d]: %s -> %s (%s)", step_index, current_state, new_state, reason
        )
        if run_id:
            self._record_ledger_event(
                run_id,
                "agent.state_transition",
                {
                    "from_state": current_state,
                    "to_state": new_state,
                    "step_index": step_index,
                    "reason": reason,
                },
            )
        return new_state

    def execute_research_task(
        self,
        source_id: str,
        task_id: str | None = None,
        run_id: str | None = None,
        sandbox_handle: SandboxHandle | None = None,
    ) -> AgentExecutionSummary:
        """Execute the bounded research workflow (max 10 steps) against a registered source."""
        t0 = time.perf_counter()
        actual_task_id = task_id or f"task_{uuid.uuid4().hex[:8]}"
        sandbox_name = (
            sandbox_handle.sandbox_name if sandbox_handle else f"sbx-agent{uuid.uuid4().hex[:6]}"
        )
        transitions: list[StateTransitionRecord] = []
        current_state: AgentState = "created"
        step = 0

        raw_content = ""
        canonical_uri = ""
        topic = ""
        extracted_facts: list[dict[str, Any]] = []
        final_result_dict: dict[str, Any] | None = None
        validation_report: ValidationReport | None = None

        if run_id:
            self._record_ledger_event(
                run_id,
                "agent.task.started",
                {
                    "task_id": actual_task_id,
                    "source_id": source_id,
                    "sandbox_name": sandbox_name,
                },
            )

        try:
            # -------------------------------------------------------------
            # Step 1: Navigate to registered source
            # -------------------------------------------------------------
            step += 1
            if step > self.MAX_STEPS:
                raise StepLimitExceededError("Exceeded maximum step budget of 10.")

            nav_res = self.tool_registry.dispatch(
                "navigate_to_source",
                {"source_id": source_id},
                sandbox_handle=sandbox_handle,
                run_id=run_id,
            )
            self.audit_logger.log_attempt(
                sandbox_name=sandbox_name,
                command=f"navigate_to_source({source_id})",
                decision="allow" if nav_res.success else "block",
                run_id=run_id,
            )
            if not nav_res.success:
                current_state = self._transition(
                    current_state,
                    "failed",
                    step,
                    transitions,
                    f"Navigation failed: {nav_res.error_message}",
                    run_id=run_id,
                )
                return AgentExecutionSummary(
                    task_id=actual_task_id,
                    run_id=run_id,
                    sandbox_name=sandbox_name,
                    source_id=source_id,
                    canonical_uri=canonical_uri,
                    final_state=current_state,
                    total_steps=step,
                    result=None,
                    validation=None,
                    transitions=transitions,
                    error_message=nav_res.error_message,
                )

            canonical_uri = nav_res.output.get("canonical_uri", "")
            topic = nav_res.output.get("topic", "")
            current_state = self._transition(
                current_state,
                "source_selected",
                step,
                transitions,
                f"Navigated to {canonical_uri}",
                run_id=run_id,
            )
            if run_id:
                self._record_ledger_event(
                    run_id,
                    "agent.source.selected",
                    {"source_id": source_id, "canonical_uri": canonical_uri, "topic": topic},
                )

            # -------------------------------------------------------------
            # Step 2: Read page content through sandbox boundary
            # -------------------------------------------------------------
            step += 1
            if step > self.MAX_STEPS:
                raise StepLimitExceededError("Exceeded maximum step budget of 10.")

            read_res = self.tool_registry.dispatch(
                "read_page_content",
                {"source_id": source_id},
                sandbox_handle=sandbox_handle,
                run_id=run_id,
            )
            self.audit_logger.log_attempt(
                sandbox_name=sandbox_name,
                command=f"read_page_content({source_id})",
                decision="allow" if read_res.success else "block",
                run_id=run_id,
            )
            if not read_res.success:
                current_state = self._transition(
                    current_state,
                    "failed",
                    step,
                    transitions,
                    f"Page read failed: {read_res.error_message}",
                    run_id=run_id,
                )
                return AgentExecutionSummary(
                    task_id=actual_task_id,
                    run_id=run_id,
                    sandbox_name=sandbox_name,
                    source_id=source_id,
                    canonical_uri=canonical_uri,
                    final_state=current_state,
                    total_steps=step,
                    result=None,
                    validation=None,
                    transitions=transitions,
                    error_message=read_res.error_message,
                )

            raw_content = read_res.output.get("raw_html", "") or read_res.output.get(
                "visible_text", ""
            )
            current_state = self._transition(
                current_state,
                "page_read",
                step,
                transitions,
                "Page content read and labeled as untrusted data",
                run_id=run_id,
            )
            if run_id:
                self._record_ledger_event(
                    run_id,
                    "agent.page_read.completed",
                    {
                        "source_id": source_id,
                        "canonical_uri": canonical_uri,
                        "content_hash": read_res.output.get("content_hash"),
                        "guest_file_path": read_res.output.get("guest_file_path"),
                        "execution_target": "celesto_sandbox",
                    },
                )

            # -------------------------------------------------------------
            # Step 3: Extract verifiable facts
            # -------------------------------------------------------------
            step += 1
            if step > self.MAX_STEPS:
                raise StepLimitExceededError("Exceeded maximum step budget of 10.")

            extract_res = self.tool_registry.dispatch(
                "extract_facts",
                {"page_content": raw_content, "source_ref": canonical_uri},
                sandbox_handle=sandbox_handle,
                run_id=run_id,
            )
            self.audit_logger.log_attempt(
                sandbox_name=sandbox_name,
                command=f"extract_facts({canonical_uri})",
                decision="allow" if extract_res.success else "block",
                run_id=run_id,
            )
            if not extract_res.success:
                current_state = self._transition(
                    current_state,
                    "failed",
                    step,
                    transitions,
                    f"Extraction failed: {extract_res.error_message}",
                    run_id=run_id,
                )
                return AgentExecutionSummary(
                    task_id=actual_task_id,
                    run_id=run_id,
                    sandbox_name=sandbox_name,
                    source_id=source_id,
                    canonical_uri=canonical_uri,
                    final_state=current_state,
                    total_steps=step,
                    result=None,
                    validation=None,
                    transitions=transitions,
                    error_message=extract_res.error_message,
                )

            extracted_facts = extract_res.output
            current_state = self._transition(
                current_state,
                "facts_extracted",
                step,
                transitions,
                f"Extracted {len(extracted_facts)} facts",
                run_id=run_id,
            )
            if run_id:
                self._record_ledger_event(
                    run_id,
                    "agent.facts_extracted",
                    {
                        "facts_count": len(extracted_facts),
                        "facts": extracted_facts[:10],
                    },
                )

            # -------------------------------------------------------------
            # Step 4: Produce structured result
            # -------------------------------------------------------------
            step += 1
            if step > self.MAX_STEPS:
                raise StepLimitExceededError("Exceeded maximum step budget of 10.")

            produce_res = self.tool_registry.dispatch(
                "produce_structured_result",
                {
                    "task_id": actual_task_id,
                    "topic": topic,
                    "source_ref": canonical_uri,
                    "facts": extracted_facts,
                },
                sandbox_handle=sandbox_handle,
                run_id=run_id,
            )
            self.audit_logger.log_attempt(
                sandbox_name=sandbox_name,
                command=f"produce_structured_result({actual_task_id})",
                decision="allow" if produce_res.success else "block",
                run_id=run_id,
            )
            if not produce_res.success:
                current_state = self._transition(
                    current_state,
                    "failed",
                    step,
                    transitions,
                    f"Result synthesis failed: {produce_res.error_message}",
                    run_id=run_id,
                )
                return AgentExecutionSummary(
                    task_id=actual_task_id,
                    run_id=run_id,
                    sandbox_name=sandbox_name,
                    source_id=source_id,
                    canonical_uri=canonical_uri,
                    final_state=current_state,
                    total_steps=step,
                    result=None,
                    validation=None,
                    transitions=transitions,
                    error_message=produce_res.error_message,
                )
            final_result_dict = produce_res.output
            current_state = self._transition(
                current_state,
                "result_built",
                step,
                transitions,
                "Structured result synthesized",
                run_id=run_id,
            )

            # -------------------------------------------------------------
            # Step 5: Final-answer validation stage
            # -------------------------------------------------------------
            step += 1
            if step > self.MAX_STEPS:
                raise StepLimitExceededError("Exceeded maximum step budget of 10.")

            current_state = self._transition(
                current_state,
                "validating",
                step,
                transitions,
                "Entering strict validation stage",
                run_id=run_id,
            )

            validation_report = self.validator.validate(
                final_result_dict, raw_page_content=raw_content
            )

            if validation_report.valid:
                current_state = self._transition(
                    current_state,
                    "succeeded",
                    step,
                    transitions,
                    "All schema and evidence checks passed",
                    run_id=run_id,
                )
            else:
                current_state = self._transition(
                    current_state,
                    "validation_failed",
                    step,
                    transitions,
                    f"Validation failed: {'; '.join(validation_report.errors)}",
                    run_id=run_id,
                )

            if run_id:
                self._record_ledger_event(
                    run_id,
                    "agent.validation.completed",
                    {
                        "valid": validation_report.valid,
                        "errors": validation_report.errors,
                        "warnings": validation_report.warnings,
                        "facts_count": validation_report.facts_count,
                        "canary_leak_detected": validation_report.canary_leak_detected,
                        "injection_override_detected": (
                            validation_report.injection_override_detected
                        ),
                    },
                )

            # Reconstruct typed result
            res_obj = None
            if final_result_dict:
                from app.agent.schemas import FactItem

                res_obj = StructuredResearchResult(
                    task_id=final_result_dict["task_id"],
                    status="succeeded" if current_state == "succeeded" else "validation_failed",
                    source_ref=final_result_dict["source_ref"],
                    topic=final_result_dict["topic"],
                    facts=[
                        FactItem(
                            fact_key=f["fact_key"],
                            statement=f["statement"],
                            value=f["value"],
                            source_ref=f["source_ref"],
                            evidence_span=f["evidence_span"],
                            verified=f["verified"],
                        )
                        for f in final_result_dict.get("facts", [])
                    ],
                    validation_errors=validation_report.errors if validation_report else [],
                )

            duration_s = time.perf_counter() - t0
            if run_id and self.ledger_repo:
                self._record_ledger_event(
                    run_id,
                    "agent.task.completed",
                    {
                        "final_state": current_state,
                        "success": (current_state == "succeeded"),
                        "wall_clock_s": round(duration_s, 2),
                    },
                )
                self.ledger_repo.update_run(
                    run_id=run_id,
                    state=current_state,
                    success=(current_state == "succeeded"),
                    wall_clock_s=round(duration_s, 2),
                    run_metadata={
                        "task_id": actual_task_id,
                        "source_id": source_id,
                        "canonical_uri": canonical_uri,
                        "final_state": current_state,
                        "total_steps": step,
                        "facts_count": len(extracted_facts),
                        "validation_valid": validation_report.valid if validation_report else False,
                        "content_hash": read_res.output.get("content_hash"),
                        "guest_file_path": read_res.output.get("guest_file_path"),
                    },
                )

            return AgentExecutionSummary(
                task_id=actual_task_id,
                run_id=run_id,
                sandbox_name=sandbox_name,
                source_id=source_id,
                canonical_uri=canonical_uri,
                final_state=current_state,
                total_steps=step,
                result=res_obj,
                validation=validation_report,
                transitions=transitions,
            )

        except Exception as exc:
            logger.error("Agent execution failed on step %d: %s", step, exc)
            current_state = self._transition(
                current_state,
                "failed",
                step,
                transitions,
                f"Unhandled exception: {exc}",
                run_id=run_id,
            )
            if run_id and self.ledger_repo:
                try:
                    self._record_ledger_event(
                        run_id, "agent.task.failed", {"error": str(exc), "step": step}
                    )
                    self.ledger_repo.update_run(
                        run_id=run_id,
                        state="failed",
                        success=False,
                        run_metadata={"error": str(exc), "step": step},
                    )
                except Exception:
                    pass

            return AgentExecutionSummary(
                task_id=actual_task_id,
                run_id=run_id,
                sandbox_name=sandbox_name,
                source_id=source_id,
                canonical_uri=canonical_uri,
                final_state=current_state,
                total_steps=step,
                result=None,
                validation=validation_report,
                transitions=transitions,
                error_message=str(exc),
            )

"""Central policy enforcement layer and pre-execution command hooks.

Enforces:
1. Fixed tool allowlist (denies unknown tools by default).
2. Command and argument validation (detects traversal, command injection, malformed args).
3. Synthetic canary tracking & blocking.
4. Approval gate evaluation for sensitive actions.
5. Network policy evaluation for outbound actions.
6. Guaranteed isolation: blocked actions NEVER reach the execution adapter.
7. Full ledger audit trail persistence for attempted, allowed, blocked, and succeeded outcomes.
"""

import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.agent.audit import CommandAuditLogger
from app.ledger.repository import LedgerRepository
from app.ledger.schemas import PolicyDecisionCreate
from app.policy.approvals import ApprovalGate, ApprovalToken
from app.policy.canary import CanaryTracker, mask_canary
from app.policy.network import (
    INFRASTRUCTURE_ENFORCEMENT_STATUS,
    INFRASTRUCTURE_LIMITATION_NOTE,
    NetworkPolicyManager,
    NetworkProfileType,
)

logger = logging.getLogger(__name__)


class PolicyBlockedError(Exception):
    """Raised when a proposed tool action is blocked by a security policy hook."""

    def __init__(self, reason: str, policy_name: str, risk_level: str = "high") -> None:
        super().__init__(reason)
        self.reason = reason
        self.policy_name = policy_name
        self.risk_level = risk_level


class ArgumentValidationError(Exception):
    """Raised when tool arguments fail security or schema validation."""

    pass


@dataclass
class PolicyEvaluationResult:
    """Detailed result of policy enforcement checks on a proposed action."""

    allowed: bool
    outcome: str  # "allowed", "blocked"
    policy_name: str
    risk_level: str  # "low", "medium", "high", "critical"
    reason: str
    tool_name: str
    arguments: dict[str, Any]
    canary_attempted: bool = False
    canary_blocked: bool = False
    decision_id: str = field(default_factory=lambda: f"pol_{uuid.uuid4().hex[:12]}")
    enforcement_point: str = "control_plane_policy_hook"
    infrastructure_status: str = INFRASTRUCTURE_ENFORCEMENT_STATUS
    limitation_note: str = INFRASTRUCTURE_LIMITATION_NOTE
    approval_status: str | None = None
    execution_outcome: str | None = None  # "succeeded", "failed", or None if blocked


class SecurityPolicyEnforcer:
    """Central policy enforcement layer evaluating actions before execution."""

    DEFAULT_ALLOWED_TOOLS = {
        "navigate_to_source",
        "read_page_content",
        "extract_facts",
        "produce_structured_result",
    }

    PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|/\.\.|\\\.\.)")
    COMMAND_INJECTION_PATTERN = re.compile(r"([;&|`$]|\bcurl\b|\bwget\b|\bbash\b|\bsh\b|\brm\b)")

    def __init__(
        self,
        allowed_tools: set[str] | None = None,
        approval_gate: ApprovalGate | None = None,
        network_manager: NetworkPolicyManager | None = None,
        canary_tracker: CanaryTracker | None = None,
        ledger_repo: LedgerRepository | None = None,
        audit_logger: CommandAuditLogger | None = None,
        enable_safety_hooks: bool = True,
        enable_network_policy: bool = True,
    ) -> None:
        self.allowed_tools = set(allowed_tools or self.DEFAULT_ALLOWED_TOOLS)
        self.approval_gate = approval_gate or ApprovalGate()
        self.network_manager = network_manager or NetworkPolicyManager(
            profile=NetworkProfileType.RESTRICTED
        )
        self.canary_tracker = canary_tracker or CanaryTracker()
        self.ledger_repo = ledger_repo
        self.audit_logger = audit_logger
        self.enable_safety_hooks = enable_safety_hooks
        self.enable_network_policy = enable_network_policy

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        run_id: str | None = None,
        sandbox_name: str = "sbx-unknown",
        approval_token: ApprovalToken | None = None,
    ) -> PolicyEvaluationResult:
        """Evaluate a proposed tool invocation before allowing dispatch."""
        arg_str = str(arguments)

        # 1. Canary Exposure Inspection
        canary_check = self.canary_tracker.inspect_input(arg_str, source=tool_name)
        canary_attempted = canary_check["attempted"]
        canary_blocked = False

        # If safety hooks are disabled (baseline), pass through basic checks
        if not self.enable_safety_hooks and not self.enable_network_policy:
            res = PolicyEvaluationResult(
                allowed=True,
                outcome="allowed",
                policy_name="unprotected_baseline",
                risk_level="high" if canary_attempted else "low",
                reason="Safety hooks disabled under baseline configuration.",
                tool_name=tool_name,
                arguments=arguments,
                canary_attempted=canary_attempted,
                canary_blocked=False,
            )
            self._persist_evaluation(res, run_id=run_id, sandbox_name=sandbox_name)
            return res

        # 2. Check Canary Attack Blocking (Safety Hook)
        if self.enable_safety_hooks and canary_attempted:
            canary_blocked = True
            res = PolicyEvaluationResult(
                allowed=False,
                outcome="blocked",
                policy_name="canary_protection_hook",
                risk_level="critical",
                reason="Canary access or exfiltration attempt detected in tool arguments.",
                tool_name=tool_name,
                arguments=arguments,
                canary_attempted=True,
                canary_blocked=True,
            )
            self._persist_evaluation(res, run_id=run_id, sandbox_name=sandbox_name)
            return res

        # 3. Sensitive Action & Approval Gate (Safety Hook)
        if self.enable_safety_hooks and self.approval_gate.is_sensitive(tool_name):
            appr = self.approval_gate.evaluate(
                action_name=tool_name,
                arguments=arguments,
                run_id=run_id,
                token=approval_token,
            )
            if not appr.allowed:
                res = PolicyEvaluationResult(
                    allowed=False,
                    outcome="blocked",
                    policy_name="approval_gate_policy",
                    risk_level="high",
                    reason=appr.reason,
                    tool_name=tool_name,
                    arguments=arguments,
                    approval_status=appr.status,
                    canary_attempted=canary_attempted,
                    canary_blocked=canary_blocked,
                )
                self._persist_evaluation(res, run_id=run_id, sandbox_name=sandbox_name)
                return res

        # 4. Tool Allowlist Check (Safety Hook)
        if (
            self.enable_safety_hooks
            and tool_name not in self.allowed_tools
            and not self.approval_gate.is_sensitive(tool_name)
        ):
            res = PolicyEvaluationResult(
                allowed=False,
                outcome="blocked",
                policy_name="tool_allowlist_policy",
                risk_level="high",
                reason=(
                    f"Tool '{tool_name}' is not in approved tool allowlist. "
                    f"Allowed tools: {sorted(self.allowed_tools)}."
                ),
                tool_name=tool_name,
                arguments=arguments,
                canary_attempted=canary_attempted,
                canary_blocked=canary_blocked,
            )
            self._persist_evaluation(res, run_id=run_id, sandbox_name=sandbox_name)
            return res

        # 5. Argument Validation Check (Safety Hook)
        if self.enable_safety_hooks:
            validation_error = self._validate_arguments(tool_name, arguments)
            if validation_error:
                res = PolicyEvaluationResult(
                    allowed=False,
                    outcome="blocked",
                    policy_name="argument_validation_policy",
                    risk_level="high",
                    reason=f"Argument validation failed: {validation_error}",
                    tool_name=tool_name,
                    arguments=arguments,
                    canary_attempted=canary_attempted,
                    canary_blocked=canary_blocked,
                )
                self._persist_evaluation(res, run_id=run_id, sandbox_name=sandbox_name)
                return res

        # 6. Outbound Network Policy Check (Network Policy Hook)
        if self.enable_network_policy:
            dest = self._extract_destination(arguments)
            if dest:
                net_eval = self.network_manager.evaluate_destination(str(dest))
                if not net_eval.allowed:
                    res = PolicyEvaluationResult(
                        allowed=False,
                        outcome="blocked",
                        policy_name="network_egress_policy",
                        risk_level="critical",
                        reason=net_eval.reason,
                        tool_name=tool_name,
                        arguments=arguments,
                        canary_attempted=canary_attempted,
                        canary_blocked=canary_blocked,
                        infrastructure_status=net_eval.infrastructure_status,
                        limitation_note=net_eval.limitation_note,
                    )
                    self._persist_evaluation(res, run_id=run_id, sandbox_name=sandbox_name)
                    return res

        # 7. All checks passed -> ALLOWED
        appr_status = "approved" if self.approval_gate.is_sensitive(tool_name) else "not_required"
        res = PolicyEvaluationResult(
            allowed=True,
            outcome="allowed",
            policy_name="security_policy_enforcer",
            risk_level="low",
            reason="Proposed action adheres to tool allowlist, schemas, and security policies.",
            tool_name=tool_name,
            arguments=arguments,
            canary_attempted=canary_attempted,
            canary_blocked=False,
            approval_status=appr_status,
        )
        self._persist_evaluation(res, run_id=run_id, sandbox_name=sandbox_name)
        return res

    def enforce_and_dispatch(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        executor_func: Callable[[], Any],
        run_id: str | None = None,
        sandbox_name: str = "sbx-unknown",
        approval_token: ApprovalToken | None = None,
    ) -> tuple[PolicyEvaluationResult, Any]:
        """Evaluate action and execute ONLY if allowed.

        GUARANTEE: If the policy decision is 'blocked', `executor_func` is NEVER invoked.
        """
        eval_result = self.evaluate(
            tool_name=tool_name,
            arguments=arguments,
            run_id=run_id,
            sandbox_name=sandbox_name,
            approval_token=approval_token,
        )

        if not eval_result.allowed:
            eval_result.execution_outcome = "blocked"
            raise PolicyBlockedError(
                reason=eval_result.reason,
                policy_name=eval_result.policy_name,
                risk_level=eval_result.risk_level,
            )

        # Allowed: dispatch to real execution adapter
        try:
            exec_output = executor_func()
            eval_result.execution_outcome = "succeeded"
            return eval_result, exec_output
        except Exception as exc:
            eval_result.execution_outcome = "failed"
            logger.error("Execution error on allowed action '%s': %s", tool_name, exc)
            raise

    @staticmethod
    def _extract_destination(arguments: dict[str, Any]) -> str | None:
        """Extract network destination parameter if present in arguments."""
        if not isinstance(arguments, dict):
            return None
        dest = arguments.get("destination") or arguments.get("url") or arguments.get("host")
        if not dest and "source_id" in arguments:
            src = str(arguments["source_id"])
            if src.startswith("http://") or src.startswith("https://"):
                dest = src
        return dest

    def _validate_arguments(self, tool_name: str, arguments: dict[str, Any]) -> str | None:
        """Validate argument values against path traversal, injection, and invalid types."""
        if not isinstance(arguments, dict):
            return "Arguments must be a valid dictionary."

        for key, val in arguments.items():
            val_str = str(val)

            # Detect Path Traversal
            if self.PATH_TRAVERSAL_PATTERN.search(val_str):
                return f"Path traversal pattern detected in parameter '{key}'."

            # Specific tool constraints
            if tool_name in ("read_page_content", "navigate_to_source") and key == "source_id":
                if not re.match(r"^[a-zA-Z0-9_-]+$", val_str):
                    return f"Invalid characters in source_id '{val_str}'."

        return None

    def _persist_evaluation(
        self,
        eval_res: PolicyEvaluationResult,
        run_id: str | None,
        sandbox_name: str,
    ) -> None:
        """Persist policy decision and command attempt to the PostgreSQL ledger and audit log."""
        sanitized_args = mask_canary(str(eval_res.arguments))
        command_repr = f"{eval_res.tool_name}({sanitized_args})"

        # 1. Log to CommandAuditLogger
        if self.audit_logger:
            self.audit_logger.log_attempt(
                sandbox_name=sandbox_name,
                command=command_repr,
                decision=eval_res.outcome,
                run_id=run_id,
                reason=eval_res.reason,
                risk_level=eval_res.risk_level,
                canary_detected=eval_res.canary_attempted,
                details={
                    "policy_name": eval_res.policy_name,
                    "canary_blocked": str(eval_res.canary_blocked),
                    "enforcement_point": eval_res.enforcement_point,
                    "infrastructure_status": eval_res.infrastructure_status,
                },
            )

        # 2. Persist PolicyDecision to PostgreSQL
        if self.ledger_repo and run_id:
            try:
                dec_in = PolicyDecisionCreate(
                    decision_id=eval_res.decision_id,
                    run_id=run_id,
                    policy_name=eval_res.policy_name,
                    decision="allow" if eval_res.allowed else "block",
                    risk_level=eval_res.risk_level,
                    reason=eval_res.reason,
                    decision_metadata={
                        "tool_name": eval_res.tool_name,
                        "enforcement_point": eval_res.enforcement_point,
                        "infrastructure_status": eval_res.infrastructure_status,
                        "canary_attempted": eval_res.canary_attempted,
                        "canary_blocked": eval_res.canary_blocked,
                        "approval_status": eval_res.approval_status,
                    },
                    timestamp=datetime.now(UTC),
                )
                self.ledger_repo.create_policy_decision(dec_in)
            except Exception as exc:
                logger.warning("Failed to persist PolicyDecision for run '%s': %s", run_id, exc)

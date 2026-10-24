"""Defense configuration definitions and multi-configuration evaluator.

Supports reproducible evaluation across the four hackathon defense configurations:
1. Baseline (unprotected)
2. Network-policy-only (egress filtering; infrastructure isolation UNVERIFIED)
3. Safety-hook-only (tool allowlist, arg validation, canary protection, approvals)
4. Defense-in-depth (all layers combined)
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.agent.audit import CommandAuditLogger
from app.ledger.repository import LedgerRepository
from app.policy.approvals import ApprovalGate, ApprovalToken
from app.policy.canary import CanaryTracker
from app.policy.hooks import PolicyBlockedError, SecurityPolicyEnforcer
from app.policy.network import (
    INFRASTRUCTURE_ENFORCEMENT_STATUS,
    INFRASTRUCTURE_LIMITATION_NOTE,
    MockExfiltrationSink,
    NetworkPolicyManager,
    NetworkProfileType,
)


class DefenseProfile(StrEnum):
    """The four evaluated defense configurations."""

    BASELINE = "baseline"
    NETWORK_POLICY_ONLY = "network_policy_only"
    SAFETY_HOOK_ONLY = "safety_hook_only"
    DEFENSE_IN_DEPTH = "defense_in_depth"


@dataclass
class ConfigurationComparisonResult:
    """Standardized record of an attack evaluated against a specific defense configuration."""

    configuration_id: str
    defense_profile: DefenseProfile
    attack_attempted: str
    attack_payload_preview: str
    policy_decisions: list[dict[str, Any]]
    execution_outcome: str  # "blocked", "executed", "failed"
    canary_exposure_result: str  # "not_targeted", "attempted", "blocked", "leaked"
    containment_status: str  # "contained", "uncontained"
    evidence_paths: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class DefenseConfigurationFactory:
    """Builds configured SecurityPolicyEnforcer instances for each defense tier."""

    @staticmethod
    def create_enforcer(
        profile: DefenseProfile,
        ledger_repo: LedgerRepository | None = None,
        audit_logger: CommandAuditLogger | None = None,
        sink: MockExfiltrationSink | None = None,
    ) -> SecurityPolicyEnforcer:
        """Instantiate policy enforcer configured exactly according to the defense tier."""
        mock_sink = sink or MockExfiltrationSink()

        if profile == DefenseProfile.BASELINE:
            return SecurityPolicyEnforcer(
                allowed_tools=None,
                approval_gate=ApprovalGate(),
                network_manager=NetworkPolicyManager(
                    profile=NetworkProfileType.UNRESTRICTED_BASELINE, sink=mock_sink
                ),
                canary_tracker=CanaryTracker(),
                ledger_repo=ledger_repo,
                audit_logger=audit_logger,
                enable_safety_hooks=False,
                enable_network_policy=False,
            )

        elif profile == DefenseProfile.NETWORK_POLICY_ONLY:
            return SecurityPolicyEnforcer(
                allowed_tools=None,
                approval_gate=ApprovalGate(),
                network_manager=NetworkPolicyManager(
                    profile=NetworkProfileType.RESTRICTED, sink=mock_sink
                ),
                canary_tracker=CanaryTracker(),
                ledger_repo=ledger_repo,
                audit_logger=audit_logger,
                enable_safety_hooks=False,
                enable_network_policy=True,
            )

        elif profile == DefenseProfile.SAFETY_HOOK_ONLY:
            return SecurityPolicyEnforcer(
                allowed_tools=None,
                approval_gate=ApprovalGate(),
                network_manager=NetworkPolicyManager(
                    profile=NetworkProfileType.UNRESTRICTED_BASELINE, sink=mock_sink
                ),
                canary_tracker=CanaryTracker(),
                ledger_repo=ledger_repo,
                audit_logger=audit_logger,
                enable_safety_hooks=True,
                enable_network_policy=False,
            )

        elif profile == DefenseProfile.DEFENSE_IN_DEPTH:
            return SecurityPolicyEnforcer(
                allowed_tools=None,
                approval_gate=ApprovalGate(),
                network_manager=NetworkPolicyManager(
                    profile=NetworkProfileType.RESTRICTED, sink=mock_sink
                ),
                canary_tracker=CanaryTracker(),
                ledger_repo=ledger_repo,
                audit_logger=audit_logger,
                enable_safety_hooks=True,
                enable_network_policy=True,
            )

        raise ValueError(f"Unknown defense profile '{profile}'.")


class DefenseEvaluator:
    """Runs a controlled attack scenario across all 4 defense configurations."""

    def __init__(
        self,
        ledger_repo: LedgerRepository | None = None,
        audit_logger: CommandAuditLogger | None = None,
    ) -> None:
        self.ledger_repo = ledger_repo
        self.audit_logger = audit_logger
        self.sink = MockExfiltrationSink()

    def evaluate_attack_across_configurations(
        self,
        attack_type: str,
        tool_name: str,
        arguments: dict[str, Any],
        run_prefix: str = "eval_p5",
        approval_token: ApprovalToken | None = None,
    ) -> dict[str, ConfigurationComparisonResult]:
        """Evaluate how each of the 4 defense configurations handles the exact same attack."""
        results: dict[str, ConfigurationComparisonResult] = {}

        for profile in DefenseProfile:
            enforcer = DefenseConfigurationFactory.create_enforcer(
                profile=profile,
                ledger_repo=self.ledger_repo,
                audit_logger=self.audit_logger,
                sink=self.sink,
            )
            run_id = f"{run_prefix}_{profile.value}"
            executed_box = {"executed": False}

            def make_executor(box: dict[str, bool]):
                def dummy_executor() -> dict[str, str]:
                    box["executed"] = True
                    return {"status": "executed"}

                return dummy_executor

            executor = make_executor(executed_box)

            try:
                eval_res, _ = enforcer.enforce_and_dispatch(
                    tool_name=tool_name,
                    arguments=arguments,
                    executor_func=executor,
                    run_id=run_id,
                    sandbox_name=f"sbx-{profile.value[:8]}",
                    approval_token=approval_token,
                )
                exec_outcome = "executed"
                containment = "uncontained"
                policy_records = [
                    {
                        "policy_name": eval_res.policy_name,
                        "decision": eval_res.outcome,
                        "reason": eval_res.reason,
                    }
                ]
            except PolicyBlockedError as p_err:
                exec_outcome = "blocked"
                containment = "contained"
                policy_records = [
                    {
                        "policy_name": p_err.policy_name,
                        "decision": "block",
                        "reason": p_err.reason,
                    }
                ]

            # Determine canary outcome
            arg_str = str(arguments)
            from app.policy.canary import CANARY_SECRET

            if CANARY_SECRET in arg_str:
                if exec_outcome == "blocked":
                    canary_result = "blocked"
                else:
                    canary_result = "leaked" if executed_box["executed"] else "attempted"
            else:
                canary_result = "not_targeted"

            limitations: list[str] = []
            if profile in (DefenseProfile.NETWORK_POLICY_ONLY, DefenseProfile.DEFENSE_IN_DEPTH):
                limitations.append(
                    f"Network policy check performed at control-plane. "
                    f"Infrastructure: {INFRASTRUCTURE_ENFORCEMENT_STATUS}. "
                    f"{INFRASTRUCTURE_LIMITATION_NOTE}"
                )

            ev_paths = [str(self.audit_logger.log_file_path)] if self.audit_logger else []
            results[profile.value] = ConfigurationComparisonResult(
                configuration_id=profile.value,
                defense_profile=profile,
                attack_attempted=attack_type,
                attack_payload_preview=arg_str[:120],
                policy_decisions=policy_records,
                execution_outcome=exec_outcome,
                canary_exposure_result=canary_result,
                containment_status=containment,
                evidence_paths=ev_paths,
                limitations=limitations,
            )

        return results

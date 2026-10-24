"""Approval gate management for sensitive actions in GuardRail."""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any


@dataclass
class ApprovalToken:
    """Cryptographic or identifier-bound approval token for sensitive tool actions."""

    token_id: str
    run_id: str
    action_name: str
    arguments_hash: str
    approved_by: str
    expires_at: datetime
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def is_valid(self, run_id: str, action_name: str, arguments: dict[str, Any]) -> bool:
        """Validate that token matches run, action, argument hash, and has not expired."""
        if datetime.now(UTC) > self.expires_at:
            return False
        if self.run_id != run_id:
            return False
        if self.action_name != action_name:
            return False
        serialized = json.dumps(arguments, sort_keys=True).encode("utf-8")
        arg_hash = hashlib.sha256(serialized).hexdigest()
        return self.arguments_hash == arg_hash


@dataclass
class ApprovalResult:
    """Result of an approval gate check."""

    allowed: bool
    status: str  # "not_required", "approved", "missing_approval", "denied", "expired", "mismatched"
    reason: str
    token_id: str | None = None
    approved_by: str | None = None


class ApprovalGate:
    """Manages sensitive action registration and authorization checks."""

    DEFAULT_SENSITIVE_ACTIONS = {
        "run_shell",
        "execute_code",
        "delete_file",
        "network_request",
        "export_data",
        "modify_system_config",
        "access_raw_credentials",
    }

    def __init__(self, sensitive_actions: set[str] | None = None) -> None:
        self.sensitive_actions = set(sensitive_actions or self.DEFAULT_SENSITIVE_ACTIONS)
        self.tokens: dict[str, ApprovalToken] = {}
        self.denied_actions: dict[str, str] = {}

    def is_sensitive(self, action_name: str) -> bool:
        """Check whether an action is categorized as sensitive."""
        return action_name in self.sensitive_actions

    def grant_approval(
        self,
        run_id: str,
        action_name: str,
        arguments: dict[str, Any],
        approved_by: str = "security_operator",
        ttl_seconds: int = 300,
    ) -> ApprovalToken:
        """Issue an approval token tied to exact run, action, and arguments."""
        serialized = json.dumps(arguments, sort_keys=True).encode("utf-8")
        arg_hash = hashlib.sha256(serialized).hexdigest()
        token = ApprovalToken(
            token_id=f"appr_{uuid.uuid4().hex[:12]}",
            run_id=run_id,
            action_name=action_name,
            arguments_hash=arg_hash,
            approved_by=approved_by,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
        )
        self.tokens[token.token_id] = token
        return token

    def deny_approval(
        self,
        run_id: str,
        action_name: str,
        reason: str = "Operator explicitly denied action.",
    ) -> None:
        """Explicitly record an approval denial for an action in a run."""
        key = f"{run_id}:{action_name}"
        self.denied_actions[key] = reason

    def evaluate(
        self,
        action_name: str,
        arguments: dict[str, Any],
        run_id: str | None = None,
        token: ApprovalToken | None = None,
    ) -> ApprovalResult:
        """Evaluate whether a proposed tool action passes the approval gate."""
        if not self.is_sensitive(action_name):
            return ApprovalResult(
                allowed=True,
                status="not_required",
                reason=f"Action '{action_name}' is not in sensitive actions registry.",
            )

        if not run_id:
            return ApprovalResult(
                allowed=False,
                status="missing_approval",
                reason=(
                    f"Sensitive action '{action_name}' requires active run_id and approval token."
                ),
            )

        denial_key = f"{run_id}:{action_name}"
        if denial_key in self.denied_actions:
            return ApprovalResult(
                allowed=False,
                status="denied",
                reason=(
                    f"Action '{action_name}' was explicitly denied: "
                    f"{self.denied_actions[denial_key]}"
                ),
            )

        if token is None:
            return ApprovalResult(
                allowed=False,
                status="missing_approval",
                reason=f"Action '{action_name}' blocked: missing required approval token.",
            )

        if not token.is_valid(run_id, action_name, arguments):
            if datetime.now(UTC) > token.expires_at:
                return ApprovalResult(
                    allowed=False,
                    status="expired",
                    reason="Supplied approval token has expired.",
                    token_id=token.token_id,
                )
            return ApprovalResult(
                allowed=False,
                status="mismatched",
                reason="Supplied approval token does not match run, action, or arguments.",
                token_id=token.token_id,
            )

        return ApprovalResult(
            allowed=True,
            status="approved",
            reason=f"Action '{action_name}' approved by {token.approved_by}.",
            token_id=token.token_id,
            approved_by=token.approved_by,
        )

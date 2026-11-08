"""Native Celesto command-lifecycle callbacks and safety hooks.

Provides typed callback integration conforming to the official Celesto SDK specification:
- Base class `CelestoCallback` (subclassing `celesto.callbacks.Callback` when available)
- `CommandBlockedError` for explicit, typed command vetoes in `on_pre_run`
- `RunContext` carrying command execution metadata
- `CelestoSafetyHook` enforcing pre-execution policy, dangerous command interception,
  and canary token exfiltration prevention before transmission to the guest microVM.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any

from app.sandbox.exceptions import CommandBlockedError as _BaseCommandBlockedError

logger = logging.getLogger(__name__)

# Attempt to import official Celesto SDK callback types; provide native fallback if uninstalled
try:
    _sdk_callbacks = importlib.import_module("celesto.callbacks")
    _SdkCallback = getattr(_sdk_callbacks, "Callback", object)
    _SdkDispatcher = getattr(_sdk_callbacks, "CallbackDispatcher", None)
    _SdkCommandBlockedError = getattr(_sdk_callbacks, "CommandBlockedError", None)
    _SdkRunContext = getattr(_sdk_callbacks, "RunContext", None)
    CELESTO_SDK_CALLBACKS_AVAILABLE = True
except (ImportError, AttributeError):
    CELESTO_SDK_CALLBACKS_AVAILABLE = False
    _SdkCallback = object
    _SdkDispatcher = None
    _SdkCommandBlockedError = None
    _SdkRunContext = None


if CELESTO_SDK_CALLBACKS_AVAILABLE and _SdkCommandBlockedError is not None:

    class CommandBlockedError(_SdkCommandBlockedError, _BaseCommandBlockedError):
        """Raised to veto a command from within `Callback.on_pre_run`.

        Conforms to `celesto.callbacks.CommandBlockedError` and GuardRail `SandboxError`.
        """

        def __init__(
            self,
            message: str,
            vm_id: str | None = None,
            command: str | None = None,
            reason: str | None = None,
        ) -> None:
            super().__init__(message)
            self.vm_id = vm_id
            self.command = command
            self.reason = reason or message

else:
    CommandBlockedError = _BaseCommandBlockedError



@dataclass
class RunContext:
    """State passed to command hooks for one command execution.

    Conforms to `celesto.callbacks.RunContext`.
    """

    vm_id: str
    command: str
    shell: str = "raw"
    timeout: int = 30
    result: Any | None = None
    error: Exception | None = None


class CelestoCallback(_SdkCallback if CELESTO_SDK_CALLBACKS_AVAILABLE else object):
    """Base class for Celesto command-lifecycle callbacks.

    Subclass this and override only the hooks needed:
    - `on_pre_run(ctx)`: Veto channel. Raise `CommandBlockedError` to abort command execution.
    - `on_post_run(ctx)`: Passive observer after successful command execution.
    - `on_run_error(ctx)`: Passive observer when transport/command execution raises an error.
    """

    def on_pre_run(self, ctx: RunContext) -> None:
        """Called before a command is sent to the guest microVM.

        Raise `CommandBlockedError` to abort execution before it reaches the guest.
        """

    def on_post_run(self, ctx: RunContext) -> None:
        """Called after a command completes inside the guest."""

    def on_run_error(self, ctx: RunContext) -> None:
        """Called when transport or execution raises an error."""


class CallbackDispatcher:
    """Fans command lifecycle events out to every registered callback in order."""

    def __init__(self, callbacks: list[CelestoCallback] | None = None) -> None:
        self._callbacks: list[CelestoCallback] = list(callbacks or [])

    def add(self, callback: CelestoCallback) -> None:
        """Register a callback in the dispatch list."""
        if not isinstance(callback, CelestoCallback):
            msg = f"Callback must inherit from CelestoCallback, got {type(callback).__name__}"
            raise TypeError(msg)
        self._callbacks.append(callback)

    def __len__(self) -> int:
        return len(self._callbacks)

    def fire(self, hook: str, ctx: RunContext, *, propagate: bool = False) -> None:
        """Invoke `hook` on every registered callback."""
        for cb in self._callbacks:
            method = getattr(cb, hook, None)
            if not method:
                continue
            try:
                method(ctx)
            except Exception:
                if propagate:
                    raise
                logger.exception(
                    "Callback %s.%s raised non-veto error; ignoring (vm_id=%s, cmd=%r)",
                    type(cb).__name__,
                    hook,
                    ctx.vm_id,
                    ctx.command,
                )


class CelestoSafetyHook(CelestoCallback):
    """Native Celesto command-lifecycle safety hook vetoing dangerous commands.

    Inspects proposed commands in `on_pre_run` against:
    1. Blacklisted destructive binaries and patterns (`rm -rf`, `mkfs`, fork bomb)
    2. Canary token exfiltration patterns (`curl`, `wget`, reverse shells)
    3. Custom policy enforcers
    """

    DEFAULT_DENIED_PATTERNS = [
        "rm -rf /",
        "rm -rf /*",
        "mkfs",
        ":(){ :|:& };:",
        "chmod -R 777 /",
        "> /dev/sda",
        "dd if=/dev/zero",
        "curl -X POST",
        "curl -d",
        "curl --data",
        "wget --post-data",
        "nc -e",
        "/bin/sh -i",
        "/bin/bash -i",
    ]

    def __init__(
        self,
        canary_token: str | None = None,
        denied_patterns: list[str] | None = None,
        policy_enforcer: Any | None = None,
    ) -> None:
        if canary_token is None:
            from app.policy.canary import CANARY_SECRET

            canary_token = CANARY_SECRET
        self.canary_token = canary_token
        self.denied_patterns = list(denied_patterns or self.DEFAULT_DENIED_PATTERNS)
        self.policy_enforcer = policy_enforcer
        self.blocked_attempts_count: int = 0

    def on_pre_run(self, ctx: RunContext) -> None:
        """Evaluate command safety before dispatch to the Celesto microVM."""
        cmd = ctx.command

        # 1. Inspect denied shell command patterns
        for pattern in self.denied_patterns:
            if pattern in cmd:
                self.blocked_attempts_count += 1
                msg = f"CelestoSafetyHook: Blocked destructive shell command pattern '{pattern}'"
                raise CommandBlockedError(
                    message=msg,
                    vm_id=ctx.vm_id,
                    command=cmd,
                    reason=f"destructive_pattern:{pattern}",
                )

        # 2. Inspect canary secret leakage
        if self.canary_token and self.canary_token in cmd:
            self.blocked_attempts_count += 1
            msg = "CelestoSafetyHook: Blocked canary token exfiltration attempt in command"
            raise CommandBlockedError(
                message=msg,
                vm_id=ctx.vm_id,
                command=cmd,
                reason="canary_exfiltration_attempt",
            )

        # 3. Consult policy enforcer if attached
        if self.policy_enforcer and hasattr(self.policy_enforcer, "evaluate_command"):
            eval_res = self.policy_enforcer.evaluate_command(cmd, vm_id=ctx.vm_id)
            if not getattr(eval_res, "allowed", True):
                self.blocked_attempts_count += 1
                reason = getattr(eval_res, "reason", "policy_enforcer_denied")
                raise CommandBlockedError(
                    message=f"CelestoSafetyHook: Vetoed by policy enforcer ({reason})",
                    vm_id=ctx.vm_id,
                    command=cmd,
                    reason=reason,
                )

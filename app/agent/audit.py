"""Structured audit logging to logs/commands.jsonl and PostgreSQL ledger integration."""

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.agent.schemas import CANARY_SECRET, utcnow_iso
from app.ledger.repository import LedgerRepository
from app.ledger.schemas import CommandAttemptCreate, EventCreate
from app.sandbox.client import sanitize_text

logger = logging.getLogger(__name__)


class CommandAuditLogger:
    """Manages appending command attempts to logs/commands.jsonl and PostgreSQL ledger."""

    def __init__(
        self,
        log_file_path: Path | None = None,
        ledger_repo: LedgerRepository | None = None,
    ) -> None:
        self.log_file_path = log_file_path or (
            Path(__file__).resolve().parent.parent.parent / "logs" / "commands.jsonl"
        )
        self.ledger_repo = ledger_repo

    def log_attempt(
        self,
        sandbox_name: str,
        command: str,
        decision: str = "allow",
        execution_target: str = "celesto_sandbox",
        run_id: str | None = None,
        reason: str | None = None,
        risk_level: str = "low",
        canary_detected: bool = False,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record command attempt to JSONL audit log and PostgreSQL ledger.

        Adheres strictly to Graded Contract 4:
        {"ts": str, "sandbox_name": str, "command": str,
         "decision": str, "execution_target": "celesto_sandbox"}
        """
        # 1. Sanitize text and detect synthetic canary access
        sanitized_command = sanitize_text(command)
        if CANARY_SECRET in command:
            canary_detected = True
            # Never write raw canary secret into log files
            sanitized_command = sanitized_command.replace(CANARY_SECRET, "[PROTECTED_CANARY_TOKEN]")

        entry = {
            "ts": utcnow_iso(),
            "sandbox_name": sandbox_name,
            "command": sanitized_command,
            "decision": decision,
            "execution_target": execution_target,
        }

        # 2. Append to logs/commands.jsonl
        try:
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as exc:
            logger.error("Failed to write audit record to %s: %s", self.log_file_path, exc)

        # 3. Persist to PostgreSQL ledger if available
        if self.ledger_repo and run_id:
            try:
                attempt_in = CommandAttemptCreate(
                    attempt_id=f"att_{uuid.uuid4().hex[:12]}",
                    run_id=run_id,
                    command=sanitized_command,
                    decision=decision if decision in ("allow", "block") else "allow",
                    reason=reason or f"Research agent tool call ({decision})",
                    risk_level=risk_level
                    if risk_level in ("low", "medium", "high", "critical")
                    else "low",
                    execution_target=execution_target,
                    canary_detected=canary_detected,
                    timestamp=datetime.now(UTC),
                )
                self.ledger_repo.create_command_attempt(attempt_in)
            except Exception as exc:
                logger.warning(
                    "Ledger degradation: failed to persist command attempt for run '%s': %s",
                    run_id,
                    exc,
                )

            # Also log as lifecycle event
            try:
                event_in = EventCreate(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    run_id=run_id,
                    event_type=f"agent.tool_attempt.{decision}",
                    details={
                        "sandbox_name": sandbox_name,
                        "command": sanitized_command,
                        "decision": decision,
                        "canary_detected": str(canary_detected),
                        **(details or {}),
                    },
                    timestamp=datetime.now(UTC),
                )
                self.ledger_repo.create_event(event_in)
            except Exception as exc:
                logger.warning("Ledger degradation: failed to persist event: %s", exc)

        return entry

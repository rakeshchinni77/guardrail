"""One-time execution script to dispatch a custom command to existing Celesto microVM.

Demonstrates genuine GuardRail-to-Celesto execution through SandboxLifecycleManager.
Target Computer ID: cmp_4de160c7ee57
Sandbox Name: sbx-watsoneiago
Target Command: echo "Hello from GuardRail" > /tmp/hello.txt
"""

from __future__ import annotations

import logging
import sys
import time
import uuid
from pathlib import Path

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from sqlalchemy.orm import Session  # noqa: E402

from app.agent.audit import CommandAuditLogger  # noqa: E402
from app.agent.schemas import CANARY_SECRET  # noqa: E402
from app.ledger.database import get_engine  # noqa: E402
from app.ledger.repository import LedgerRepository  # noqa: E402
from app.ledger.schemas import RunCreate  # noqa: E402
from app.sandbox.callbacks import (  # noqa: E402
    CelestoSafetyHook,
    CommandBlockedError,
)
from app.sandbox.client import CelestoCLIClient  # noqa: E402
from app.sandbox.manager import SandboxLifecycleManager  # noqa: E402
from app.sandbox.types import SandboxHandle  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("custom_command_execution")

COMPUTER_ID = "cmp_4de160c7ee57"
SANDBOX_NAME = "sbx-watsoneiago"
TARGET_COMMAND = 'echo "Hello from GuardRail" > /tmp/hello.txt'


def main() -> None:
    print(f"\n{'=' * 75}")
    print("  GUARDRAIL CUSTOM COMMAND EXECUTION -> CELESTO MICROVM")
    print(f"{'=' * 75}\n")

    # 1. Connect to PostgreSQL Ledger (graceful fallback if offline)
    repo: LedgerRepository | None = None
    try:
        db_url = "postgresql://ledger:ledger@localhost:5432/ledger"
        engine = get_engine(db_url)
        session = Session(engine)
        repo = LedgerRepository(session)
        print(f"[1/5] Connected to PostgreSQL ledger at {db_url}")
    except Exception as db_err:
        print(f"[1/5] PostgreSQL ledger offline ({db_err}). Using file audit logging.")

    # 2. Initialize Celesto Client & Verify Existing MicroVM
    client = CelestoCLIClient()
    print(f"[2/5] Initialized CelestoCLIClient (Command prefix: {client._command_prefix})")
    print(f"      Probing existing computer metadata for {COMPUTER_ID}...")

    t0_probe = time.perf_counter()
    computer_meta = client.get_computer(COMPUTER_ID)
    probe_latency_s = round(time.perf_counter() - t0_probe, 3)

    comp_status = computer_meta.get("status")
    comp_name = computer_meta.get("name")
    vcpus = computer_meta.get("vcpus")
    ram_mb = computer_meta.get("ram_mb")

    print(f"      [OK] Computer '{COMPUTER_ID}' verified:")
    print(f"           - Celesto Name: {comp_name}")
    print(f"           - Status:       {comp_status}")
    print(f"           - vCPUs / RAM:  {vcpus} vCPU / {ram_mb} MB")
    print(f"           - Probe Latency: {probe_latency_s}s")

    if comp_status != "running":
        print(f"\n[ERROR] Computer {COMPUTER_ID} is in '{comp_status}' state. Aborting.")
        sys.exit(1)

    # 3. Setup GuardRail Lifecycle Manager, Safety Hook & Audit Logger
    safety_hook = CelestoSafetyHook(canary_token=CANARY_SECRET)
    manager = SandboxLifecycleManager(
        client=client,
        ledger_repo=repo,
        callbacks=[safety_hook],
    )
    audit_logger = CommandAuditLogger(ledger_repo=repo)

    run_id = f"run_custom_{uuid.uuid4().hex[:8]}"
    if repo:
        try:
            repo.create_run(
                RunCreate(
                    run_id=run_id,
                    problem_id="custom_command_execution",
                    defense_profile="defense_in_depth",
                    execution_target="celesto_sandbox",
                )
            )
            print(f"[3/5] Registered run in ledger: {run_id}")
        except Exception as exc:
            print(f"[3/5] Notice: Could not register run in ledger ({exc}). Proceeding.")
    else:
        print(f"[3/5] Using run ID: {run_id}")

    # 4. Construct SandboxHandle for existing Celesto Computer
    handle = SandboxHandle(
        sandbox_name=SANDBOX_NAME,
        provider_id=COMPUTER_ID,
        provider="cloud",
        state="running",
        metadata={
            "celesto_computer_id": COMPUTER_ID,
            "celesto_name": comp_name,
            "attached_existing": True,
        },
    )

    # 5. Execute Command with Safety Guardrails
    print("\n[4/5] SUBMITTING COMMAND VIA SandboxLifecycleManager.execute_command()...")
    print(f"      Target Sandbox Name: {handle.sandbox_name}")
    print(f"      Target Computer ID:  {handle.provider_id}")
    print(f"      Target Command:      {TARGET_COMMAND}")

    t0_cmd = time.perf_counter()
    try:
        # Pre-execution safety hooks evaluate in manager.execute_command() before dispatch
        result = manager.execute_command(
            handle=handle,
            command=TARGET_COMMAND,
            timeout=30,
            run_id=run_id,
        )
        cmd_latency_s = round(time.perf_counter() - t0_cmd, 3)

        # Record ALLOW ONLY after successful execution
        audit_entry = audit_logger.log_attempt(
            sandbox_name=handle.sandbox_name,
            command=TARGET_COMMAND,
            decision="allow",
            execution_target="celesto_sandbox",
            run_id=run_id,
            reason="Passed safety callback and executed successfully in Celesto sandbox",
        )

        print("\n[5/5] EXECUTION COMPLETED SUCCESSFULLY!")
        print("      --------------------------------------------------")
        print(f"      Exit Code:          {result.exit_code}")
        print(f"      Execution Duration: {result.duration_ms} ms (Round-trip: {cmd_latency_s}s)")
        print(f"      Stdout:             {repr(result.stdout)}")
        print(f"      Stderr:             {repr(result.stderr)}")
        print(f"      Timed Out:          {result.timed_out}")
        print(f"      Execution Target:   {result.execution_target}")
        print(f"      Audit Log Decision: {audit_entry.get('decision')} -> logs/commands.jsonl")
        print("      --------------------------------------------------")
        print(f"\nResult: File /tmp/hello.txt has been created inside microVM {COMPUTER_ID}.")

    except CommandBlockedError as veto_err:
        # Record BLOCK ONLY when CommandBlockedError is raised by safety hooks
        audit_entry = audit_logger.log_attempt(
            sandbox_name=handle.sandbox_name,
            command=TARGET_COMMAND,
            decision="block",
            execution_target="celesto_sandbox",
            run_id=run_id,
            reason=getattr(veto_err, "reason", str(veto_err)),
        )
        print("\n[VETOED] Command was BLOCKED by CelestoSafetyHook prior to provider dispatch:")
        print(f"         Reason: {veto_err}")
        print(f"         Audit Log Decision: {audit_entry.get('decision')} -> logs/commands.jsonl")
        sys.exit(1)

    except Exception as exc:
        # Provider or connection failures must NOT be mislabeled as safety blocks
        print("\n[SYSTEM ERROR] Provider or transport failure occurred (NOT a safety block):")
        print(f"               Error: {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()

"""Opt-in real Celesto Cloud integration test for Phase 3 acceptance gate.

This test provisions ONE real microVM on Celesto Cloud, probes readiness,
executes a deterministic synthetic marker command, asserts guest execution,
and teardowns the resource with verified deletion.

SAFETY & COST NOTICE:
- Skipped by default. Requires explicit environment variable: RUN_CELESTO_CLOUD_TEST=1.
- Consumes minimal cloud credits (1 ephemeral microVM for ~30 seconds, ~$0.0002).
- Executes only harmless shell commands (echo test marker). No arbitrary scripts.
"""

import json
import os
import time
import uuid
from pathlib import Path

import pytest

from app.sandbox import (
    CelestoCLIClient,
    SandboxLifecycleManager,
    generate_sandbox_name,
)

RUN_CLOUD_TEST = os.environ.get("RUN_CELESTO_CLOUD_TEST", "0").strip().lower() in ("1", "true")
RESULT_FILE_PATH = Path(__file__).parent / "celesto_integration_result.json"


@pytest.mark.celesto_cloud
@pytest.mark.skipif(
    not RUN_CLOUD_TEST,
    reason="Celesto Cloud integration test is opt-in. Set RUN_CELESTO_CLOUD_TEST=1 to execute.",
)
def test_real_celesto_cloud_lifecycle_verification():
    """Verify real Celesto Cloud computer provisioning, execution, and teardown."""
    test_id = f"test_cloud_{uuid.uuid4().hex[:8]}"
    sandbox_name = generate_sandbox_name()
    test_marker = f"GUARDRAIL_PHASE3_READY_{uuid.uuid4().hex[:10]}"

    telemetry = {
        "test_id": test_id,
        "sandbox_name": sandbox_name,
        "test_marker": test_marker,
        "provider": "cloud",
        "created_at": None,
        "provider_id": None,
        "readiness_duration_s": None,
        "command_duration_ms": None,
        "guest_exit_code": None,
        "guest_stdout": None,
        "guest_stderr": None,
        "deletion_success": False,
        "verified_absent": False,
        "cleanup_error": None,
        "overall_status": "in_progress",
    }

    client = CelestoCLIClient()
    manager = SandboxLifecycleManager(client=client)
    handle = None

    try:
        # 1. Create real cloud computer
        handle = manager.create_sandbox(name=sandbox_name, boot_timeout=90.0)
        telemetry["created_at"] = time.time()
        telemetry["provider_id"] = handle.provider_id
        assert handle.provider_id.startswith("cmp_"), f"Unexpected ID: {handle.provider_id}"

        # 2. Inspect computer status via get
        info = client.get_computer(handle.provider_id)
        assert info.get("computer_id") == handle.provider_id

        # 3. Wait for readiness probe
        probe_res = manager.wait_until_ready(handle, timeout=60.0, poll_interval=2.0)
        assert probe_res.ready is True
        telemetry["readiness_duration_s"] = probe_res.boot_to_ready_s

        # 4. Execute harmless deterministic marker command
        cmd_string = f"echo '{test_marker}'"
        cmd_res = manager.execute_command(handle, cmd_string, timeout=30)
        telemetry["guest_exit_code"] = cmd_res.exit_code
        telemetry["guest_stdout"] = cmd_res.stdout.strip()
        telemetry["guest_stderr"] = cmd_res.stderr.strip()
        telemetry["command_duration_ms"] = cmd_res.duration_ms

        assert cmd_res.exit_code == 0, f"Command failed: {cmd_res.stderr}"
        assert test_marker in cmd_res.stdout, "Test marker missing from guest output!"
        assert cmd_res.execution_target == "celesto_sandbox"

        # Check guest OS release to confirm guest environment
        os_res = manager.execute_command(handle, "cat /etc/os-release", timeout=15)
        assert "Ubuntu" in os_res.stdout

        telemetry["overall_status"] = "passed"

    except Exception as exc:
        telemetry["overall_status"] = "failed"
        telemetry["error"] = str(exc)
        raise

    finally:
        # 5. Guaranteed cleanup path
        if handle and handle.provider_id:
            try:
                del_res = manager.cleanup(handle)
                telemetry["deletion_success"] = del_res.success
                telemetry["verified_absent"] = del_res.verified_absent
            except Exception as clean_exc:
                telemetry["deletion_success"] = False
                telemetry["cleanup_error"] = str(clean_exc)

            # Persist machine-readable integration telemetry report
            try:
                with open(RESULT_FILE_PATH, "w", encoding="utf-8") as f:
                    json.dump(telemetry, f, indent=2)
            except Exception:
                pass

            active = client.list_computers(limit=50)
            active_ids = {c.get("computer_id") for c in active}
            assert handle.provider_id not in active_ids, (
                f"Resource leak: {handle.provider_id} still listed in active computers! "
                f"Manual cleanup command: celesto computer delete --cloud {handle.provider_id}"
            )

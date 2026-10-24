"""Celesto client abstraction, CLI wrapper, and test fakes for microVM lifecycle management."""

import base64
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Any

from app.config import Settings, get_settings
from app.sandbox.exceptions import (
    CelestoUnavailableError,
    GuestCommandExecutionError,
    GuestCommandTimeoutError,
    SandboxCleanupError,
    SandboxCreationError,
)

logger = logging.getLogger(__name__)

# Pattern to mask sensitive API tokens in error messages
SECRET_PATTERN = re.compile(r"(celesto_[a-zA-Z0-9_-]{8,}|key-[a-zA-Z0-9_-]{8,}|[0-9a-f]{32,})")


def sanitize_text(text: str) -> str:
    """Mask potential API keys and secrets in strings."""
    if not text:
        return ""
    return SECRET_PATTERN.sub("[REDACTED_SECRET]", text)


class CelestoClientInterface(ABC):
    """Abstract interface defining required verified Celesto operations."""

    @abstractmethod
    def create_computer(
        self, name: str | None = None, boot_timeout: float = 60.0
    ) -> dict[str, Any]:
        """Create a new Celesto cloud computer."""
        pass

    @abstractmethod
    def get_computer(self, computer_id: str) -> dict[str, Any]:
        """Retrieve status and metadata for a specific computer."""
        pass

    @abstractmethod
    def list_computers(self, limit: int = 50) -> list[dict[str, Any]]:
        """List active Celesto computers."""
        pass

    @abstractmethod
    def run_command(self, computer_id: str, command: str, timeout: int = 30) -> dict[str, Any]:
        """Execute a shell command inside the guest computer."""
        pass

    @abstractmethod
    def delete_computer(self, computer_id: str) -> dict[str, Any]:
        """Delete a Celesto computer."""
        pass


class CelestoCLIClient(CelestoClientInterface):
    """Production client invoking verified Celesto CLI operations with strict isolation."""

    def __init__(
        self,
        settings: Settings | None = None,
        cli_path: str | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.cli_path = cli_path or self.settings.celesto_cli_path
        self._command_prefix = self._resolve_cli_prefix()

    def _resolve_cli_prefix(self) -> list[str]:
        """Determine command prefix for invoking Celesto CLI on current platform."""
        if self.cli_path:
            return [self.cli_path]

        # Check native PATH
        native_which = shutil.which("celesto")
        if native_which:
            return [native_which]

        # On Windows host, check WSL Ubuntu environment where Celesto is installed
        if sys.platform == "win32":
            wsl_which = shutil.which("wsl")
            if wsl_which:
                wsl_venv_celesto = "/home/rakes/guardrail/.venv/bin/celesto"
                try:
                    probe = subprocess.run(
                        ["wsl", "-d", "Ubuntu", "test", "-x", wsl_venv_celesto],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    if probe.returncode == 0:
                        return ["wsl", "-d", "Ubuntu", wsl_venv_celesto]
                except Exception:
                    pass

        msg = (
            "Celesto CLI binary was not found on PATH or in WSL environment. "
            "Please install Celesto CLI 0.1.8 or configure CELESTO_CLI_PATH."
        )
        raise CelestoUnavailableError(msg)

    def _run_cli_json(self, sub_args: list[str], timeout: float) -> dict[str, Any]:
        """Execute Celesto CLI command with `--json` and return parsed JSON payload."""
        cmd = [*self._command_prefix, *sub_args, "--json"]
        env = os.environ.copy()
        if self.settings.celesto_api_key:
            env["CELESTO_API_KEY"] = self.settings.celesto_api_key.get_secret_value()

        try:
            logger.debug("Executing Celesto CLI: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            msg = f"Celesto CLI command timed out after {timeout}s: {' '.join(sub_args)}"
            raise GuestCommandTimeoutError(msg) from exc
        except Exception as exc:
            sanitized = sanitize_text(str(exc))
            msg = f"Failed to execute Celesto CLI: {sanitized}"
            raise CelestoUnavailableError(msg) from exc

        stdout_raw = proc.stdout.strip()
        stderr_raw = proc.stderr.strip()

        # Parse JSON envelope
        if not stdout_raw:
            if proc.returncode != 0:
                sanitized_err = sanitize_text(stderr_raw)
                msg = f"Celesto CLI failed with exit code {proc.returncode}: {sanitized_err}"
                raise CelestoUnavailableError(msg)
            return {}

        try:
            payload = json.loads(stdout_raw)
        except json.JSONDecodeError as exc:
            sanitized_out = sanitize_text(stdout_raw[:500])
            msg = f"Celesto CLI returned malformed JSON: {sanitized_out}"
            raise CelestoUnavailableError(msg) from exc

        if not payload.get("ok", False):
            err_dict = payload.get("error") or {}
            err_msg = sanitize_text(
                err_dict.get("message")
                or err_dict.get("code")
                or f"CLI error (exit code {proc.returncode})"
            )
            # Differentiate command run errors vs general CLI errors
            if payload.get("command") == "computer.run" and "exit_code" in payload.get("data", {}):
                # Guest command finished with non-zero exit code, return data payload
                return payload
            raise CelestoUnavailableError(err_msg, details=err_dict)

        return payload

    def create_computer(
        self, name: str | None = None, boot_timeout: float = 60.0
    ) -> dict[str, Any]:
        """Create cloud computer: `celesto computer create --cloud`."""
        # Celesto Cloud rejects `-n/--name` flag. Celesto assigns provider IDs (cmp_...)
        # while GuardRail tracks sandbox_name (sbx-...) in SandboxHandle and the ledger.
        args = ["computer", "create", "--cloud", "--boot-timeout", str(boot_timeout)]

        try:
            # Subprocess timeout slightly higher than boot_timeout
            envelope = self._run_cli_json(args, timeout=boot_timeout + 15.0)
            data = envelope.get("data") or {}
            computer_id = data.get("computer_id")
            if not computer_id:
                msg = f"Celesto create response missing computer_id: {envelope}"
                raise SandboxCreationError(msg)
            return data
        except (CelestoUnavailableError, GuestCommandTimeoutError) as exc:
            raise SandboxCreationError(f"Failed to create sandbox: {exc}") from exc

    def get_computer(self, computer_id: str) -> dict[str, Any]:
        """Inspect cloud computer: `celesto computer get <computer_id>`."""
        args = ["computer", "get", computer_id]
        envelope = self._run_cli_json(args, timeout=20.0)
        return envelope.get("data") or {}

    def list_computers(self, limit: int = 50) -> list[dict[str, Any]]:
        """List computers: `celesto computer list --cloud --limit <limit>`."""
        args = ["computer", "list", "--cloud", "--limit", str(limit)]
        envelope = self._run_cli_json(args, timeout=30.0)
        data = envelope.get("data") or {}
        return data.get("computers") or []

    def run_command(self, computer_id: str, command: str, timeout: int = 30) -> dict[str, Any]:
        """Execute command inside guest: `celesto computer run --timeout <t> <id> <cmd>`."""
        args = ["computer", "run", "--timeout", str(timeout), computer_id, command]
        try:
            envelope = self._run_cli_json(args, timeout=float(timeout) + 15.0)
            data = envelope.get("data") or {}
            return data
        except GuestCommandTimeoutError:
            raise
        except CelestoUnavailableError as exc:
            raise GuestCommandExecutionError(f"Guest command execution failed: {exc}") from exc

    def delete_computer(self, computer_id: str) -> dict[str, Any]:
        """Delete cloud computer: `celesto computer delete --cloud <computer_id>`."""
        args = ["computer", "delete", "--cloud", computer_id]
        try:
            envelope = self._run_cli_json(args, timeout=40.0)
            return envelope.get("data") or {}
        except Exception as exc:
            sanitized = sanitize_text(str(exc))
            raise SandboxCleanupError(
                f"Failed to delete computer '{computer_id}': {sanitized}"
            ) from exc


class FakeCelestoClient(CelestoClientInterface):
    """Deterministic, high-fidelity in-memory fake client for unit tests."""

    def __init__(self) -> None:
        self.computers: dict[str, dict[str, Any]] = {}
        self.command_history: list[dict[str, Any]] = []
        self.deleted_computers: list[str] = []

        # Configurable fault injection
        self.fail_on_create: bool = False
        self.create_error_msg: str = "Simulated cloud allocation capacity exceeded"
        self.fail_on_readiness: bool = False
        self.fail_on_command: bool = False
        self.timeout_on_command: bool = False
        self.fail_on_delete: bool = False
        self.delete_error_msg: str = "Simulated deletion API failure"

        # Pre-canned command responses: command_str -> dict(exit_code=int, stdout=str, stderr=str)
        self.command_responses: dict[str, dict[str, Any]] = {}
        # In-memory virtual guest filesystem for safe offline command execution
        self.virtual_files: dict[str, str] = {}
        self.terminal_states: dict[str, str] = {}

    def set_command_response(
        self, command: str, exit_code: int = 0, stdout: str = "", stderr: str = ""
    ) -> None:
        """Set custom canned response for a specific guest shell command."""
        self.command_responses[command] = {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
        }

    def create_computer(
        self, name: str | None = None, boot_timeout: float = 60.0
    ) -> dict[str, Any]:
        """Simulate creating a cloud computer."""
        if self.fail_on_create:
            raise SandboxCreationError(self.create_error_msg)

        computer_id = f"cmp_fake_{len(self.computers) + 1:04d}"
        computer_record = {
            "computer_id": computer_id,
            "name": name,
            "status": "running",
            "provider": "cloud",
            "vcpus": 1,
            "ram_mb": 1024,
            "boot_timeout": boot_timeout,
        }
        self.computers[computer_id] = computer_record
        return {"computer_id": computer_id, "provider": "cloud"}

    def get_computer(self, computer_id: str) -> dict[str, Any]:
        """Simulate getting computer details."""
        if computer_id in self.computers:
            return self.computers[computer_id]
        if computer_id in self.terminal_states:
            return {
                "computer_id": computer_id,
                "status": self.terminal_states[computer_id],
                "provider": "cloud",
            }
        return {}

    def list_computers(self, limit: int = 50) -> list[dict[str, Any]]:
        """Simulate listing cloud computers."""
        return list(self.computers.values())[:limit]

    def run_command(self, computer_id: str, command: str, timeout: int = 30) -> dict[str, Any]:
        """Simulate running a command inside the guest."""
        if computer_id not in self.computers:
            msg = f"Computer '{computer_id}' does not exist or was deleted."
            raise GuestCommandExecutionError(msg)

        if self.timeout_on_command:
            raise GuestCommandTimeoutError(f"Command '{command}' timed out after {timeout}s.")

        if self.fail_on_command:
            raise GuestCommandExecutionError("Simulated guest transport failure.")

        self.command_history.append(
            {"computer_id": computer_id, "command": command, "timeout": timeout}
        )

        # Check pre-canned response
        if command in self.command_responses:
            return self.command_responses[command]

        # Check readiness probes
        if "READY" in command:
            if self.fail_on_readiness:
                return {
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": "Service not ready",
                }
            return {
                "exit_code": 0,
                "stdout": "READY\n",
                "stderr": "",
            }

        # Check OS release
        if "cat /etc/os-release" in command:
            return {
                "exit_code": 0,
                "stdout": 'NAME="Ubuntu"\nVERSION="24.04.5 LTS (Noble Numbat)"\n',
                "stderr": "",
            }

        # Handle base64 transfer into virtual guest filesystem
        # e.g.: mkdir -p /tmp/... && echo '...' | base64 -d > /tmp/...
        if "base64 -d >" in command:
            try:
                parts = command.split("base64 -d >")
                target_file = parts[1].strip()
                echo_part = parts[0]
                # extract base64 payload from echo '...' or echo "..."
                b64_match = re.search(r"echo\s+['\"]([a-zA-Z0-9+/=]+)['\"]", echo_part)
                if b64_match:
                    raw_b64 = b64_match.group(1)
                    decoded_text = base64.b64decode(raw_b64).decode("utf-8")
                    self.virtual_files[target_file] = decoded_text
                    return {"exit_code": 0, "stdout": "", "stderr": ""}
            except Exception as exc:
                return {"exit_code": 1, "stdout": "", "stderr": str(exc)}

        # Handle sha256sum on virtual file
        if "sha256sum" in command:
            words = command.strip().split()
            target_file = words[-1]
            if target_file in self.virtual_files:
                digest = hashlib.sha256(self.virtual_files[target_file].encode("utf-8")).hexdigest()
                return {
                    "exit_code": 0,
                    "stdout": f"{digest}  {target_file}\n",
                    "stderr": "",
                }
            return {"exit_code": 1, "stdout": "", "stderr": f"No such file: {target_file}"}

        # Handle cat on virtual file
        if command.startswith("cat ") and not command.startswith("cat /etc/"):
            target_file = command.split("cat ")[1].strip()
            if target_file in self.virtual_files:
                return {
                    "exit_code": 0,
                    "stdout": self.virtual_files[target_file],
                    "stderr": "",
                }
            return {"exit_code": 1, "stdout": "", "stderr": f"No such file: {target_file}"}

        # Default standard command output
        return {
            "exit_code": 0,
            "stdout": f"Executed: {command}\n",
            "stderr": "",
        }

    def delete_computer(self, computer_id: str) -> dict[str, Any]:
        """Simulate deleting a cloud computer."""
        if self.fail_on_delete:
            raise SandboxCleanupError(self.delete_error_msg)

        if computer_id in self.computers:
            del self.computers[computer_id]
        self.terminal_states[computer_id] = "deleted"
        self.deleted_computers.append(computer_id)
        return {"computer_id": computer_id, "status": "deleted", "provider": "cloud"}

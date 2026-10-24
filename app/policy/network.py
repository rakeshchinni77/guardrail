"""Network policy profiles, local mock sink, and honest capability boundary definitions.

IMPORTANT SECURITY & HONESTY NOTICE:
- Control plane policy checks evaluate proposed destinations at the Python/orchestrator layer.
- Infrastructure-level guest microVM network filtering (e.g. eBPF, iptables) is UNVERIFIED on
  Celesto Cloud 0.1.8. Python policy decisions must NOT be claimed as guest OS network isolation.
- Real external exfiltration destinations and real credential transmission are strictly forbidden.
- Local mock sink (MockExfiltrationSink) is used for testing exfiltration attempts.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

INFRASTRUCTURE_ENFORCEMENT_STATUS = "UNVERIFIED"
INFRASTRUCTURE_LIMITATION_NOTE = (
    "Control plane Python policy enforcement only. Operating system or infrastructure-level "
    "network isolation on Celesto Cloud 0.1.8 is UNVERIFIED."
)


class NetworkProfileType(StrEnum):
    """Configurable network policy profile types."""

    RESTRICTED = "restricted"
    CONTROLLED_TEST = "controlled_test"
    UNRESTRICTED_BASELINE = "unrestricted_baseline"


@dataclass
class NetworkEvaluationResult:
    """Evaluation result for an outbound network request or destination."""

    allowed: bool
    profile: NetworkProfileType
    destination: str
    reason: str
    enforcement_point: str = "control_plane_policy_hook"
    infrastructure_status: str = INFRASTRUCTURE_ENFORCEMENT_STATUS
    limitation_note: str = INFRASTRUCTURE_LIMITATION_NOTE


class MockExfiltrationSink:
    """In-memory, local controlled sink for testing exfiltration attempts safely."""

    def __init__(self) -> None:
        self.recorded_attempts: list[dict[str, Any]] = []

    def receive_payload(
        self,
        destination: str,
        payload: str | dict[str, Any],
        run_id: str | None = None,
        canary_present: bool = False,
    ) -> dict[str, Any]:
        """Record an attempted transmission to the mock sink without touching the external web."""
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "destination": destination,
            "run_id": run_id,
            "payload_size": len(str(payload)),
            "canary_present": canary_present,
            "sink_type": "local_mock_sink",
        }
        self.recorded_attempts.append(record)
        return {
            "status": "received_by_mock_sink",
            "attempt_index": len(self.recorded_attempts) - 1,
        }

    def clear(self) -> None:
        """Clear recorded attempts."""
        self.recorded_attempts.clear()


class NetworkPolicyManager:
    """Evaluates proposed destinations against the active network policy profile."""

    ALLOWED_LOCAL_SCHEMES = {"mock", "fixture"}
    ALLOWED_CONTROLLED_HOSTS = {"localhost", "127.0.0.1", "sink.local", "mock-sink"}

    def __init__(
        self,
        profile: NetworkProfileType = NetworkProfileType.RESTRICTED,
        sink: MockExfiltrationSink | None = None,
    ) -> None:
        self.profile = profile
        self.sink = sink or MockExfiltrationSink()

    def evaluate_destination(self, destination: str) -> NetworkEvaluationResult:
        """Evaluate whether a destination is permitted under the active profile."""
        if not destination or not isinstance(destination, str):
            return NetworkEvaluationResult(
                allowed=False,
                profile=self.profile,
                destination=str(destination),
                reason="Destination must be a non-empty string.",
            )

        parsed = urlparse(destination)
        scheme = parsed.scheme.lower() if parsed.scheme else ""
        hostname = (parsed.hostname or "").lower()

        # 1. Profile: RESTRICTED - Strict Zero-Egress
        if self.profile == NetworkProfileType.RESTRICTED:
            # Only internal fixtures/mock schemes allowed; all network egress is blocked
            if scheme in self.ALLOWED_LOCAL_SCHEMES:
                return NetworkEvaluationResult(
                    allowed=True,
                    profile=self.profile,
                    destination=destination,
                    reason=f"Local scheme '{scheme}' permitted under restricted profile.",
                )
            return NetworkEvaluationResult(
                allowed=False,
                profile=self.profile,
                destination=destination,
                reason=(
                    f"Outbound network request to '{destination}' blocked by restricted "
                    "network policy profile (zero-egress mode)."
                ),
            )

        # 2. Profile: CONTROLLED_TEST - Local Sink / Mock Only
        if self.profile == NetworkProfileType.CONTROLLED_TEST:
            if scheme in self.ALLOWED_LOCAL_SCHEMES or hostname in self.ALLOWED_CONTROLLED_HOSTS:
                return NetworkEvaluationResult(
                    allowed=True,
                    profile=self.profile,
                    destination=destination,
                    reason=(
                        f"Destination '{destination}' matches controlled test allowlist "
                        "(local mock sink)."
                    ),
                )
            return NetworkEvaluationResult(
                allowed=False,
                profile=self.profile,
                destination=destination,
                reason=(
                    f"External destination '{destination}' rejected under controlled_test profile. "
                    "Only local mock sinks are permitted."
                ),
            )

        # 3. Profile: UNRESTRICTED_BASELINE - Baseline Mode
        if self.profile == NetworkProfileType.UNRESTRICTED_BASELINE:
            # Note: even in baseline, GuardRail forbids transmitting canary over external network
            return NetworkEvaluationResult(
                allowed=True,
                profile=self.profile,
                destination=destination,
                reason="Unrestricted baseline profile allows network destinations at policy layer.",
            )

        return NetworkEvaluationResult(
            allowed=False,
            profile=self.profile,
            destination=destination,
            reason=f"Unknown network policy profile '{self.profile}'.",
        )

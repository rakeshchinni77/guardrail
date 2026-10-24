"""Synthetic canary token management and exposure tracking.

Provides distinct tracking for canary exposure attempts, blocks, and leakage,
with guaranteed masking in logs and user-facing records.
"""

from typing import Any

CANARY_SECRET = "GR-canary-7f3a91d2"
CANARY_MASK = "[PROTECTED_CANARY_TOKEN]"


def mask_canary(text: str) -> str:
    """Mask synthetic canary token from text to prevent accidental log disclosure."""
    if not isinstance(text, str):
        return text
    return text.replace(CANARY_SECRET, CANARY_MASK)


class CanaryTracker:
    """Tracks synthetic canary detection, containment, and leakage outcomes."""

    def __init__(self, canary_token: str = CANARY_SECRET) -> None:
        self.canary_token = canary_token

    def inspect_input(self, text: str, source: str = "") -> dict[str, Any]:
        """Check whether incoming prompt, argument, or content attempts canary exposure."""
        if not isinstance(text, str):
            return {"attempted": False, "source": source}

        attempted = self.canary_token in text
        return {
            "attempted": attempted,
            "source": source,
            "masked_preview": mask_canary(text[:200]) if attempted else None,
        }

    def inspect_output(self, text: str, source: str = "") -> dict[str, Any]:
        """Check whether final agent output or tool result leaked the canary."""
        if not isinstance(text, str):
            return {"leaked": False, "source": source}

        leaked = self.canary_token in text
        return {
            "leaked": leaked,
            "source": source,
            "masked_preview": mask_canary(text[:200]) if leaked else None,
        }

    def sanitize(self, text: str) -> str:
        """Return text guaranteed free of raw canary secret tokens."""
        return mask_canary(text)

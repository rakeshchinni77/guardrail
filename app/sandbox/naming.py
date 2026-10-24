"""Unique sandbox name generation and validation matching GuardRail conventions."""

import re
import secrets

SANDBOX_NAME_PREFIX = "sbx-"
SANDBOX_NAME_REGEX = re.compile(r"^sbx-[a-z0-9]{8,}$")


def generate_sandbox_name(prefix: str = SANDBOX_NAME_PREFIX, entropy_bytes: int = 5) -> str:
    """Generate a unique sandbox identifier matching `^sbx-[a-z0-9]{8,}$`.

    Default entropy of 5 bytes produces 10 lowercase hexadecimal characters,
    ensuring 16^10 (> 10^12) possible values for safe concurrent generation.
    """
    token = secrets.token_hex(entropy_bytes)
    candidate = f"{prefix}{token}"
    if not validate_sandbox_name(candidate):
        msg = f"Generated sandbox name '{candidate}' does not match contract."
        raise ValueError(msg)
    return candidate


def validate_sandbox_name(name: str) -> bool:
    """Check if sandbox name matches the required convention."""
    return bool(SANDBOX_NAME_REGEX.match(name))

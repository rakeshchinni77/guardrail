"""Scan all Git commit history for leaked secrets, credentials, or keys."""

import subprocess
import sys


def main() -> int:
    print("[Phase 10] Scanning complete git history for committed secrets...")
    # Get all commits
    rev_list = subprocess.run(
        ["git", "rev-list", "--all"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()

    print(f"Total commits in history: {len(rev_list)}")

    secret_patterns = [
        "celesto_api_key",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    ]

    violations = []
    for commit in rev_list:
        diff_proc = subprocess.run(
            ["git", "show", commit],
            capture_output=True,
            text=True,
            errors="replace",
        )
        content = diff_proc.stdout
        for pattern in secret_patterns:
            if pattern in content:
                # Exclude .env.example with replace-me placeholders and code definitions
                for line in content.splitlines():
                    if pattern in line:
                        is_safe = any(
                            safe in line
                            for safe in (
                                "replace-me",
                                "replace_with_your",
                                "test-celesto-key",
                                "another-secret",
                                "SecretStr",
                                "celesto_api_key: SecretStr",
                                "celesto_api_key: str | None",
                                "celesto_api_key is None",
                                "celesto_api_key is not None",
                                "celesto_api_key=None",
                                "celesto_api_key=raw_secret",
                            )
                        )
                        if not is_safe:
                            violations.append((commit[:8], pattern, line.strip()[:80]))

    if violations:
        print(f"[FAIL] Found {len(violations)} suspicious commit diffs:")
        for commit, pat, line in violations:
            print(f"  - Commit {commit}: pattern '{pat}': {line}")
        return 1
    else:
        print("[PASS] Zero committed secrets found in entire git history.")
        return 0


if __name__ == "__main__":
    sys.exit(main())

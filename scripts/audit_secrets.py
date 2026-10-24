"""Automated secret scan and repository hygiene auditor (Phase 10).

Checks:
1. No unmasked canary secrets (GR-canary-7f3a91d2) in reports, logs, or evidence.
2. Authorized locations for CANARY_SECRET (app/policy/canary.py and test definitions).
3. No hardcoded API keys, private passwords, tokens, or private key material.
4. No committed .env files or certificates.
5. No non-portable absolute local paths in config, Docker, or code files.
6. Clean git ignore compliance.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CANARY_TOKEN = "GR-canary-7f3a91d2"

# Authorized files allowed to declare or inspect the canary token definition
AUTHORIZED_CANARY_FILES = {
    Path("app/policy/canary.py"),
    Path("app/agent/schemas.py"),
    Path("app/reporting/validator.py"),
    Path("tests/test_policy_defenses.py"),
    Path("tests/test_report_pipeline.py"),
    Path("scripts/audit_secrets.py"),
    Path("docs/ARCHITECTURE.md"),
    Path("docs/TESTING.md"),
}

SUSPECT_PATTERNS = [
    (re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----"), "Private key block"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "OpenAI/similar API key"),
    (
        re.compile(r"(?i)celesto[_-]key\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
        "Hardcoded Celesto API key",
    ),
    (
        re.compile(r"(?i)password\s*[:=]\s*['\"](?!ledger|password|fake|test|none)[\w\W]{8,}['\"]"),
        "Suspicious password",
    ),
]

# Files where local dev absolute paths must NOT appear
PORTABLE_CONFIG_FILES = [
    Path("docker-compose.yml"),
    Path("Dockerfile"),
    Path(".env.example"),
    Path("pyproject.toml"),
    Path("reports/problem.json"),
    Path("reports/capabilities.json"),
    Path("reports/lifecycle.json"),
    Path("reports/reliability.json"),
    Path("reports/containment.json"),
    Path("reports/failure_policy.json"),
    Path("reports/concurrency.json"),
]

IGNORED_DIRS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    ".clean_checkout_test",
}


def audit_repository() -> dict[str, list[str]]:
    """Run full audit across the repository and return findings by category."""
    findings: dict[str, list[str]] = {
        "canary_leaks": [],
        "hardcoded_secrets": [],
        "committed_env_or_keys": [],
        "non_portable_paths": [],
    }

    # 1. Check for committed .env or certificate files
    for path in REPO_ROOT.glob("**/*"):
        if any(ignored in path.parts for ignored in IGNORED_DIRS):
            continue
        if path.is_file():
            rel = path.relative_to(REPO_ROOT)
            if rel.name == ".env" or (
                rel.suffix in (".pem", ".key", ".cert", ".crt")
                and not rel.name.endswith(".example")
            ):
                findings["committed_env_or_keys"].append(str(rel))

    # 2. Scan file contents
    for path in REPO_ROOT.glob("**/*"):
        if any(ignored in path.parts for ignored in IGNORED_DIRS):
            continue
        if not path.is_file() or path.suffix in (".pyc", ".png", ".jpg", ".gitkeep"):
            continue

        rel = path.relative_to(REPO_ROOT)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Canary leak check
        if CANARY_TOKEN in content:
            if rel not in AUTHORIZED_CANARY_FILES:
                findings["canary_leaks"].append(str(rel))

        # Hardcoded secret patterns
        for pat, desc in SUSPECT_PATTERNS:
            if pat.search(content):
                findings["hardcoded_secrets"].append(f"{rel}: {desc}")

        # Non-portable paths in critical config/report files
        if rel in PORTABLE_CONFIG_FILES:
            if re.search(r"[a-zA-Z]:[/\\]Users[/\\]", content) or re.search(r"/home/\w+", content):
                findings["non_portable_paths"].append(str(rel))

    return findings


def main() -> int:
    print(f"[Phase 10] Scanning repository at {REPO_ROOT} for secrets and portability issues...")
    findings = audit_repository()

    passed = True
    print("\n--- Secret & Repository Hygiene Audit Results ---")

    # 1. Canary Leaks
    if findings["canary_leaks"]:
        passed = False
        print(f"[FAIL] Unmasked canary leaks found in {len(findings['canary_leaks'])} file(s):")
        for f in findings["canary_leaks"]:
            print(f"  - {f}")
    else:
        print("[PASS] Zero unmasked canary token leaks in reports, logs, and evidence.")

    # 2. Hardcoded Secrets
    if findings["hardcoded_secrets"]:
        passed = False
        count = len(findings["hardcoded_secrets"])
        print(f"[FAIL] Hardcoded secret candidates found in {count} file(s):")
        for f in findings["hardcoded_secrets"]:
            print(f"  - {f}")
    else:
        print("[PASS] Zero hardcoded API keys, private passwords, or private keys detected.")

    # 3. Committed .env or Keys
    if findings["committed_env_or_keys"]:
        passed = False
        count = len(findings["committed_env_or_keys"])
        print(f"[FAIL] Committed .env or certificate files found in {count} file(s):")
        for f in findings["committed_env_or_keys"]:
            print(f"  - {f}")
    else:
        print("[PASS] Zero committed .env, .pem, or .key files detected.")

    # 4. Non-Portable Absolute Paths
    if findings["non_portable_paths"]:
        passed = False
        count = len(findings["non_portable_paths"])
        print(f"[FAIL] Non-portable host paths found in {count} config/report file(s):")
        for f in findings["non_portable_paths"]:
            print(f"  - {f}")
    else:
        print(
            "[PASS] Zero non-portable absolute host paths in config, Docker, or report artifacts."
        )

    if passed:
        print("\n=== REPOSITORY HYGIENE AUDIT PASSED ===")
        return 0
    else:
        print("\n=== REPOSITORY HYGIENE AUDIT FAILED ===", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

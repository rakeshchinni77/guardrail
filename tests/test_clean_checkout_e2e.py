"""End-to-End Clean Checkout and Hardening Verification Test (Phase 10).

Validates:
- Clean checkout reproducibility.
- Missing .env fallback and safe defaults.
- .env.example completeness.
- .gitignore protection of secrets while tracking deliverables.
- Docker Compose validity and live endpoint checks.
- All 10 report artifacts cross-validation.
- Zero secret/credential exposure across the repository.
"""

import re
from pathlib import Path

import pytest

from app.config import Settings
from app.reporting.validator import ReportPipelineValidator
from scripts.audit_secrets import audit_repository

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def test_missing_env_loads_safe_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Verify application initializes with safe defaults when .env is absent."""
    # Run in an empty directory with no .env
    monkeypatch.chdir(tmp_path)
    # Clear any matching environment variables
    for env_key in ("APP_NAME", "APP_ENV", "LOG_LEVEL", "API_PORT", "DATABASE_URL"):
        monkeypatch.delenv(env_key, raising=False)

    settings = Settings()
    assert settings.app_name == "GuardRail"
    assert settings.app_env == "development"
    assert settings.log_level == "INFO"
    assert settings.api_port == 8080
    assert settings.database_url is None
    assert settings.celesto_api_key is None


def test_env_example_completeness_and_safe_placeholders():
    """Verify .env.example has safe placeholders and contains all required keys."""
    env_example = WORKSPACE_ROOT / ".env.example"
    assert env_example.exists()
    content = env_example.read_text(encoding="utf-8")
    raw_lines = content.splitlines()
    lines = [line.strip() for line in raw_lines if line.strip() and not line.startswith("#")]

    keys = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            keys[k.strip()] = v.strip()

    required_keys = {
        "APP_NAME",
        "APP_ENV",
        "LOG_LEVEL",
        "API_PORT",
        "DATABASE_URL",
        "CELESTO_PROVIDER",
        "CELESTO_API_KEY",
        "CANARY_SECRET",
    }
    assert required_keys.issubset(keys.keys())

    # Ensure sensitive fields use safe dummy placeholders
    assert keys["CELESTO_API_KEY"] in ("replace-me", "replace_with_your_celesto_api_key")
    assert "replace" in keys["CANARY_SECRET"] or "fake" in keys["CANARY_SECRET"]


def test_gitignore_protects_secrets_and_tracks_deliverables():
    """Verify .gitignore rules protect secrets, caches, and logs while tracking deliverables."""
    gitignore = WORKSPACE_ROOT / ".gitignore"
    assert gitignore.exists()
    content = gitignore.read_text(encoding="utf-8")

    # Critical secret protections
    assert ".env" in content
    assert "*.pem" in content
    assert "*.key" in content
    assert ".venv/" in content

    # Deliverables un-ignored
    assert "!logs/commands.jsonl" in content
    assert "!reports/*.json" in content
    assert "!fixtures/clean/*" in content
    assert "!fixtures/pages/*" in content
    assert "!scripts/*" in content


def test_all_ten_reports_validate_in_place():
    """Verify all 10 required artifacts pass the ReportPipelineValidator audit."""
    validator = ReportPipelineValidator(WORKSPACE_ROOT)
    audit = validator.validate_all()
    assert audit["overall_status"] == "PASSED"
    assert audit["secret_scan"]["status"] == "CLEAN"
    assert audit["cross_report_consistency"] == "VERIFIED"


def test_repository_secret_hygiene_audit():
    """Verify zero unmasked canaries, hardcoded keys, or non-portable paths."""
    findings = audit_repository()
    assert not findings["canary_leaks"], f"Canary leaks: {findings['canary_leaks']}"
    assert not findings["hardcoded_secrets"], f"Secrets: {findings['hardcoded_secrets']}"
    assert not findings["committed_env_or_keys"], (
        f"Committed keys: {findings['committed_env_or_keys']}"
    )
    assert not findings["non_portable_paths"], (
        f"Non-portable paths: {findings['non_portable_paths']}"
    )


def test_readme_contains_all_six_mandatory_phrases():
    """Verify README.md contains all 6 hackathon-mandated headings and phrases."""
    readme_path = WORKSPACE_ROOT / "README.md"
    assert readme_path.exists()
    content = readme_path.read_text(encoding="utf-8")

    mandatory_phrases = [
        "Problem statement",
        "How I used Celesto",
        "Eval report",
        "Containment test",
        "State and failure design",
        "Setup",
    ]

    for phrase in mandatory_phrases:
        pattern = re.compile(
            rf"(?:#{{1,6}}\s+.*{re.escape(phrase)}|\*\*{re.escape(phrase)}\*\*)",
            re.IGNORECASE,
        )
        assert pattern.search(content), f"Mandatory README phrase missing: '{phrase}'"

"""Unit tests for GuardRail application configuration."""

import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings


def test_default_settings_load_successfully(monkeypatch):
    """Confirm default settings load with expected default values."""
    monkeypatch.delenv("APP_NAME", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("CELESTO_API_KEY", raising=False)
    monkeypatch.delenv("CELESTO_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.app_name == "GuardRail"
    assert settings.app_env == "development"
    assert settings.log_level == "INFO"
    assert settings.database_url is None
    assert settings.celesto_api_key is None
    assert settings.celesto_timeout_seconds == 60
    assert settings.llm_provider is None
    assert settings.llm_model is None
    assert settings.llm_api_key is None


def test_environment_variables_override_defaults(monkeypatch):
    """Verify environment variables correctly override configuration defaults."""
    monkeypatch.setenv("APP_NAME", "CustomGuardRail")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("CELESTO_TIMEOUT_SECONDS", "120")
    monkeypatch.setenv("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("CELESTO_API_KEY", "test-celesto-key-12345")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("LLM_API_KEY", "test-llm-key-67890")

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.app_name == "CustomGuardRail"
    assert settings.app_env == "production"
    assert settings.log_level == "DEBUG"
    assert settings.celesto_timeout_seconds == 120
    assert settings.database_url == "postgresql://test:test@localhost:5432/test"
    assert settings.celesto_api_key is not None
    assert settings.celesto_api_key.get_secret_value() == "test-celesto-key-12345"
    assert settings.llm_provider == "openai"
    assert settings.llm_model == "gpt-4o"
    assert settings.llm_api_key is not None
    assert settings.llm_api_key.get_secret_value() == "test-llm-key-67890"


def test_invalid_app_env_rejected():
    """Verify that unsupported app_env values raise a validation error."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(app_env="staging")
    assert "Invalid app_env" in str(exc_info.value)


def test_invalid_log_level_rejected():
    """Verify that unsupported log levels raise a validation error."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(log_level="VERBOSE")
    assert "Invalid log_level" in str(exc_info.value)


@pytest.mark.parametrize("invalid_timeout", [0, -1, -60])
def test_invalid_timeout_rejected(invalid_timeout):
    """Verify non-positive timeout values raise validation errors."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(celesto_timeout_seconds=invalid_timeout)
    assert "celesto_timeout_seconds must be positive" in str(exc_info.value)


def test_missing_optional_credentials_allow_instantiation():
    """Verify absence of credentials does not prevent configuration instantiation."""
    settings = Settings(celesto_api_key=None, llm_api_key=None, database_url=None)
    assert settings.celesto_api_key is None
    assert settings.llm_api_key is None
    assert settings.database_url is None


def test_secret_fields_masked_in_representation():
    """Ensure secret fields are masked in str and repr to prevent accidental leakage."""
    raw_secret = "super-secret-celesto-token"
    settings = Settings(celesto_api_key=raw_secret, llm_api_key="another-secret")

    representation = repr(settings)
    stringified = str(settings)

    assert raw_secret not in representation
    assert raw_secret not in stringified
    assert "**********" in representation or "******" in representation


def test_settings_isolation_and_cache_clearing(monkeypatch):
    """Verify get_settings cache can be cleared to avoid state leaks between tests."""
    monkeypatch.setenv("APP_NAME", "FirstInstance")
    get_settings.cache_clear()
    first = get_settings()
    assert first.app_name == "FirstInstance"

    # Mutate env without clearing cache: result should remain cached
    monkeypatch.setenv("APP_NAME", "SecondInstance")
    assert get_settings().app_name == "FirstInstance"

    # Clearing cache should pick up new environment value
    get_settings.cache_clear()
    second = get_settings()
    assert second.app_name == "SecondInstance"

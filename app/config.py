"""Application configuration module for GuardRail.

Provides typed, validated configuration loading using Pydantic Settings.
Secret fields are masked in representations, and credentials remain strictly optional.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnvironment = Literal["development", "test", "production"]
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class Settings(BaseSettings):
    """Core settings for the GuardRail platform."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core Application Settings
    app_name: str = Field(
        default="GuardRail",
        description="Name of the application service",
    )
    app_env: AppEnvironment = Field(
        default="development",
        description="Execution environment: development, test, or production",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging verbosity level",
    )
    api_port: int = Field(
        default=8080,
        description="HTTP port for the FastAPI service",
    )

    # Database Settings (Phase 2+)
    database_url: str | None = Field(
        default=None,
        description="Optional PostgreSQL database connection URL",
    )

    # Celesto Sandbox Settings (Phase 3+)
    celesto_provider: str = Field(
        default="cloud",
        description="Celesto provider: cloud or local",
    )
    celesto_api_key: SecretStr | None = Field(
        default=None,
        description="Celesto Cloud API key for remote sandbox provisioning",
    )
    celesto_timeout_seconds: int = Field(
        default=60,
        description="Timeout bound for Celesto sandbox operations (must be positive)",
    )
    celesto_cli_path: str | None = Field(
        default=None,
        description="Optional explicit path to Celesto CLI executable",
    )
    celesto_boot_timeout_seconds: float = Field(
        default=60.0,
        description="Maximum seconds to wait for guest boot and readiness",
    )
    celesto_command_timeout_seconds: int = Field(
        default=30,
        description="Default maximum seconds to wait for guest command execution",
    )
    celesto_max_output_bytes: int = Field(
        default=102400,
        description="Maximum captured output bytes before safe truncation (default 100 KB)",
    )

    # LLM Settings (Phase 4+)
    llm_provider: str | None = Field(
        default=None,
        description="Optional LLM provider identifier",
    )
    llm_model: str | None = Field(
        default=None,
        description="Optional model identifier",
    )
    llm_api_key: SecretStr | None = Field(
        default=None,
        description="Optional API key for LLM provider",
    )

    @field_validator("app_env", mode="before")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        """Validate and normalize execution environment."""
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized not in ("development", "test", "production"):
                msg = f"Invalid app_env '{value}'. Allowed: development, test, production."
                raise ValueError(msg)
            return normalized
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Validate and normalize log level to standard uppercase strings."""
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized not in VALID_LOG_LEVELS:
                allowed = ", ".join(sorted(VALID_LOG_LEVELS))
                msg = f"Invalid log_level '{value}'. Allowed: {allowed}."
                raise ValueError(msg)
            return normalized
        return value

    @field_validator("celesto_timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: int) -> int:
        """Ensure timeout is a strictly positive integer."""
        if value <= 0:
            msg = f"celesto_timeout_seconds must be positive, got {value}."
            raise ValueError(msg)
        return value

    @property
    def sqlalchemy_database_url(self) -> str:
        """Return database URL normalized for SQLAlchemy with psycopg 3 driver."""
        if not self.database_url:
            return "sqlite:///:memory:"
        url = self.database_url
        if url.startswith("postgresql://"):
            return "postgresql+psycopg://" + url[len("postgresql://") :]
        return url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached instance of application settings.

    Use `get_settings.cache_clear()` in tests to reset state.
    """
    return Settings()

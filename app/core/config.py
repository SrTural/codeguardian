"""
CodeGuardian - Configuration Module
====================================
Centralized configuration using Pydantic Settings.
Supports environment variable overrides via .env file.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings.
    Values can be overridden via environment variables or .env file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    APP_NAME: str = Field(default="CodeGuardian", description="Application name")
    APP_VERSION: str = Field(default="0.1.0", description="Application version")
    APP_ENV: str = Field(default="development", description="Environment: dev/staging/prod")
    DEBUG: bool = Field(default=True, description="Debug mode")

    # --- Server ---
    HOST: str = Field(default="127.0.0.1", description="Server host")
    PORT: int = Field(default=8000, description="Server port")

    # --- LLM / Ollama ---
    OLLAMA_URL: str = Field(
        default="http://localhost:11434",
        description="Ollama API endpoint"
    )
    MODEL_NAME: str = Field(
        default="qwen2.5:7b-16k",
        description="LLM model to use"
    )
    LLM_TIMEOUT: int = Field(
        default=60,
        description="LLM request timeout in seconds"
    )
    LLM_MAX_TOKENS: int = Field(
        default=2000,
        description="Max characters sent to LLM"
    )

    # --- Scanner ---
    MAX_FILE_SIZE_MB: int = Field(
        default=10,
        description="Maximum file size to scan (MB)"
    )
    ALLOWED_EXTENSIONS: List[str] = Field(
        default=[".py", ".js", ".ts", ".java", ".go", ".txt"],
        description="Allowed file extensions for scanning"
    )
    DANGEROUS_FUNCTIONS: List[str] = Field(
        default=["eval", "exec", "__import__", "compile", "input"],
        description="Python functions considered dangerous"
    )

    # --- CORS ---
    CORS_ORIGINS: List[str] = Field(
        default=["*"],
        description="Allowed CORS origins (restrict in production)"
    )

    # --- Logging ---
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level: DEBUG/INFO/WARNING/ERROR"
    )

    @field_validator("APP_ENV")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v.lower() not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}")
        return v.lower()

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v.upper()

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.APP_ENV == "production"

    @property
    def is_debug(self) -> bool:
        """Check if debug mode is enabled."""
        return self.DEBUG and not self.is_production


@lru_cache()
def get_settings() -> Settings:
    """
    Cached settings instance.
    Use this instead of creating new Settings() each time.
    """
    return Settings()


# Module-level singleton for convenience
settings = get_settings()
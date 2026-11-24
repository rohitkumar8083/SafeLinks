"""Application configuration using pydantic-settings."""

from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SafeLinks service configuration."""

    # Application
    APP_NAME: str = "SafeLinks API"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["dev", "prod"] = "dev"
    LOG_LEVEL: str = "INFO"
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # CORS
    ALLOWED_ORIGINS: str = "*"
    ALLOWED_ORIGIN_REGEX: str | None = None
    TRUST_PROXY_HEADERS: bool = False

    # External Threat Intelligence API Keys
    GOOGLE_SAFE_BROWSING_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None
    URLHAUS_AUTH_KEY: str | None = None

    # Gemini AI Threat Intelligence
    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = "gemini-3-flash-preview"

    # Storage & Lifecycle
    SCAN_TTL_MINUTES: int = 60
    MAX_STORED_SCANS: int = 5000
    MAX_CONCURRENT_SCANS: int = 20

    # Rate Limiting
    RATE_LIMIT_SCANS_PER_MINUTE: int = 10
    RATE_LIMIT_READS_PER_MINUTE: int = 120

    # Timeouts & HTTP Limits
    CHECK_TIMEOUT_SECONDS: float = 12.0
    OVERALL_SCAN_TIMEOUT_SECONDS: float = 45.0
    HTTP_TIMEOUT_SECONDS: float = 8.0
    MAX_REDIRECTS: int = 5

    # Caching & Rate Limits for VT
    CACHE_TTL_SECONDS: int = 3600
    VT_REQUESTS_PER_MINUTE: int = 4
    VT_REQUESTS_PER_DAY: int = 500
    VT_MAX_WAIT_SECONDS: float = 20.0

    # Machine Learning
    MODEL_PATH: str = "app/ml/model/phishing_model.joblib"

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse ALLOWED_ORIGINS into a clean list of allowed origins."""
        if not self.ALLOWED_ORIGINS or self.ALLOWED_ORIGINS.strip() == "*":
            return ["*"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        if isinstance(v, str):
            return v.upper()
        return "INFO"

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent.parent / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

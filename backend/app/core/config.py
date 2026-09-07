"""
Sentinel SOC v2.2 — validated application configuration.

All environment variables are declared here with sensible defaults.
Validation fails fast at import time so misconfiguration is caught immediately.
"""
import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application metadata
    app_name: str = Field(default="SENTINEL SOC API", alias="APP_NAME")
    app_version: str = Field(default="2.0.0", alias="APP_VERSION")
    app_environment: str = Field(default="development", alias="APP_ENVIRONMENT")
    debug: bool = Field(default=False, alias="DEBUG")

    # Server
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")

    # CORS — comma-separated origins. In production this should be explicit.
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:5174,http://localhost:3000,http://127.0.0.1:5173",
        alias="CORS_ORIGINS",
    )

    # SQLite database path. Must resolve inside the project or a configured data directory.
    sqlite_db_path: Optional[str] = Field(default=None, alias="SQLITE_DB_PATH")

    # AI / LLM (optional)
    ai_api_key: Optional[str] = Field(default=None, alias="AI_API_KEY")
    ai_api_base_url: Optional[str] = Field(default=None, alias="AI_API_BASE_URL")
    ai_model: str = Field(default="gpt-3.5-turbo", alias="AI_MODEL")

    # NVD API key (optional but recommended)
    nvd_api_key: Optional[str] = Field(default=None, alias="NVD_API_KEY")

    # Rate limiting
    rate_limit_requests: int = Field(default=100, alias="RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")

    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")  # "json" or "text"
    request_id_header: str = Field(default="X-Request-ID", alias="REQUEST_ID_HEADER")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Allow hosting platforms to inject extra vars without crashing

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors_origins(cls, value: str) -> str:
        if isinstance(value, str):
            return value
        raise ValueError("CORS_ORIGINS must be a comma-separated string")

    @field_validator("sqlite_db_path", mode="before")
    @classmethod
    def _validate_sqlite_path(cls, value: Optional[str]) -> Optional[str]:
        if not value:
            return value
        # Reject paths that try to escape the application data directory.
        path = Path(value).resolve()
        # Normalize to absolute and ensure no parent traversal via symlinks.
        if not path.is_absolute():
            raise ValueError("SQLITE_DB_PATH must be an absolute path")
        # Block dangerous locations.
        forbidden_roots = {Path("/"), Path("/etc"), Path("/bin"), Path("/sbin"), Path("/usr"), Path("/tmp")}
        for root in forbidden_roots:
            try:
                path.relative_to(root)
                if root == Path("/"):
                    raise ValueError("SQLITE_DB_PATH cannot be the filesystem root")
                raise ValueError(f"SQLITE_DB_PATH cannot be under {root}")
            except ValueError as exc:
                if "cannot be" in str(exc):
                    raise
                continue
        return str(path)

    @property
    def parsed_cors_origins(self) -> List[str]:
        """Return CORS origins as a list of trimmed strings."""
        defaults = [
            "http://localhost:5173",
            "http://localhost:5174",
            "http://localhost:5175",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
        ]
        configured = [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        # In production, only use explicitly configured origins unless defaults are still present.
        if self.app_environment == "production":
            return configured
        return list(dict.fromkeys(defaults + configured))

    @property
    def resolved_sqlite_db_path(self) -> str:
        """Return the validated SQLite database path."""
        if self.sqlite_db_path:
            return self.sqlite_db_path
        # Default to backend/sentinel.db
        backend_dir = Path(__file__).resolve().parent.parent.parent
        return str(backend_dir / "sentinel.db")


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()

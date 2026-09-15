"""Environment-driven configuration shared by all IMMUNE-NET services."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    watsonx_project_id: str | None = Field(default=None, validation_alias="WATSONX_PROJECT_ID")
    watsonx_api_key: str | None = Field(default=None, validation_alias="WATSONX_API_KEY")
    watsonx_model_id: str | None = Field(default=None, validation_alias="WATSONX_MODEL_ID")
    auto_quarantine: bool = Field(default=True, validation_alias="AUTO_QUARANTINE")
    confidence_quarantine: float = Field(default=0.95, validation_alias="CONFIDENCE_QUARANTINE")
    confidence_sustained: int = Field(default=3, validation_alias="CONFIDENCE_SUSTAINED")
    telemetry_interval: float = Field(default=1.0, validation_alias="TELEMETRY_INTERVAL")
    agent_count: int = Field(default=8, validation_alias="AGENT_COUNT")
    model_path: Path = Field(default=Path("data/model.joblib"), validation_alias="MODEL_PATH")
    db_path: Path = Field(default=Path("data/immune_memory.db"), validation_alias="DB_PATH")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    webhook_url: str | None = Field(default=None, validation_alias="WEBHOOK_URL")
    alert_escalation_seconds: float = Field(default=45.0, validation_alias="ALERT_ESCALATION_SECONDS")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

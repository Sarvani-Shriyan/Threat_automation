from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    threat_queue_db: Path = Field(
        default=Path("./data/threat_queue.db"),
        alias="THREAT_QUEUE_DB",
    )
    feed_urls: list[str] = Field(default_factory=list, alias="FEED_URLS")
    keywords: list[str] = Field(
        default=["AWS", "CloudTrail", "Okta"],
        alias="KEYWORDS",
    )
    slm_model: str = Field(default="gemma-2-9b-it", alias="SLM_MODEL")
    reasoning_model: str = Field(
        default="ollama/phi4-mini-reasoning",
        alias="REASONING_MODEL",
    )
    llm_mock: bool = Field(default=False, alias="LLM_MOCK")
    max_feedback_retries: int = Field(default=3, alias="MAX_FEEDBACK_RETRIES")
    fetch_timeout_seconds: float = Field(default=30.0, alias="FETCH_TIMEOUT_SECONDS")
    pipeline_version: str = Field(default="0.1.0", alias="PIPELINE_VERSION")

    valid_action_names: list[str] = Field(
        default=[
            "block_ip",
            "isolate_host",
            "disable_user",
            "revoke_session",
            "quarantine_file",
            "alert_soc",
            "collect_forensics",
        ],
        alias="VALID_ACTION_NAMES",
    )
    valid_severities: list[str] = Field(
        default=["low", "medium", "high", "critical"],
        alias="VALID_SEVERITIES",
    )
    near_duplicate_hamming_threshold: int = Field(
        default=3,
        alias="NEAR_DUP_HAMMING_THRESHOLD",
    )

    @field_validator("feed_urls", "keywords", mode="before")
    @classmethod
    def split_comma_separated(cls, v: Any) -> Any:
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    def model_post_init(self, __context: object) -> None:
        if str(self.threat_queue_db) != ":memory:":
            self.threat_queue_db.parent.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()

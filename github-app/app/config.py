import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # GitHub App
    github_app_id: str
    github_private_key: str          # PEM content (newlines as \n) or file path
    github_webhook_secret: str

    # Gemini
    gemini_api_key: str
    gemini_model: str = "gemini-3-flash-preview"
    gemini_fallback_model: str = "gemini-2.5-flash"
    gemini_timeout_seconds: int = 30
    gemini_total_budget_seconds: int = 90
    gemini_reasoning_thinking_level: str = "medium"
    gemini_verification_thinking_level: str = "low"
    gemini_reasoning_max_output_tokens: int = 4096
    gemini_verification_max_output_tokens: int = 3072

    # Frontend → backend shared auth secret
    api_secret: str = ""

    # DB
    database_url: str = "sqlite:///./scans.db"

    def get_private_key(self) -> str:
        """Return PEM content whether value is a path or inline PEM."""
        val = self.github_private_key
        if val.strip().startswith("-----"):
            return val.replace("\\n", "\n")
        with open(val) as f:
            return f.read()


@lru_cache
def get_settings() -> Settings:
    return Settings()

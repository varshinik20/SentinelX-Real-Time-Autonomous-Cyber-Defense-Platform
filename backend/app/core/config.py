import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_ENV: str = "development"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    TELEMETRY_MODE: str = "development"  # 'windows' or 'development'
    WINDOWS_POLL_INTERVAL: int = 1
    RISK_THRESHOLD: int = 70
    RESPONSE_MODE: str = "DRY_RUN"
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinelx.db"
    LLM_ENABLED: bool = False
    MODEL_PATH: str = ""

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_TIMEOUT_S: float = 2.0
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    MODEL_PATH: str = "./models/trained"
    PROMPT_INJECTION_THRESHOLD: float = 0.75
    SHUTDOWN_TIMEOUT: float = 10.0
    CORS_ALLOWED_ORIGINS: str = "https://localhost:3000,https://localhost:5173"
    CORS_ORIGINS: str = "http://localhost:3000"
    
    CB_FAILURE_THRESHOLD: int = 3
    CB_RECOVERY_TIMEOUT_S: float = 30.0
    CB_HALF_OPEN_MAX_CALLS: int = 1
    
    AUDIT_HMAC_SECRET: str = "tenet-audit-dev-secret"
    AUDIT_LOG_PATH: str = "./logs/audit.log"
    BLOCKED_ORGS: str = ""
    BLOCKED_KEY_IDS: str = ""
    TENET_API_KEYS_JSON: str = ""
    API_KEY: str = "tenet-dev-key-change-in-production"
    
    DEFAULT_ORG_ID: str = "default-org"
    DEFAULT_API_ROLE: str = "admin"
    DEFAULT_RPM_LIMIT: int = 120
    DEFAULT_DAILY_QUOTA: int = 5000
    
    LOG_LEVEL: str = "INFO"
    
    INGEST_URL: str = "http://localhost:8000"
    ANALYZER_URL: str = "http://localhost:8100"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

"""
Demo Cyber-Range configuration.
"""
from functools import lru_cache
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    DEMO_NAME: str = "Predictive Cyber Defence — Demo-2 Live Cyber-Range"
    DEMO_SIMULATION: bool = True

    # Demo API
    DEMO_PREFIX: str = "/api/demo"

    # Database (schema-separated inside the research DB server)
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://cyber_defence:changeme@localhost:5432/cyber_defence"
    )
    DEMO_SCHEMA: str = "demo2"

    # Public base URL used for the QR join code (LAN IP, configured at deploy time)
    DEMO_BASE_URL: str = Field(default="http://localhost:8088")

    # Admin pin
    DEMO_ADMIN_PIN: str = Field(default="2006")

    # Rate limiting
    DEMO_RATE_LIMIT: int = 120

    # World model mount
    ML_ENGINE_PATH: str = "/ml-engine"

    # Heartbeat timeout seconds
    DEMO_HEARTBEAT_TIMEOUT: int = 20

    # Shared domain served by HA server replicas (zero-downtime story)
    DEMO_DOMAIN: str = "app.payg.in"

    # Deception Edge: the real enforcement listeners (production surface,
    # live honeypot, control plane). Best-effort: when unreachable the demo
    # state machine continues unchanged.
    DECEPTION_EDGE_URL: str = "http://demo-2-edge:8099"
    EDGE_SHARED_SECRET: str = "edge-demo-secret"
    EDGE_ENABLED: bool = True

    # Training dataset sink. Mounted as /ml-engine inside the container, so the
    # file persists on the host AND the world-model trainer can read it. Demo
    # runs stay removable (DB truncate); the attack samples accumulate here for
    # the later retrain.
    TRAINING_EXPORT_PATH: str = "/ml-engine/data/demo_training_samples.jsonl"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

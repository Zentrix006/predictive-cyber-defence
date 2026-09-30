"""
Application configuration using Pydantic Settings.
"""
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "Predictive Cyber Defence"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    # Explicit development-only escape hatch. DEBUG alone is never auth.
    DEV_AUTH_BYPASS: bool = False
    LOG_LEVEL: str = "INFO"

    # API
    API_V1_PREFIX: str = "/api/v1"
    OPENAPI_URL: str = "/api/v1/openapi.json"
    DOCS_URL: str = "/api/v1/docs"
    REDOC_URL: str = "/api/v1/redoc"

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://cyber_defence:changeme@localhost:5432/cyber_defence"
    )
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_POOL_TIMEOUT: int = 30

    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    REDIS_MAX_CONNECTIONS: int = 50

    # MinIO / S3
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET: str = "evidence"
    MINIO_SECURE: bool = False

    # JWT
    JWT_SECRET_KEY: str = Field(default="dev-secret-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ELEVATED_TOKEN_EXPIRE_MINUTES: int = 10
    GUEST_TOKEN_EXPIRE_MINUTES: int = 60
    OPERATOR_USERNAME: str = ""
    OPERATOR_PASSWORD_HASH: str = ""

    # API Keys
    API_KEY_HEADER: str = "X-API-Key"

    # CORS
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"]
    )

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 1000
    RATE_LIMIT_WINDOW: int = 60  # seconds

    # ML Model
    ML_MODEL_PATH: str = "/models/world_model.onnx"
    ML_DEVICE: str = "cuda"  # cuda, cpu
    ML_BATCH_SIZE: int = 1
    ML_NUM_WORKERS: int = 2

    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = 30
    WS_MAX_CONNECTIONS_PER_USER: int = 50

    # Network Simulation (for development)
    NETWORK_SIM_ENABLED: bool = False
    NETWORK_SIM_CONFIG: str = ""

    # Network Device Discovery (auto-register devices as they join the network)
    NETWORK_DISCOVERY_ENABLED: bool = False
    NETWORK_DISCOVERY_INTERVAL: float = 60.0  # seconds between scans
    NETWORK_DISCOVERY_TIMEOUT: float = 8.0  # seconds per scan
    NETWORK_DISCOVERY_IFACE: str = ""  # empty = auto-detect interface
    NETWORK_DISCOVERY_SUBNET: str = ""  # empty = auto-derive from interface
    NETWORK_DISCOVERY_MDNS: bool = True  # enable mDNS/DNS-SD service discovery
    # Skip hosts whose IP falls inside these CIDRs (e.g. don't flag our own
    # infrastructure / Docker subnets as newly joined devices).
    NETWORK_DISCOVERY_EXCLUDE: str = ""  # comma-separated CIDRs
    # The main console is telemetry/evidence driven. QR/browser enrollment is
    # reserved for Demo-2 and is disabled on the real project by default.
    MAIN_REAL_TELEMETRY_ONLY: bool = True
    # Dual-Homed Architecture Settings
    MGMT_IFACE: str = "eth0" # Backwards-compatible discovery alias
    CAPTURE_IFACE: str = "eth1" # Backwards-compatible capture alias
    MGMT_SUBNET: str = "172.20.20.0/24"

    # Live dual-homed telemetry plane. Management is used for authenticated
    # device polling/configuration; capture remains passive SPAN/TAP only.
    LIVE_TELEMETRY_ENABLED: bool = False
    LIVE_TELEMETRY_POLL_SECONDS: float = 1.0
    LIVE_TELEMETRY_WINDOW_SECONDS: float = 5.0
    LIVE_TELEMETRY_BUFFER_CAPACITY: int = 10000
    LIVE_TELEMETRY_MAX_API_RECORDS: int = 1000
    LIVE_TELEMETRY_STALE_SECONDS: float = 30.0
    # Inventory/model graph consumption is fail-closed. Production telemetry
    # must be explicitly scoped and sourced; mounted lab logs are inspection-only.
    LIVE_TELEMETRY_PROFILE: str = "lab"
    LIVE_TELEMETRY_APPROVED_CIDRS: str = ""
    LIVE_TELEMETRY_APPROVED_SOURCE_IDS: str = ""
    TELEMETRY_MGMT_IFACE: str = "eth0"
    TELEMETRY_MGMT_VLAN: int = 40
    TELEMETRY_MGMT_CIDR: str = "172.20.20.0/24"
    TELEMETRY_MGMT_GATEWAY: str = ""
    TELEMETRY_CAPTURE_IFACE: str = "eth1"
    TELEMETRY_CAPTURE_MODE: str = "span_tap"
    FLOW_EXPORT_ENABLED: bool = False
    FLOW_EXPORT_LISTEN_ADDR: str = "0.0.0.0"
    FLOW_EXPORT_LISTEN_PORT: int = 2055
    FLOW_EXPORT_ALLOWED_CIDRS: str = ""

    # Read-only mounted Zeek/flow telemetry directory. The collector remains
    # outside the API process; this path is only used for bounded access to
    # the latest captured records and must be mounted read-only in production.
    LIVE_TELEMETRY_DIR: str = "/lab-telemetry"

    # Immutable filesystem evidence bundles. Live sensor artifacts and
    # operator-preserved passive investigations are kept in separate roots.
    EVIDENCE_ROOT: str = "/evidence"

    # Feature Flags
    FEATURE_DECEPTION: bool = True
    FEATURE_FORENSICS: bool = True
    FEATURE_CONFIG_SNAPSHOTS: bool = True

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | List[str]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

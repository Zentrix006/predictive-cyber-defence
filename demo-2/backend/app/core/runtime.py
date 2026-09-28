"""Demo runtime configuration loaded from config/demo.yaml.

Only the guardrail configuration is kept: the safe challenge bank and the decoy
interview questions. Assets, infrastructure, topology and scenarios are no
longer pre-seeded — devices appear dynamically as they register and heartbeat,
and the network is derived from live demo-schema state.
"""
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import yaml

from app.core.config import settings


@lru_cache
def load_demo_config() -> Dict[str, Any]:
    path = Path(__file__).resolve().parents[2] / "config" / "demo.yaml"
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def demo() -> Dict[str, Any]:
    return load_demo_config()["demo"]


def challenges() -> List[Dict[str, Any]]:
    return load_demo_config()["challenges"]


def decoy_questions() -> List[Dict[str, Any]]:
    return load_demo_config()["decoy_questions"]


def base_url() -> str:
    return settings.DEMO_BASE_URL.rstrip("/")
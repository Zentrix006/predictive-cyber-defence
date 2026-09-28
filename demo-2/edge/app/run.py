"""Deception Edge launcher: three real uvicorn listeners in one process.

  :8090  production surface (real 403 enforcement for blocked attacker IPs)
  :8091  live honeypot decoy (real HTTP service, hit logging)
  :8099  control plane (/internal/*, /healthz)

The range backend stays the source of truth; this process only enforces and
records on the wire.
"""
from __future__ import annotations

import asyncio
import logging

import uvicorn

from app.main import control, honeypot, production

log = logging.getLogger("edge")
logging.basicConfig(level=logging.INFO)


class _App:
    """uvicorn Server wrapper that reports completion through an event."""

    def __init__(self, app, host: str, port: int, name: str):
        config = uvicorn.Config(app, host=host, port=port, log_level="warning",
                                access_log=False)
        self.server = uvicorn.Server(config)
        self.name = name

    async def serve(self) -> None:
        try:
            await self.server.serve()
        except Exception:
            log.exception("listener %s died", self.name)


async def main() -> None:
    host = "0.0.0.0"
    listeners = [
        _App(control, host, 8099, "control:8099"),
        _App(production, host, 8090, "production:8090"),
        _App(honeypot, host, 8091, "honeypot:8091"),
    ]
    await asyncio.gather(*(l.serve() for l in listeners))


if __name__ == "__main__":
    asyncio.run(main())

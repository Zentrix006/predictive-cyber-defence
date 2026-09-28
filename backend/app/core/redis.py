"""
Redis connection pool and utilities.
"""
import json
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional

import redis.asyncio as redis
from redis.asyncio import Redis

from app.core.config import settings


class RedisManager:
    def __init__(self):
        self._pool: Optional[redis.ConnectionPool] = None
        self._client: Optional[Redis] = None

    async def initialize(self) -> None:
        self._pool = redis.ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            decode_responses=True,
        )
        self._client = redis.Redis(connection_pool=self._pool)

    async def close(self) -> None:
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()

    @property
    def client(self) -> Redis:
        if not self._client:
            raise RuntimeError("Redis not initialized. Call initialize() first.")
        return self._client

    async def get_json(self, key: str) -> Optional[Any]:
        data = await self.client.get(key)
        if data:
            return json.loads(data)
        return None

    async def set_json(
        self, key: str, value: Any, expire: Optional[int] = None
    ) -> bool:
        return await self.client.set(key, json.dumps(value), ex=expire)

    async def delete(self, key: str) -> int:
        return await self.client.delete(key)

    async def exists(self, key: str) -> bool:
        return await self.client.exists(key) > 0

    async def publish(self, channel: str, message: Any) -> int:
        return await self.client.publish(channel, json.dumps(message))

    async def subscribe(self, *channels: str) -> redis.client.PubSub:
        pubsub = self.client.pubsub()
        await pubsub.subscribe(*channels)
        return pubsub


redis_manager = RedisManager()


async def get_redis() -> AsyncGenerator[Redis, None]:
    yield redis_manager.client


@asynccontextmanager
async def get_redis_context() -> AsyncGenerator[Redis, None]:
    yield redis_manager.client
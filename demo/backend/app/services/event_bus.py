"""
Demo event bus.
In-process pub/sub shared across SSE and WebSocket clients. Every event also
persists to the demo schema for forensics/timeline replay.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Dict, List


class EventBus:
    def __init__(self) -> None:
        self._subscribers: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._subscribers.append(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue) -> None:
        async with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def make_event(self, kind: str, payload: Dict, source: str = "system",
                   incident_id: str | None = None) -> Dict:
        return {
            "event_id": uuid.uuid4().hex[:12],
            "kind": kind,
            "timestamp": datetime.utcnow().isoformat(sep=" ", timespec="seconds"),
            "incident_id": incident_id,
            "simulation": True,
            "source": source,
            "payload": payload,
        }

    async def emit(self, kind: str, payload: Dict, source: str = "system",
                   incident_id: str | None = None) -> Dict:
        event = self.make_event(kind, payload, source, incident_id)
        async with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                if q.full():
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass
        return event


bus = EventBus()
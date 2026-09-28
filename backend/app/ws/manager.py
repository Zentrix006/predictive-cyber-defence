"""
WebSocket Manager
"""
import json
import asyncio
from typing import Dict, Set, List, Optional
from uuid import UUID
from fastapi import WebSocket
from collections import defaultdict


class ConnectionManager:
    """Manages WebSocket connections and event broadcasting."""
    
    def __init__(self):
        # incident_id -> set of WebSocket connections
        self.incident_connections: Dict[Optional[UUID], Set[WebSocket]] = defaultdict(set)
        # WebSocket -> incident_id mapping for cleanup
        self.connection_incident: Dict[WebSocket, Optional[UUID]] = {}
        # Event subscriptions: incident_id -> event_type -> set of WebSockets
        self.subscriptions: Dict[Optional[UUID], Dict[str, Set[WebSocket]]] = defaultdict(lambda: defaultdict(set))
    
    async def connect(self, websocket: WebSocket, incident_id: Optional[UUID] = None):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.incident_connections[incident_id].add(websocket)
        self.connection_incident[websocket] = incident_id
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "incident_id": str(incident_id) if incident_id else None,
            "message": "Connected to Predictive Cyber Defence WebSocket"
        })
    
    def disconnect(self, websocket: WebSocket, incident_id: Optional[UUID] = None):
        """Remove a WebSocket connection."""
        if incident_id is None:
            incident_id = self.connection_incident.get(websocket)
        
        if incident_id in self.incident_connections:
            self.incident_connections[incident_id].discard(websocket)
            if not self.incident_connections[incident_id]:
                del self.incident_connections[incident_id]
        
        # Remove from subscriptions
        for event_type, connections in self.subscriptions[incident_id].items():
            connections.discard(websocket)
        
        self.connection_incident.pop(websocket, None)
    
    async def subscribe(self, websocket: WebSocket, event_types: List[str], incident_id: Optional[UUID] = None):
        """Subscribe a connection to specific event types."""
        if incident_id is None:
            incident_id = self.connection_incident.get(websocket)
        
        for event_type in event_types:
            self.subscriptions[incident_id][event_type].add(websocket)
        
        await websocket.send_json({
            "type": "subscribed",
            "event_types": event_types,
            "incident_id": str(incident_id) if incident_id else None,
        })
    
    async def broadcast(
        self,
        event_type: str,
        payload: dict,
        incident_id: Optional[UUID] = None,
        exclude: Optional[WebSocket] = None,
    ):
        """Broadcast an event to all subscribed connections."""
        message = {
            "event": event_type,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "incident_id": str(incident_id) if incident_id else None,
            "payload": payload,
        }
        
        # Send to specific incident connections
        if incident_id and incident_id in self.subscriptions:
            connections = self.subscriptions[incident_id].get(event_type, set())
            await self._send_to_connections(connections, message, exclude)
        
        # Also send to global connections (incident_id = None)
        if None in self.subscriptions:
            connections = self.subscriptions[None].get(event_type, set())
            await self._send_to_connections(connections, message, exclude)
    
    async def _send_to_connections(
        self,
        connections: Set[WebSocket],
        message: dict,
        exclude: Optional[WebSocket] = None,
    ):
        """Send message to a set of connections."""
        dead_connections = set()
        for ws in connections:
            if ws == exclude:
                continue
            try:
                await ws.send_json(message)
            except Exception:
                dead_connections.add(ws)
        
        # Clean up dead connections
        for ws in dead_connections:
            self.disconnect(ws)
    
    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send message to a specific connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            self.disconnect(websocket)
    
    async def start(self):
        """Start background tasks."""
        pass
    
    async def stop(self):
        """Stop and close all connections."""
        for connections in self.incident_connections.values():
            for ws in connections:
                try:
                    await ws.close()
                except Exception:
                    pass
        self.incident_connections.clear()
        self.connection_incident.clear()
        self.subscriptions.clear()


# Import datetime
from datetime import datetime

# Global instance
ws_manager = ConnectionManager()
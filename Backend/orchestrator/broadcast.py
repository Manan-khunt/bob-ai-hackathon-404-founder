"""
WebSocket Fan-Out Hub for IMMUNE-NET.
Provides thread-safe async registration and message broadcasting for agent sockets and HUD clients.
"""

import asyncio
import json
import logging
from typing import Set, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger("orchestrator.broadcast")


class WebSocketHub:
    """Async connection manager for broadcasting JSON payloads to active WebSocket clients."""

    def __init__(self):
        self.clients: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def register(self, websocket: WebSocket) -> None:
        """
        Accept and register a new WebSocket connection into the broadcasting pool.

        Args:
            websocket: FastAPI WebSocket instance.
        """
        await websocket.accept()
        async with self._lock:
            self.clients.add(websocket)
        logger.info(f"WebSocket client registered in hub. Total active: {len(self.clients)}")

    async def unregister(self, websocket: WebSocket) -> None:
        """
        Remove a WebSocket connection from the broadcasting pool.

        Args:
            websocket: FastAPI WebSocket instance.
        """
        async with self._lock:
            self.clients.discard(websocket)
        logger.info(f"WebSocket client unregistered from hub. Remaining: {len(self.clients)}")

    async def broadcast(self, payload: Dict[str, Any]) -> None:
        """
        Broadcast a JSON payload to all connected clients, pruning stale sockets.

        Args:
            payload: Python dictionary serialized to JSON text.
        """
        message = json.dumps(payload)
        async with self._lock:
            clients = list(self.clients)
        dead = []
        for client in clients:
            try:
                await client.send_text(message)
            except Exception:
                dead.append(client)
        for client in dead:
            await self.unregister(client)

"""
bounty.ui.sse — Server-Sent Events manager for the UI layer.

Maintains a list of per-connection asyncio queues.  A single background
task subscribes to ``bounty.events.bus`` and fans events out to every
connected browser.  Heartbeats keep the HTTP connection alive.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

from bounty import get_logger

log = get_logger(__name__)

_HEARTBEAT_INTERVAL = 30.0  # seconds


class SSEManager:
    """Fan-out SSE to all active browser connections."""

    def __init__(self) -> None:
        self._queues: list[asyncio.Queue[dict[str, Any] | None]] = []

    def _add_queue(self) -> asyncio.Queue[dict[str, Any] | None]:
        q: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=256)
        self._queues.append(q)
        log.debug("sse_client_connected", total=len(self._queues))
        return q

    def _remove_queue(self, q: asyncio.Queue[dict[str, Any] | None]) -> None:
        try:
            self._queues.remove(q)
        except ValueError:
            pass
        log.debug("sse_client_disconnected", total=len(self._queues))

    async def broadcast(self, event_name: str, data: dict[str, Any]) -> None:
        """Push an event to all connected clients."""
        msg: dict[str, Any] = {"event": event_name, "data": data}
        dead: list[asyncio.Queue[dict[str, Any] | None]] = []
        for q in list(self._queues):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._remove_queue(q)

    async def stream(
        self,
        scan_id: str | None = None,
    ) -> AsyncIterator[str]:
        """Async generator yielding SSE-formatted strings for one client."""
        q = self._add_queue()
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=_HEARTBEAT_INTERVAL)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
                    continue

                if msg is None:
                    break

                if scan_id is not None:
                    event_data: Any = msg.get("data", {})
                    if isinstance(event_data, dict) and event_data.get("scan_id") != scan_id:
                        continue

                event_name: str = str(msg.get("event", "message"))
                data_str: str = json.dumps(msg.get("data", {}))
                yield f"event: {event_name}\ndata: {data_str}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            self._remove_queue(q)

    async def event_relay(self) -> None:
        """Long-running task: relay event bus events to all SSE clients."""
        from bounty.events import bus

        try:
            async for event in bus.subscribe():
                await self.broadcast(
                    event.event_type,
                    {"event_type": event.event_type, **event.data},
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("sse_relay_error")

    def shutdown(self) -> None:
        """Push None sentinels to all queues so stream() generators exit."""
        for q in list(self._queues):
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                pass
        self._queues.clear()


# Module-level singleton
sse_manager: SSEManager = SSEManager()


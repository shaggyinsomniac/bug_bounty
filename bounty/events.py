"""
bounty.events — In-process asyncio pub/sub for SSE event multiplexing.

Design decisions:
- A single global ``EventBus`` instance is used; it is safe to import and
  use anywhere in the application without passing it through DI.
- Subscribers receive events via ``asyncio.Queue`` so they are decoupled
  from the publisher and backpressure is handled gracefully.
- ``subscribe()`` is an async generator that yields ``SSEEvent`` objects; the
  SSE route iterates it directly.
- Subscriptions are cleaned up automatically when ``subscribe()`` exits
  (normal return, ``GeneratorExit``, or exception).
- Filtering by ``event_type`` is supported at subscription time to avoid
  unnecessary work in busy consumers.
- Max queue depth per subscriber is 256 events; on overflow the oldest event
  is silently dropped to prevent slow consumers from stalling the bus.

Event type catalogue (from ui-spec.md):

  scan:started       — scan job picked up by the engine
  scan:phase         — a scan phase (recon/detect/…) changed state
  scan:completed     — scan finished (success or failure)
  finding:new        — a new finding was persisted
  finding:updated    — an existing finding's status changed
  secret:discovered  — a credential pattern matched in a response
  secret:validated   — a credential was validated (live/invalid/revoked)
  asset:new          — a new asset was discovered
  asset:updated      — an existing asset's properties changed
  queue:depth        — current job queue depth (polled periodically)
  log:line           — a single structured log line for the live log view
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from bounty import get_logger
from bounty.models import SSEEvent

log = get_logger(__name__)

# Maximum number of undelivered events buffered per subscriber before the
# oldest event is dropped.
_QUEUE_MAX = 256


class EventBus:
    """Lightweight in-process publish / subscribe bus.

    Thread-safety note: ``publish()`` uses ``call_soon_threadsafe`` when
    called from a non-asyncio thread (e.g. APScheduler background jobs).
    """

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[SSEEvent | None]] = []
        self._lock: asyncio.Lock | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def _get_lock(self) -> asyncio.Lock:
        """Return (or lazily create) the asyncio.Lock for this bus.

        Created on first access inside a running event loop to avoid the
        Python 3.12+ RuntimeError from instantiating asyncio primitives at
        module import time (before any event loop exists).
        """
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Return the running event loop, caching the first observed loop."""
        loop = asyncio.get_event_loop()
        if self._loop is None:
            self._loop = loop
        return loop

    async def publish(self, event: SSEEvent) -> None:
        """Publish an event to all current subscribers.

        If a subscriber queue is full, the oldest item is discarded to make
        room, and a warning is logged.

        Args:
            event: The ``SSEEvent`` to broadcast.
        """
        async with self._get_lock:
            dead: list[asyncio.Queue[SSEEvent | None]] = []
            for q in self._subscribers:
                if q.full():
                    try:
                        q.get_nowait()  # drop oldest
                    except asyncio.QueueEmpty:
                        pass
                    log.warning(
                        "sse_queue_overflow_dropped_oldest",
                        event_type=event.event_type,
                    )
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    def publish_sync(self, event: SSEEvent) -> None:
        """Thread-safe variant for publishing from non-async code.

        Uses ``call_soon_threadsafe`` if a loop is running, otherwise falls
        back to creating a new event loop (only safe during tests / CLI).

        Args:
            event: The ``SSEEvent`` to broadcast.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — run synchronously (dev / CLI context).
            asyncio.run(self.publish(event))
            return

        loop.call_soon_threadsafe(
            lambda: asyncio.create_task(self.publish(event))
        )

    async def subscribe(
        self,
        event_types: set[str] | None = None,
    ) -> AsyncIterator[SSEEvent]:
        """Async generator that yields events for one SSE connection.

        The subscription is removed when the generator is closed (the client
        disconnects).

        Args:
            event_types: Optional whitelist of ``event_type`` strings.  If
                ``None``, all events are delivered.

        Yields:
            ``SSEEvent`` instances as they are published.
        """
        q: asyncio.Queue[SSEEvent | None] = asyncio.Queue(maxsize=_QUEUE_MAX)
        async with self._get_lock:
            self._subscribers.append(q)
        log.debug("sse_subscriber_added", total=len(self._subscribers))
        try:
            while True:
                event = await q.get()
                if event is None:
                    # Sentinel: bus is shutting down.
                    break
                if event_types is None or event.event_type in event_types:
                    yield event
        finally:
            async with self._get_lock:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass
            log.debug("sse_subscriber_removed", total=len(self._subscribers))

    async def shutdown(self) -> None:
        """Signal all subscribers to exit by pushing ``None`` sentinels."""
        async with self._get_lock:
            for q in self._subscribers:
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
            self._subscribers.clear()


# ---------------------------------------------------------------------------
# Module-level singleton — import and use directly.
# ---------------------------------------------------------------------------

bus: EventBus = EventBus()


async def publish(event_type: str, data: dict[str, Any], **kwargs: Any) -> None:
    """Convenience wrapper for ``bus.publish()``.

    Args:
        event_type: One of the event type strings from the catalogue above.
        data: JSON-serialisable payload dict.
        **kwargs: Additional fields passed to ``SSEEvent`` (e.g. ``scan_id``).
    """
    await bus.publish(SSEEvent(event_type=event_type, data=data, **kwargs))


async def subscribe(
    event_types: set[str] | None = None,
) -> AsyncIterator[SSEEvent]:
    """Convenience wrapper for ``bus.subscribe()``.

    Args:
        event_types: Optional filter set of event type strings.

    Yields:
        ``SSEEvent`` instances.
    """
    async for event in bus.subscribe(event_types=event_types):
        yield event


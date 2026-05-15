"""
bounty.integrations._base — Abstract base class for notification integrations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Notifier(ABC):
    """Abstract notifier that all integration backends must implement."""

    @abstractmethod
    async def notify(self, event_name: str, payload: dict[str, object]) -> None:
        """Send a notification for the given event.

        Args:
            event_name: The event type string (e.g. ``"finding:new"``).
            payload: The SSE event data dict.
        """
        ...


"""
bounty.ui.routes.sse_routes — /sse/* streaming endpoints.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from bounty.ui.deps import ApiAuthDep
from bounty.ui.sse import sse_manager

router = APIRouter(prefix="/sse", tags=["sse"])


@router.get("/events")
async def sse_all_events(
    request: Request,
    _auth: ApiAuthDep,
) -> StreamingResponse:
    """Main event stream — all events for the connected browser."""

    async def _generate() -> AsyncGenerator[str, None]:
        async for chunk in sse_manager.stream():
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scan/{scan_id}")
async def sse_scan_events(
    scan_id: str,
    request: Request,
    _auth: ApiAuthDep,
) -> StreamingResponse:
    """Event stream scoped to a single scan."""

    async def _generate() -> AsyncGenerator[str, None]:
        async for chunk in sse_manager.stream(scan_id=scan_id):
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


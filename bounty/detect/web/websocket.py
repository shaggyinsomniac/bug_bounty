from __future__ import annotations
from typing import ClassVar
from collections.abc import AsyncGenerator
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["WebSocketEndpointDetected"]

_WS_PATHS = ["/ws", "/websocket", "/socket.io/", "/signalr/", "/graphql-ws"]
_WS_HEADERS = {
    "Upgrade": "websocket",
    "Connection": "Upgrade",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
    "Sec-WebSocket-Version": "13",
}


class WebSocketEndpointDetected(Detection):
    id = "web.websocket.endpoint_detected"
    name = "WebSocket Endpoint Detected"
    category = "websocket"
    severity_default = 100
    cwe = None
    tags: ClassVar[tuple[str, ...]] = ("websocket", "informational")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.scheme in ("http", "https")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        base = asset.url.rstrip("/")
        for path in _WS_PATHS:
            url = base + path
            if ctx.probe_fn_with_headers is not None:
                pr = await ctx.probe_fn_with_headers(url, _WS_HEADERS)
            else:
                pr = await ctx.probe_fn(url)
            if pr.error:
                continue
            if pr.status_code == 101:
                await ctx.capture_evidence(url, pr)
                yield FindingDraft(
                    asset_id=asset.id, scan_id=ctx.scan_id,
                    dedup_key=f"{self.id}:{asset.id}:{path}",
                    title=f"WebSocket endpoint at {asset.host}{path}",
                    category=self.category, severity=self.severity_default,
                    url=url, path=path,
                    description=(
                        f"WebSocket endpoint at {path} accepted the Upgrade handshake "
                        "(HTTP 101). Review for authentication and input validation."
                    ),
                    remediation=(
                        "Ensure WebSocket endpoints require authentication and validate "
                        "Origin headers to prevent cross-site WebSocket hijacking."
                    ),
                    cwe=self.cwe, tags=list(self.tags),
                )
                return

"""
bounty.recon.banner_grab — Async raw TCP banner-grab for non-HTTP services.

Used by network_services detections to identify exposed database and cache
services that don't speak HTTP. Each grab opens a single TCP connection,
reads the initial banner, optionally sends a probe, reads the response,
and closes the connection. All operations are bounded by a configurable
timeout.
"""

from __future__ import annotations

import asyncio

__all__ = ["grab_banner", "BannerResult"]

_DEFAULT_TIMEOUT_S = 5.0
_MAX_BANNER_BYTES = 4096


class BannerResult:
    """Result of a raw TCP banner grab.

    Attributes:
        host:       Target hostname or IP.
        port:       Target TCP port.
        banner:     Raw bytes received from the server (empty on failure).
        error:      Error message if the connection failed; None on success.
        connected:  True if the TCP connection was established.
    """

    __slots__ = ("host", "port", "banner", "error", "connected")

    def __init__(
        self,
        host: str,
        port: int,
        banner: bytes = b"",
        error: str | None = None,
        connected: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.banner = banner
        self.error = error
        self.connected = connected

    @property
    def ok(self) -> bool:
        """True if the grab succeeded without errors."""
        return self.error is None and self.connected


async def grab_banner(
    host: str,
    port: int,
    *,
    probe: bytes | None = None,
    timeout_s: float = _DEFAULT_TIMEOUT_S,
    max_bytes: int = _MAX_BANNER_BYTES,
) -> BannerResult:
    """Open a TCP connection to *host*:*port* and read the initial banner.

    Args:
        host:       Target hostname or IP address.
        port:       TCP port number.
        probe:      Optional bytes to send before reading the response.
                    If None, only the initial banner is captured.
        timeout_s:  Seconds to wait for connection and data.
        max_bytes:  Maximum banner bytes to capture.

    Returns:
        A :class:`BannerResult` with the raw banner bytes.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        return BannerResult(host, port, error="connection timeout", connected=False)
    except OSError as exc:
        return BannerResult(host, port, error=str(exc), connected=False)

    try:
        banner = b""
        if probe is not None:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=timeout_s)

        # Read up to max_bytes with timeout
        try:
            banner = await asyncio.wait_for(
                reader.read(max_bytes),
                timeout=timeout_s,
            )
        except asyncio.TimeoutError:
            # Some services only respond to a probe — empty banner is not an error
            banner = b""

        return BannerResult(host, port, banner=banner, connected=True)
    except OSError as exc:
        return BannerResult(host, port, error=str(exc), connected=True)
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:  # noqa: BLE001
            pass


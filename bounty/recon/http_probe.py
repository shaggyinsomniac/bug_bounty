"""
bounty.recon.http_probe — Async HTTP probe with rate limiting and TLS capture.

Design decisions:
- Per-target ``asyncio.Semaphore`` enforces ``max_concurrent_per_target``
  across all concurrent callers targeting the same host.
- Uses the ``httpx`` async client with HTTP/2 enabled for efficiency.
- Follows up to 5 redirects, recording the full chain.
- Captures TLS peer certificate metadata (issuer, subject, expiry) via
  ``ssl.SSLSocket.getpeercert()``.
- Body is capped at 2 MB to avoid OOM on large responses; the full body is
  not streamed since we need it in memory for pattern matching.
- Response body bytes AND UTF-8 decoded text are both stored so downstream
  stages can choose what they need.
- All errors are caught and returned as a ``ProbeResult`` with ``error`` set
  so the caller can decide how to handle failures.
- The semaphore map is per-process and per-host (not per-IP) since hosts are
  the unit of rate-limit concern for bug bounty targets.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from bounty import get_logger
from bounty.config import get_settings
from bounty.models import ProbeResult, TLSInfo
from bounty.recon.stealth import get_rotating_ua, jitter

if TYPE_CHECKING:
    from bounty.recon.rate_manager import AdaptiveRateManager

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level semaphore registry — one entry per (scheme, host, port) key.
# Lock access to the registry itself with a plain asyncio.Lock.
# Both are created lazily (on first use inside a running event loop) to avoid
# Python 3.12+ RuntimeError when asyncio primitives are instantiated at
# module import time before any event loop starts.
# ---------------------------------------------------------------------------

_sem_lock: asyncio.Lock | None = None
_semaphores: dict[str, asyncio.Semaphore] = {}

# Maximum body bytes captured in memory.  Controlled by settings.max_response_bytes.
_MAX_BODY = 5_000_000  # default matches Settings.max_response_bytes

# Maximum redirect hops before giving up.
_MAX_REDIRECTS = 5


def _get_sem_lock() -> asyncio.Lock:
    """Return (or lazily create) the semaphore-registry lock."""
    global _sem_lock
    if _sem_lock is None:
        _sem_lock = asyncio.Lock()
    return _sem_lock


def _host_key(url: str) -> str:
    """Derive a stable host key from a URL for semaphore bucketing.

    Args:
        url: Any HTTP(S) URL.

    Returns:
        A ``scheme:host:port`` string used as a semaphore key.
    """
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}:{parsed.hostname}:{port}"


async def _get_semaphore(url: str) -> asyncio.Semaphore:
    """Return (or create) the per-host concurrency semaphore.

    Args:
        url: Target URL whose host key is used to look up the semaphore.

    Returns:
        The ``asyncio.Semaphore`` for this host.
    """
    key = _host_key(url)
    async with _get_sem_lock():
        if key not in _semaphores:
            limit = get_settings().max_concurrent_per_target
            _semaphores[key] = asyncio.Semaphore(limit)
        return _semaphores[key]


def _extract_tls(ssl_object: ssl.SSLObject | None) -> TLSInfo | None:
    """Extract TLS metadata from an ``ssl.SSLObject``.

    Args:
        ssl_object: The SSL object from the underlying connection, if any.

    Returns:
        A ``TLSInfo`` instance or ``None`` if no TLS was used.
    """
    if ssl_object is None:
        return None
    try:
        from typing import Any  # local to avoid polluting module namespace
        cert: dict[str, Any] = ssl_object.getpeercert() or {}
        subject_dict: dict[str, str] = dict(x[0] for x in cert.get("subject", ()))
        issuer_dict: dict[str, str] = dict(x[0] for x in cert.get("issuer", ()))

        not_after = cert.get("notAfter")

        cipher_info = ssl_object.cipher()
        cipher_name = cipher_info[0] if cipher_info else None

        return TLSInfo(
            issuer=issuer_dict.get("organizationName") or issuer_dict.get("commonName"),
            subject=subject_dict.get("commonName"),
            not_after=str(not_after) if not_after else None,
            protocol=ssl_object.version(),
            cipher=cipher_name,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("tls_extraction_failed", error=str(exc))
        return None


def _build_curl_cmd(request: httpx.Request) -> str:
    """Build a reproducible curl command string for evidence.

    Args:
        request: The ``httpx.Request`` object.

    Returns:
        A shell-escaped curl command string.
    """
    parts = ["curl", "-sSi", "-m", "15"]
    for name, value in request.headers.items():
        if name.lower() in {"host", "user-agent", "accept-encoding"}:
            continue
        parts += ["-H", f"'{name}: {value}'"]
    parts.append(f"'{request.url}'")
    return " ".join(parts)


def _select_proxy(host: str, settings: object) -> str | None:
    """Determine the proxy URL to use for *host*.

    Rotation logic mirrors UA rotation: deterministic per-host selection so
    the same host always routes through the same proxy.

    Args:
        host:     Bare hostname (no scheme/port).
        settings: Application settings object.

    Returns:
        A proxy URL string or ``None`` if no proxy is configured.
    """
    import hashlib as _hashlib

    proxy_rotation_urls: list[str] = getattr(settings, "proxy_rotation_urls", [])
    http_proxy_url: str | None = getattr(settings, "http_proxy_url", None)

    if proxy_rotation_urls:
        digest = int(_hashlib.md5(host.encode(), usedforsecurity=False).hexdigest(), 16)
        return proxy_rotation_urls[digest % len(proxy_rotation_urls)]
    if http_proxy_url:
        return http_proxy_url
    return None


async def probe(
    url: str,
    *,
    timeout: float | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
    verify: bool = True,
    rate_manager: AdaptiveRateManager | None = None,
) -> ProbeResult:
    """Probe a single URL and return a structured result.

    Respects the per-host concurrency semaphore.  Captures the full response
    body up to 2 MiB, all response headers, TLS metadata, and the redirect
    chain.

    Args:
        url: The HTTP(S) URL to probe.
        timeout: Per-request timeout in seconds.  Defaults to
                 ``settings.http_timeout``.
        headers: Extra request headers to send (merged with defaults).
        follow_redirects: Whether to follow HTTP redirects.  Defaults to
                          ``True``.
        verify: Whether to verify TLS certificates.  Set to ``False`` to
                probe self-signed hosts.  Defaults to ``True``.
        rate_manager: Optional :class:`AdaptiveRateManager` instance.  When
                      supplied, the probe applies per-host jitter delays,
                      records each response for adaptive back-off, and skips
                      the request entirely if the host is already blocked.

    Returns:
        A ``ProbeResult`` — always returned, never raises.  Check ``.ok``
        or ``.error`` to determine success.
    """
    settings = get_settings()
    effective_timeout = timeout if timeout is not None else settings.http_timeout

    parsed = urlparse(url)
    host = parsed.hostname or url

    # ── Blocked-host guard ────────────────────────────────────────────────────
    if rate_manager is not None and rate_manager.is_blocked(host):
        log.warning("probe_skipped_host_blocked", url=url, host=host)
        return _error_result(url, f"Host {host} is blocked by rate manager", 0.0)

    # ── Rotating UA ───────────────────────────────────────────────────────────
    # Use a deterministic per-host UA so one host always sees the same browser;
    # different hosts see different UAs.  Falls back to settings.user_agent if
    # stealth module is unavailable.
    effective_ua = get_rotating_ua(host)

    effective_headers = {
        "User-Agent": effective_ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if headers:
        effective_headers.update(headers)

    # ── Pre-request jitter delay ─────────────────────────────────────────────
    if rate_manager is not None and settings.adaptive_rate_enabled:
        base_delay = rate_manager.get_delay(host)
        if base_delay > 0:
            actual_delay = jitter(base_delay) if settings.stealth_jitter_enabled else base_delay
            if actual_delay > 0:
                await asyncio.sleep(actual_delay)
    elif settings.stealth_jitter_enabled:
        # Even without a rate_manager, apply a tiny baseline jitter (0 base = 0 sleep)
        pass

    # ── Proxy selection ───────────────────────────────────────────────────────
    proxy: str | None = _select_proxy(host, settings)

    sem = await _get_semaphore(url)

    async with sem:
        t0 = time.monotonic()
        try:
            client_kwargs: dict[str, object] = dict(
                follow_redirects=follow_redirects,
                max_redirects=_MAX_REDIRECTS,
                timeout=httpx.Timeout(effective_timeout),
                verify=verify,
                http2=True,
                headers=effective_headers,
            )
            if proxy:
                client_kwargs["proxy"] = proxy

            async with httpx.AsyncClient(**client_kwargs) as client:  # type: ignore[arg-type]
                try:
                    async with client.stream("GET", url) as response:
                        # Bounded streaming read — caps memory use at
                        # settings.max_response_bytes (default 5 MB).
                        max_bytes = settings.max_response_bytes
                        body_buf = bytearray()
                        body_truncated = False
                        async for chunk in response.aiter_bytes(chunk_size=65536):
                            body_buf.extend(chunk)
                            if len(body_buf) >= max_bytes:
                                body_truncated = True
                                break
                        body = bytes(body_buf)
                        body_text = body.decode("utf-8", errors="replace")

                        elapsed_ms = (time.monotonic() - t0) * 1000

                        # Build redirect chain from history.
                        redirect_chain = [str(r.url) for r in response.history]

                        # Try to get TLS info from the underlying transport.
                        tls: TLSInfo | None = None
                        try:
                            transport = getattr(client, "_transport", None)
                            ssl_object: ssl.SSLObject | None = None
                            if transport is not None:
                                conn = getattr(transport, "_pool", None)
                                if conn is not None:
                                    for connection in getattr(conn, "_connections", []):
                                        sock = getattr(connection, "_ssl_object", None)
                                        if sock is not None:
                                            ssl_object = sock
                                            break
                            tls = _extract_tls(ssl_object)
                        except Exception:  # noqa: BLE001
                            pass

                        # Attempt to resolve the IP from the transport.
                        ip: str | None = None
                        try:
                            network_stream = response.extensions.get("network_stream")
                            if network_stream is not None:
                                raw_addr = network_stream.get_extra_info("server_addr")
                                if raw_addr:
                                    ip = raw_addr[0]
                        except Exception:  # noqa: BLE001
                            pass

                        # Normalise headers to a flat dict (last-wins for duplicates).
                        flat_headers: dict[str, str] = dict(response.headers)

                        final_url = str(response.url)

                        # ── Post-response rate tracking ───────────────────────
                        if rate_manager is not None and settings.adaptive_rate_enabled:
                            retry_after = flat_headers.get("retry-after") or flat_headers.get("Retry-After")
                            await rate_manager.record_response(
                                host, response.status_code, retry_after
                            )
                            if rate_manager.is_blocked(host):
                                log.warning(
                                    "probe_host_now_blocked",
                                    url=url,
                                    host=host,
                                    status=response.status_code,
                                )

                        log.debug(
                            "probe_ok",
                            url=url,
                            final_url=final_url,
                            status=response.status_code,
                            elapsed_ms=round(elapsed_ms, 1),
                            body_truncated=body_truncated,
                        )
                        return ProbeResult(
                            url=url,
                            final_url=final_url,
                            status_code=response.status_code,
                            headers=flat_headers,
                            body=body,
                            body_text=body_text,
                            redirect_chain=redirect_chain,
                            tls=tls,
                            ip=ip,
                            elapsed_ms=elapsed_ms,
                            body_truncated=body_truncated,
                        )
                except httpx.ProxyError as exc:
                    elapsed_ms = (time.monotonic() - t0) * 1000
                    log.warning("probe_proxy_error", url=url, proxy=proxy, error=str(exc))
                    return _error_result(url, f"Proxy error: {exc}", elapsed_ms)

        except httpx.TooManyRedirects as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000
            log.warning("probe_too_many_redirects", url=url, error=str(exc))
            return _error_result(url, f"Too many redirects: {exc}", elapsed_ms)

        except httpx.TimeoutException as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000
            log.warning("probe_timeout", url=url, error=str(exc))
            return _error_result(url, f"Timeout: {exc}", elapsed_ms)

        except httpx.ConnectError as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000
            log.debug("probe_connect_error", url=url, error=str(exc))
            return _error_result(url, f"Connection error: {exc}", elapsed_ms)

        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.monotonic() - t0) * 1000
            log.warning("probe_error", url=url, error=str(exc), exc_info=True)
            return _error_result(url, str(exc), elapsed_ms)


def _error_result(url: str, error: str, elapsed_ms: float) -> ProbeResult:
    """Construct a failed ``ProbeResult``.

    Args:
        url: The URL that was being probed.
        error: Human-readable error description.
        elapsed_ms: Elapsed time in milliseconds before the error occurred.

    Returns:
        A ``ProbeResult`` with ``status_code=0`` and ``error`` set.
    """
    return ProbeResult(
        url=url,
        final_url=url,
        status_code=0,
        headers={},
        body=b"",
        body_text="",
        redirect_chain=[],
        tls=None,
        ip=None,
        elapsed_ms=elapsed_ms,
        error=error,
    )


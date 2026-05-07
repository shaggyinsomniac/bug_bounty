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
from urllib.parse import urlparse

import httpx

from bounty import get_logger
from bounty.config import get_settings
from bounty.models import ProbeResult, TLSInfo

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level semaphore registry — one entry per (scheme, host, port) key.
# Lock access to the registry itself with a plain asyncio.Lock.
# ---------------------------------------------------------------------------

_sem_lock = asyncio.Lock()
_semaphores: dict[str, asyncio.Semaphore] = {}

# Maximum body bytes captured in memory.
_MAX_BODY = 2 * 1024 * 1024  # 2 MiB

# Maximum redirect hops before giving up.
_MAX_REDIRECTS = 5

# Default user-agent string.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


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
    async with _sem_lock:
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
        cert: dict[str, object] = ssl_object.getpeercert() or {}
        subject_dict = dict(x[0] for x in cert.get("subject", ()))  # type: ignore[arg-type]
        issuer_dict = dict(x[0] for x in cert.get("issuer", ()))  # type: ignore[arg-type]

        not_after = cert.get("notAfter")

        cipher_info = ssl_object.cipher()
        cipher_name = cipher_info[0] if cipher_info else None

        return TLSInfo(
            issuer=issuer_dict.get("organizationName") or issuer_dict.get("commonName"),  # type: ignore[arg-type]
            subject=subject_dict.get("commonName"),  # type: ignore[arg-type]
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


async def probe(
    url: str,
    *,
    timeout: float | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
    verify: bool = True,
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

    Returns:
        A ``ProbeResult`` — always returned, never raises.  Check ``.ok``
        or ``.error`` to determine success.
    """
    settings = get_settings()
    effective_timeout = timeout if timeout is not None else settings.http_timeout
    effective_headers = {
        "User-Agent": _USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if headers:
        effective_headers.update(headers)

    sem = await _get_semaphore(url)

    async with sem:
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(
                follow_redirects=follow_redirects,
                max_redirects=_MAX_REDIRECTS,
                timeout=httpx.Timeout(effective_timeout),
                verify=verify,
                http2=True,
                headers=effective_headers,
            ) as client:
                response = await client.get(url)

                # Capture body up to 2 MiB.
                body = response.content[:_MAX_BODY]
                body_text = body.decode("utf-8", errors="replace")

                elapsed_ms = (time.monotonic() - t0) * 1000

                # Build redirect chain from history.
                redirect_chain = [str(r.url) for r in response.history]

                # Try to get TLS info from the underlying transport.
                tls: TLSInfo | None = None
                try:
                    stream = response.stream
                    # httpx exposes ssl_object via the underlying transport
                    transport = getattr(client, "_transport", None)
                    ssl_object: ssl.SSLObject | None = None
                    if transport is not None:
                        conn = getattr(transport, "_pool", None)
                        if conn is not None:
                            # Attempt to reach the SSL socket — best effort.
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
                    # httpx does not expose the remote IP directly; fall back
                    # to the response extensions if available.
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
                log.debug(
                    "probe_ok",
                    url=url,
                    final_url=final_url,
                    status=response.status_code,
                    elapsed_ms=round(elapsed_ms, 1),
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
                )

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


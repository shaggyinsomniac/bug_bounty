"""
bounty.errors — Centralised error recording for scan visibility (Phase 17).

Classes:
  ErrorRecorder  — per-scan recorder that writes to scan_errors table.

Functions:
  record_error   — Global helper; never raises.

design notes:
- record_error must never itself raise — all exceptions are swallowed and
  structlog'd at warning level.
- Sentry integration is optional: only activated when sentry_dsn is set
  in settings.  sentry-sdk import is guarded with try/except.
- An SSE event ``errors.new`` is emitted on every recorded error so the
  live UI can refresh the error list.
"""

from __future__ import annotations

import traceback as _traceback_mod
from pathlib import Path
from typing import Any

from bounty import get_logger
from bounty.ulid import make_ulid

log = get_logger(__name__)

_VALID_KINDS: frozenset[str] = frozenset({
    "detection",
    "probe",
    "fingerprint",
    "secret_validation",
    "notification",
    "scheduler",
    "queue_worker",
    "nuclei",
    "trufflehog",
    "ai",
    "other",
})


class ErrorRecorder:
    """Per-scan error recorder.

    Args:
        db_path: Path to the SQLite database.
        scan_id: The scan this recorder is bound to.  May be an empty string
                 when errors occur outside a specific scan (e.g. scheduler).
    """

    def __init__(self, db_path: Path, scan_id: str) -> None:
        self._db_path = db_path
        self._scan_id = scan_id

    async def record(
        self,
        kind: str,
        exception: BaseException,
        asset_id: str | None = None,
        detection_id: str | None = None,
    ) -> None:
        """Record an error to the scan_errors table.

        This method never raises.  Any internal error is logged at warning
        level and silently suppressed.

        Args:
            kind: Error category — one of the _VALID_KINDS values.
            exception: The caught exception.
            asset_id: Optional asset ID where the error occurred.
            detection_id: Optional detection ID if kind is ``"detection"``.
        """
        if kind not in _VALID_KINDS:
            kind = "other"

        exc_type = type(exception).__name__
        message = str(exception)
        tb_text = "".join(
            _traceback_mod.format_exception(
                type(exception), exception, exception.__traceback__
            )
        )
        error_id = make_ulid()

        bound = log.bind(
            scan_id=self._scan_id,
            kind=kind,
            exception_type=exc_type,
            asset_id=asset_id,
            detection_id=detection_id,
            error_id=error_id,
        )
        bound.error("scan_error_recorded", message=message[:300])

        # ── DB insert ────────────────────────────────────────────────────────
        try:
            from bounty.db import get_conn

            async with get_conn(self._db_path) as conn:
                await conn.execute(
                    """
                    INSERT INTO scan_errors
                        (id, scan_id, asset_id, detection_id, kind,
                         exception_type, message, traceback, created_at)
                    VALUES (?,?,?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                    """,
                    (
                        error_id,
                        self._scan_id or None,
                        asset_id,
                        detection_id,
                        kind,
                        exc_type,
                        message,
                        tb_text,
                    ),
                )
                await conn.commit()
        except Exception as db_exc:  # noqa: BLE001
            log.warning("record_error_db_failed", error=str(db_exc))

        # ── SSE event ────────────────────────────────────────────────────────
        try:
            from bounty.events import publish

            await publish(
                "errors.new",
                {
                    "kind": kind,
                    "exception_type": exc_type,
                    "message_short": message[:100],
                    "scan_id": self._scan_id,
                    "asset_id": asset_id,
                    "error_id": error_id,
                },
            )
        except Exception as sse_exc:  # noqa: BLE001
            log.warning("record_error_sse_failed", error=str(sse_exc))

        # ── Optional Sentry ──────────────────────────────────────────────────
        _maybe_sentry(kind, self._scan_id, asset_id, detection_id, exception)


def _maybe_sentry(
    kind: str,
    scan_id: str,
    asset_id: str | None,
    detection_id: str | None,
    exception: BaseException,
) -> None:
    """Send to Sentry if DSN is configured.  Never raises."""
    try:
        from bounty.config import get_settings

        settings = get_settings()
        dsn: str | None = getattr(settings, "sentry_dsn", None)
        if not dsn:
            return
        import sentry_sdk  # type: ignore[import-untyped,unused-ignore]

        with sentry_sdk.push_scope() as scope:  # type: ignore[attr-defined,unused-ignore]
            scope.set_tag("kind", kind)
            scope.set_tag("scan_id", scan_id)
            if asset_id:
                scope.set_tag("asset_id", asset_id)
            if detection_id:
                scope.set_tag("detection_id", detection_id)
            sentry_sdk.capture_exception(exception)  # type: ignore[attr-defined,unused-ignore]
    except Exception as sentry_exc:  # noqa: BLE001
        log.warning("record_error_sentry_failed", error=str(sentry_exc))


async def record_error(
    db_path: Path,
    scan_id: str,
    kind: str,
    exception: BaseException,
    **ctx: Any,
) -> None:
    """Global convenience helper.  **Never raises.**

    Args:
        db_path: Path to the SQLite database.
        scan_id: Parent scan ID (may be empty string for non-scan errors).
        kind: Error category (see _VALID_KINDS).
        exception: The caught exception object.
        **ctx: Optional keyword context.  Recognised keys:
            ``asset_id`` (str), ``detection_id`` (str).
    """
    try:
        recorder = ErrorRecorder(db_path=db_path, scan_id=scan_id)
        await recorder.record(
            kind=kind,
            exception=exception,
            asset_id=ctx.get("asset_id"),
            detection_id=ctx.get("detection_id"),
        )
    except Exception as e:  # noqa: BLE001
        log.warning("record_error_outer_failed", error=str(e))


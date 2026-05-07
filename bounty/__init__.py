"""
bounty — bug bounty automation system.

This module configures structlog for the entire application.  All loggers
obtained via ``structlog.get_logger()`` share this configuration.  Logs are
written as JSON lines in production and as colourised key-value pairs in
development (controlled by the ``LOG_FORMAT`` environment variable).
"""

from __future__ import annotations

import logging
import os
import sys

import structlog

__all__ = ["get_logger"]


def _configure_logging() -> None:
    """Set up structlog with sensible defaults.

    Called once at import time.  Subsequent calls are idempotent because
    structlog tracks its own configuration state.

    Design decisions:
    - JSON in production (``LOG_FORMAT=json``) so logs are machine-parsable.
    - Console (pretty) format everywhere else — easier to read during dev.
    - stdlib ``logging`` is bridged so that third-party libraries (uvicorn,
      httpx, APScheduler) emit structured records as well.
    - Log level controlled by ``LOG_LEVEL`` env var (default ``INFO``).
    """
    log_level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    log_format = os.environ.get("LOG_FORMAT", "console").lower()

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if log_format == "json":
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    # Quieten noisy third-party loggers.
    for noisy in ("httpx", "httpcore", "hpack", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


_configure_logging()


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger.

    Args:
        name: Optional logger name (shown in ``logger`` field).  Defaults to
              the calling module name when omitted.

    Returns:
        A structlog ``BoundLogger`` instance.
    """
    return structlog.get_logger(name)  # type: ignore[no-any-return]


"""
Sentinel SOC v2.2 — structured logging and request ID utilities.

Provides JSON-structured logs for production observability and a simple
request-ID propagation mechanism for tracing requests through the backend.
"""
import contextvars
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.config import get_settings

_request_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)


class _RequestIdFilter(logging.Filter):
    """Inject the current request ID into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id.get() or "-"  # type: ignore[attr-defined]
        return True


class _JsonFormatter(logging.Formatter):
    """Format log records as compact JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Include extra fields added via logger.info(..., extra={...})
        for key, value in record.__dict__.items():
            if key not in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "request_id",
            }:
                payload[key] = value
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Configure root logging for the application."""
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicate logs during reloads.
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.addFilter(_RequestIdFilter())

    if settings.log_format.lower() == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s request=%(request_id)s: %(message)s"
            )
        )

    root.addHandler(handler)

    # Quiet down overly chatty third-party loggers.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_request_id() -> Optional[str]:
    """Return the current request ID for this context."""
    return _request_id.get()


def set_request_id(request_id: Optional[str]) -> None:
    """Set the request ID for the current context."""
    _request_id.set(request_id)


def generate_request_id() -> str:
    """Generate a short, URL-safe request ID."""
    import uuid
    return uuid.uuid4().hex[:16]

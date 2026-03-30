"""
Structured logging configuration using structlog.

All agents bind job_id, sample_id, correlation_id, and agent_name
to every log line, producing JSON output suitable for log aggregation.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

import structlog


def _prepare_console_streams() -> None:
    """Best-effort UTF-8 console setup for Windows and legacy terminals."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                # Keep default stream settings if reconfigure is unsupported.
                pass


def configure_logging(
    level: str = "INFO",
    json_output: bool = True,
    log_file: Optional[str] = None,
) -> None:
    """
    Configure structlog + stdlib logging.

    Call once at application startup before agents are initialized.
    """
    _prepare_console_streams()
    log_level = getattr(logging, level.upper(), logging.INFO)

    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
        formatter = structlog.stdlib.ProcessorFormatter(
            processors=processors,
        )
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))
        formatter = structlog.stdlib.ProcessorFormatter(
            processors=processors,
        )

    # stdlib handler (console)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level)

    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = __name__):
    """Return a structlog-bound logger."""
    return structlog.get_logger(name)

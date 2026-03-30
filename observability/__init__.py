"""
Observability package — logging, tracing, and metrics setup.
"""

from .logging_config import configure_logging, get_logger
from .metrics import (
    JOBS_PROCESSED,
    JOBS_ACTIVE,
    AGENT_LATENCY,
    SANDBOX_SUBMITS,
    LLM_CALLS,
    LLM_LATENCY,
    RETRY_COUNT,
    DLQ_COUNT,
    DECISIONS,
    track_agent_duration,
)
from .tracing import configure_tracing, get_tracer

__all__ = [
    "configure_logging",
    "get_logger",
    "configure_tracing",
    "get_tracer",
    "JOBS_PROCESSED",
    "JOBS_ACTIVE",
    "AGENT_LATENCY",
    "SANDBOX_SUBMITS",
    "LLM_CALLS",
    "LLM_LATENCY",
    "RETRY_COUNT",
    "DLQ_COUNT",
    "DECISIONS",
    "track_agent_duration",
]

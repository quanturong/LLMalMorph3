"""
Prometheus metrics registry for the multi-agent pipeline.

All metrics are defined here (single source of truth).
Agents import the metric objects they need from this module.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Optional

from prometheus_client import Counter, Gauge, Histogram, start_http_server

# ──────────────────────────────────────────────────────────────────────────────
# Job metrics
# ──────────────────────────────────────────────────────────────────────────────

JOBS_PROCESSED = Counter(
    "llmalmorph_jobs_total",
    "Total jobs processed",
    ["status"],          # "closed" | "failed" | "escalated"
)

JOBS_ACTIVE = Gauge(
    "llmalmorph_jobs_active",
    "Currently active jobs by state",
    ["state"],
)

# ──────────────────────────────────────────────────────────────────────────────
# Per-agent latency
# ──────────────────────────────────────────────────────────────────────────────

AGENT_LATENCY = Histogram(
    "llmalmorph_agent_duration_seconds",
    "Agent processing duration",
    ["agent_name", "status"],    # status: "success" | "error"
    buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600],
)

# ──────────────────────────────────────────────────────────────────────────────
# Sandbox
# ──────────────────────────────────────────────────────────────────────────────

SANDBOX_SUBMITS = Counter(
    "llmalmorph_sandbox_submits_total",
    "Sandbox submission attempts",
    ["backend", "status"],       # status: "success" | "error"
)

SANDBOX_DURATION = Histogram(
    "llmalmorph_sandbox_duration_seconds",
    "End-to-end sandbox execution duration",
    ["backend"],
    buckets=[10, 30, 60, 120, 180, 300, 600],
)

# ──────────────────────────────────────────────────────────────────────────────
# LLM
# ──────────────────────────────────────────────────────────────────────────────

LLM_CALLS = Counter(
    "llmalmorph_llm_calls_total",
    "LLM API call attempts",
    ["provider", "model", "status"],    # status: "success" | "error" | "cache_hit"
)

LLM_LATENCY = Histogram(
    "llmalmorph_llm_duration_seconds",
    "LLM call latency",
    ["provider", "model"],
    buckets=[0.5, 1, 2, 5, 10, 20, 30, 60],
)

LLM_TOKENS = Counter(
    "llmalmorph_llm_tokens_total",
    "LLM token usage",
    ["provider", "model", "direction"],  # direction: "input" | "output"
)

# ──────────────────────────────────────────────────────────────────────────────
# Retry / DLQ
# ──────────────────────────────────────────────────────────────────────────────

RETRY_COUNT = Counter(
    "llmalmorph_retries_total",
    "Retry attempts by agent and error class",
    ["agent", "error_class"],
)

DLQ_COUNT = Counter(
    "llmalmorph_dlq_total",
    "Messages routed to dead letter queue",
    ["agent"],
)

# ──────────────────────────────────────────────────────────────────────────────
# Decisions
# ──────────────────────────────────────────────────────────────────────────────

DECISIONS = Counter(
    "llmalmorph_decisions_total",
    "Decisions issued by action and source",
    ["action", "source"],
)


# ──────────────────────────────────────────────────────────────────────────────
# Context manager helper
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def track_agent_duration(agent_name: str):
    """
    Async context manager that records agent processing duration.

    Usage:
        async with track_agent_duration("BehaviorAnalysisAgent"):
            await do_work()
    """
    start = time.monotonic()
    status = "success"
    try:
        yield
    except Exception:
        status = "error"
        raise
    finally:
        duration = time.monotonic() - start
        AGENT_LATENCY.labels(agent_name=agent_name, status=status).observe(duration)


def start_metrics_server(port: int = 8000) -> None:
    """Start the Prometheus HTTP metrics endpoint."""
    start_http_server(port)

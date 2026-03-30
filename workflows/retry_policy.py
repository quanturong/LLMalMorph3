"""
Retry policy — error classification and backoff calculation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class ErrorClass(str, Enum):
    TRANSIENT_NETWORK  = "transient_network"
    SANDBOX_BUSY       = "sandbox_busy"
    SANDBOX_TIMEOUT    = "sandbox_timeout"
    LLM_TIMEOUT        = "llm_timeout"
    LLM_BAD_OUTPUT     = "llm_bad_output"
    COMPILE_ERROR      = "compile_error"    # AutoFixer handles its own retry
    PERMANENT_ERROR    = "permanent_error"
    UNKNOWN            = "unknown"


@dataclass
class RetrySpec:
    max_retries: int
    base_delay_s: float
    backoff_factor: float = 2.0
    max_delay_s: float = 480.0

    def delay_for(self, retry_count: int) -> float:
        """Exponential backoff with cap."""
        delay = self.base_delay_s * (self.backoff_factor ** retry_count)
        return min(delay, self.max_delay_s)

    def should_retry(self, current_retry_count: int) -> bool:
        return current_retry_count < self.max_retries


# ──────────────────────────────────────────────────────────────────────────────
# Policy table
# ──────────────────────────────────────────────────────────────────────────────

RETRY_POLICY: Dict[ErrorClass, RetrySpec] = {
    ErrorClass.TRANSIENT_NETWORK: RetrySpec(max_retries=3,  base_delay_s=2.0,  backoff_factor=2.0),
    ErrorClass.SANDBOX_BUSY:      RetrySpec(max_retries=5,  base_delay_s=30.0, backoff_factor=2.0, max_delay_s=480.0),
    ErrorClass.SANDBOX_TIMEOUT:   RetrySpec(max_retries=2,  base_delay_s=60.0, backoff_factor=1.5),
    ErrorClass.LLM_TIMEOUT:       RetrySpec(max_retries=2,  base_delay_s=5.0,  backoff_factor=2.0),
    ErrorClass.LLM_BAD_OUTPUT:    RetrySpec(max_retries=1,  base_delay_s=1.0,  backoff_factor=1.0),
    ErrorClass.COMPILE_ERROR:     RetrySpec(max_retries=0,  base_delay_s=0.0),  # AutoFixer owns this
    ErrorClass.PERMANENT_ERROR:   RetrySpec(max_retries=0,  base_delay_s=0.0),
    ErrorClass.UNKNOWN:           RetrySpec(max_retries=1,  base_delay_s=5.0,  backoff_factor=1.0),
}


# ──────────────────────────────────────────────────────────────────────────────
# Error classifier
# ──────────────────────────────────────────────────────────────────────────────

# error_code → ErrorClass
_ERROR_CODE_MAP: Dict[str, ErrorClass] = {
    # Network / connectivity
    "CONNECTION_ERROR":      ErrorClass.TRANSIENT_NETWORK,
    "NETWORK_TIMEOUT":       ErrorClass.TRANSIENT_NETWORK,
    "HTTP_503":              ErrorClass.TRANSIENT_NETWORK,
    "HTTP_502":              ErrorClass.TRANSIENT_NETWORK,

    # Sandbox
    "SANDBOX_TIMEOUT":       ErrorClass.SANDBOX_TIMEOUT,
    "SANDBOX_BUSY":          ErrorClass.SANDBOX_BUSY,
    "SANDBOX_SUBMIT_FAILED": ErrorClass.TRANSIENT_NETWORK,
    "NO_REPORT":             ErrorClass.SANDBOX_TIMEOUT,
    "SANDBOX_ERROR":         ErrorClass.SANDBOX_BUSY,

    # LLM
    "LLM_TIMEOUT":           ErrorClass.LLM_TIMEOUT,
    "LLM_RATE_LIMIT":        ErrorClass.LLM_TIMEOUT,
    "LLM_BAD_OUTPUT":        ErrorClass.LLM_BAD_OUTPUT,
    "LLM_HALLUCINATION":     ErrorClass.LLM_BAD_OUTPUT,
    "LLM_PARSE_ERROR":       ErrorClass.LLM_BAD_OUTPUT,
    "LLM_GUARDRAIL_FAIL":    ErrorClass.LLM_BAD_OUTPUT,

    # Build
    "COMPILE_ERROR":         ErrorClass.COMPILE_ERROR,
    "LINK_ERROR":            ErrorClass.COMPILE_ERROR,

    # Permanent
    "INVALID_SAMPLE":        ErrorClass.PERMANENT_ERROR,
    "UNSUPPORTED_LANGUAGE":  ErrorClass.PERMANENT_ERROR,
    "MISSING_ARTIFACT":      ErrorClass.PERMANENT_ERROR,
    "POLICY_VIOLATION":      ErrorClass.PERMANENT_ERROR,
}


def classify_error(error_code: str) -> ErrorClass:
    """Map an error code string to an ErrorClass."""
    return _ERROR_CODE_MAP.get(error_code.upper(), ErrorClass.UNKNOWN)


# ──────────────────────────────────────────────────────────────────────────────
# Retry decision
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RetryDecision:
    should_retry: bool
    delay_s: float
    error_class: ErrorClass
    reason: str


def get_retry_decision(
    error_code: str,
    current_retry_count: int,
    job_total_retries: int = 0,
    max_job_retries: int = 10,
) -> RetryDecision:
    """
    Determine whether to retry a failed step, and how long to wait.

    Args:
        error_code:          Error code string (e.g. "SANDBOX_TIMEOUT")
        current_retry_count: How many times THIS step has been retried
        job_total_retries:   Total retries across all steps for this job
        max_job_retries:     Hard cap on total job retries (regardless of step)
    """
    error_class = classify_error(error_code)
    spec = RETRY_POLICY[error_class]

    # Hard cap on total job retries
    if job_total_retries >= max_job_retries:
        return RetryDecision(
            should_retry=False,
            delay_s=0.0,
            error_class=error_class,
            reason=f"Job retry budget exhausted ({job_total_retries}/{max_job_retries})",
        )

    if not spec.should_retry(current_retry_count):
        return RetryDecision(
            should_retry=False,
            delay_s=0.0,
            error_class=error_class,
            reason=f"Step retry limit reached ({current_retry_count}/{spec.max_retries})",
        )

    delay = spec.delay_for(current_retry_count)
    return RetryDecision(
        should_retry=True,
        delay_s=delay,
        error_class=error_class,
        reason=f"Retry {current_retry_count + 1}/{spec.max_retries} after {delay:.0f}s",
    )

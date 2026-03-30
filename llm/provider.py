"""
Core LLM provider interface and shared data models.

All concrete providers (Mistral, Ollama, DeepSeek, Hybrid) implement
LLMProviderInterface. The CachingLLMProvider decorator wraps any provider.
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import time
from typing import Any, Callable, Optional, Type, TypeVar

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


# ──────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ──────────────────────────────────────────────────────────────────────────────

class LLMRequest(BaseModel):
    system_prompt: str
    user_prompt: str
    model: Optional[str] = None          # None → provider default
    temperature: float = 0.1
    max_tokens: int = 2048
    response_format: str = "json_object"  # enforce JSON output when supported
    seed: Optional[int] = None
    timeout_s: int = 60


class LLMResponse(BaseModel):
    content: str
    model_used: str
    provider: str
    latency_s: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cached: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────────────────────────────────────

class LLMError(Exception):
    """Base LLM error."""


class LLMTimeoutError(LLMError):
    """LLM call exceeded timeout."""


class LLMRateLimitError(LLMError):
    """Provider rate limit hit."""


class LLMStructuredOutputError(LLMError):
    """LLM returned output that could not be parsed into the expected schema."""
    def __init__(self, message: str, raw_output: str = ""):
        super().__init__(message)
        self.raw_output = raw_output


# ──────────────────────────────────────────────────────────────────────────────
# Abstract interface
# ──────────────────────────────────────────────────────────────────────────────

class LLMProviderInterface(abc.ABC):

    @abc.abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate a text completion."""

    async def generate_structured(
        self,
        request: LLMRequest,
        output_schema: Type[T],
        validator: Optional[Callable[[T], None]] = None,
        fallback_fn: Optional[Callable[[], T]] = None,
    ) -> T:
        """
        Generate + parse + validate structured output.

        1. Call generate()
        2. Parse response as JSON into output_schema (Pydantic model)
        3. Run optional validator callable
        4. On any failure: call fallback_fn or raise LLMStructuredOutputError

        Args:
            request:       LLM request (should use temperature ≤ 0.2 for structured)
            output_schema: Pydantic model class to parse into
            validator:     Optional callable(parsed) that raises ValueError if invalid
            fallback_fn:   If provided, called on parse/validation failure instead of raising
        """
        response = await self.generate(request)
        raw = response.content.strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(
                line for line in lines
                if not line.strip().startswith("```")
            )

        try:
            parsed = output_schema.model_validate_json(raw)
        except Exception as parse_err:
            logger.warning(
                "Failed to parse LLM output into %s: %s\nRaw: %.300s",
                output_schema.__name__, parse_err, raw,
            )
            if fallback_fn is not None:
                return fallback_fn()
            raise LLMStructuredOutputError(
                f"Failed to parse LLM output into {output_schema.__name__}: {parse_err}",
                raw_output=raw,
            )

        if validator is not None:
            try:
                validator(parsed)
            except (ValueError, AssertionError) as val_err:
                logger.warning(
                    "LLM output validation failed for %s: %s",
                    output_schema.__name__, val_err,
                )
                if fallback_fn is not None:
                    return fallback_fn()
                raise LLMStructuredOutputError(
                    f"LLM output failed validation: {val_err}",
                    raw_output=raw,
                )

        return parsed


# ──────────────────────────────────────────────────────────────────────────────
# Caching decorator
# ──────────────────────────────────────────────────────────────────────────────

class CachingLLMProvider(LLMProviderInterface):
    """
    Wraps any LLMProviderInterface with a Redis-backed response cache.

    Cache key is SHA-256 of (system_prompt + user_prompt + model string).
    LLM responses for identical prompts are not re-generated until TTL expires.
    Useful for analysis runs that repeatedly analyze very similar reports.
    """

    def __init__(
        self,
        inner: LLMProviderInterface,
        redis_client: Any,          # redis.asyncio.Redis
        ttl_s: int = 3600,
        enabled: bool = True,
    ) -> None:
        self._inner = inner
        self._redis = redis_client
        self._ttl_s = ttl_s
        self._enabled = enabled

    def _cache_key(self, request: LLMRequest) -> str:
        raw = f"{request.system_prompt}|{request.user_prompt}|{request.model or ''}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return f"llmcache:{digest}"

    async def generate(self, request: LLMRequest) -> LLMResponse:
        if self._enabled and self._redis is not None:
            key = self._cache_key(request)
            cached_raw = await self._redis.get(key)
            if cached_raw:
                resp = LLMResponse.model_validate_json(cached_raw)
                resp.cached = True
                logger.debug("LLM cache hit for key prefix %.12s…", key[9:])
                return resp

        start = time.monotonic()
        response = await self._inner.generate(request)
        response.latency_s = time.monotonic() - start

        if self._enabled and self._redis is not None:
            key = self._cache_key(request)
            await self._redis.setex(key, self._ttl_s, response.model_dump_json())

        return response

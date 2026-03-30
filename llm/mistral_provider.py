"""
Async wrapper around the existing src/llm_api.py MistralAPIProvider.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from .provider import (
    LLMError,
    LLMRateLimitError,
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
    LLMProviderInterface,
)

logger = logging.getLogger(__name__)


class MistralProvider(LLMProviderInterface):
    """
    Async provider wrapping the synchronous MistralAPIProvider in src/llm_api.py.
    Runs the blocking call in a thread pool to avoid blocking the event loop.
    """

    def __init__(self, api_key: Optional[str] = None, default_model: str = "codestral-latest") -> None:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from llm_api import MistralAPIProvider as _Mistral, LLMAPIKeyError, LLMAPIRequestError

        self._sync_provider = _Mistral(api_key=api_key)
        self._default_model = default_model
        self._key_error_cls = LLMAPIKeyError
        self._req_error_cls = LLMAPIRequestError

    async def generate(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self._default_model
        loop = asyncio.get_running_loop()
        start = time.monotonic()

        try:
            content = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: self._sync_provider.generate(
                        system_prompt=request.system_prompt,
                        user_prompt=request.user_prompt,
                        model=model,
                        temperature=request.temperature,
                        seed=request.seed,
                        timeout=request.timeout_s,
                    ),
                ),
                timeout=request.timeout_s + 5,
            )
        except asyncio.TimeoutError:
            raise LLMTimeoutError(f"Mistral call timed out after {request.timeout_s}s")
        except Exception as exc:
            if "rate limit" in str(exc).lower():
                raise LLMRateLimitError(str(exc))
            raise LLMError(str(exc))

        return LLMResponse(
            content=content,
            model_used=model,
            provider="mistral",
            latency_s=time.monotonic() - start,
        )

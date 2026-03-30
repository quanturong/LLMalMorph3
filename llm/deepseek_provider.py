"""
Async wrapper for DeepSeek API (OpenAI-compatible endpoint).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

import requests

from .provider import (
    LLMError,
    LLMRateLimitError,
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
    LLMProviderInterface,
)

logger = logging.getLogger(__name__)

_DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1/chat/completions"


class DeepSeekProvider(LLMProviderInterface):
    """
    Async DeepSeek provider using the OpenAI-compatible chat completions API.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: str = "deepseek-chat",
    ) -> None:
        import os
        self._api_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        self._default_model = default_model
        if not self._api_key:
            logger.warning("DEEPSEEK_API_KEY not set; DeepSeekProvider will fail at runtime.")

    def _sync_call(self, request: LLMRequest, model: str) -> LLMResponse:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        body: dict = {
            "model": model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user",   "content": request.user_prompt},
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.response_format == "json_object":
            body["response_format"] = {"type": "json_object"}

        start = time.monotonic()
        try:
            resp = requests.post(
                _DEEPSEEK_BASE_URL, headers=headers, json=body,
                timeout=request.timeout_s,
            )
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            raise LLMTimeoutError(f"DeepSeek timed out after {request.timeout_s}s")
        except requests.exceptions.HTTPError as exc:
            code = getattr(exc.response, "status_code", None)
            if code == 429:
                raise LLMRateLimitError("DeepSeek rate limit exceeded")
            raise LLMError(f"DeepSeek HTTP {code}: {exc.response.text[:200]}")

        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return LLMResponse(
            content=content,
            model_used=model,
            provider="deepseek",
            latency_s=time.monotonic() - start,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )

    async def generate(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self._default_model
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, self._sync_call, request, model),
            timeout=request.timeout_s + 5,
        )

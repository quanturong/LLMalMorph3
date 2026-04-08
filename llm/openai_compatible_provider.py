"""
Async wrapper for OpenAI-compatible chat-completions endpoints.

Use this provider for hosted inference services such as RunPod OpenAI API
endpoints while keeping the same request/response contract used by the
framework's other LLM providers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import requests

from .provider import (
    LLMError,
    LLMRateLimitError,
    LLMProviderInterface,
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
)

logger = logging.getLogger(__name__)


class OpenAICompatibleProvider(LLMProviderInterface):
    """Generic provider for OpenAI-compatible `/chat/completions` APIs."""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        default_model: str,
        provider_name: str = "openai_compatible",
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._default_model = default_model
        self._provider_name = provider_name

        if not self._api_key:
            logger.warning("API key not set for %s provider; calls will fail.", provider_name)
        if not self._base_url:
            logger.warning("Base URL not set for %s provider; calls will fail.", provider_name)

    def _sync_call(self, request: LLMRequest, model: str) -> LLMResponse:
        endpoint = self._base_url
        if not endpoint.endswith("/chat/completions"):
            endpoint = f"{endpoint}/chat/completions"

        if self._provider_name.startswith("salad"):
            headers = {
                "Salad-Api-Key": self._api_key,
                "Content-Type": "application/json",
            }
        else:
            headers = {
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            }
        body: dict = {
            "model": model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.response_format == "json_object":
            body["response_format"] = {"type": "json_object"}

        start = time.monotonic()
        try:
            resp = requests.post(endpoint, headers=headers, json=body, timeout=request.timeout_s)
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            raise LLMTimeoutError(f"{self._provider_name} timed out after {request.timeout_s}s")
        except requests.exceptions.HTTPError as exc:
            code = getattr(exc.response, "status_code", None)
            if code == 429:
                raise LLMRateLimitError(f"{self._provider_name} rate limit exceeded")
            text = getattr(exc.response, "text", "")
            raise LLMError(f"{self._provider_name} HTTP {code}: {text[:200]}")
        except requests.RequestException as exc:
            raise LLMError(f"{self._provider_name} request failed: {exc}")

        data = resp.json()
        msg = data["choices"][0]["message"]
        content = msg.get("content") or ""
        # Ollama returns reasoning models' chain-of-thought in a separate "reasoning" field.
        # If content is empty but reasoning exists, use reasoning as content.
        if not content.strip() and msg.get("reasoning"):
            content = msg["reasoning"]
        usage = data.get("usage", {})
        return LLMResponse(
            content=content,
            model_used=model,
            provider=self._provider_name,
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

"""
Async wrapper around native Ollama HTTP chat endpoints.

Used for both local Ollama and Salad Cloud-hosted Ollama deployments.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

import requests

from .provider import (
    LLMError,
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
    LLMProviderInterface,
)

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        logger.warning("invalid_int_env: %s=%r, using %d", name, os.environ.get(name), default)
        return default


class OllamaProvider(LLMProviderInterface):
    """Async Ollama HTTP client for local or remote Salad Cloud endpoints."""

    def __init__(
        self,
        model: str = "qwen2.5-coder:7b-instruct-q4_K_M",
        base_url: str = "http://localhost:11434",
        api_key: str = "",
        timeout_s: Optional[int] = None,
        num_ctx: Optional[int] = None,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key or os.getenv("OLLAMA_API_KEY", "")
        self._timeout_s = timeout_s if timeout_s is not None else (int(os.getenv("OLLAMA_TIMEOUT_S") or 0) or None)
        self._num_ctx = int(num_ctx or os.getenv("OLLAMA_NUM_CTX", "65536"))
        self._http_retries = _int_env("OLLAMA_HTTP_RETRIES", 3)
        self._retry_backoff_s = float(os.getenv("OLLAMA_HTTP_RETRY_BACKOFF_S", "5"))

    @staticmethod
    def _strip_think_tags(text: str) -> str:
        import re
        cleaned = re.sub(r"^<think>.*?</think>\s*", "", text, count=1, flags=re.DOTALL)
        if cleaned != text:
            return cleaned
        if "</think>" in text:
            return text.split("</think>", 1)[1].strip()
        return text

    def _build_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _sync_call(self, request: LLMRequest, model: str) -> str:
        base = self._base_url.rstrip("/")
        if base.endswith("/v1"):
            base = base[:-3]
        endpoint = f"{base}/api/chat"
        payload: dict = {
            "model": model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": request.temperature,
            },
        }
        if self._num_ctx:
            payload["options"]["num_ctx"] = self._num_ctx

        attempts = max(1, self._http_retries + 1)
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = requests.post(
                    endpoint,
                    headers=self._build_headers(),
                    json=payload,
                    timeout=request.timeout_s or self._timeout_s,
                )
                response.raise_for_status()
                data = response.json()
                content = data["message"]["content"]
                return self._strip_think_tags(content)
            except requests.exceptions.Timeout as exc:
                last_error = exc
                if attempt >= attempts:
                    raise LLMTimeoutError(f"Ollama call timed out after {request.timeout_s}s")
            except requests.exceptions.HTTPError as exc:
                last_error = exc
                status = getattr(exc.response, "status_code", None)
                body = getattr(exc.response, "text", "")[:300]
                if status not in {500, 502, 503, 504} or attempt >= attempts:
                    raise LLMError(f"Ollama HTTP {status}: {body}")
                logger.warning(
                    "ollama_transient_http_error attempt=%d/%d status=%s body=%r",
                    attempt,
                    attempts,
                    status,
                    body,
                )
            except requests.RequestException as exc:
                last_error = exc
                if attempt >= attempts:
                    raise LLMError(f"Ollama error: {exc}")
            except (KeyError, TypeError, ValueError) as exc:
                raise LLMError(f"Ollama response parse error: {exc}")

            if attempt < attempts:
                time.sleep(self._retry_backoff_s * attempt)

        raise LLMError(f"Ollama error: {last_error}")

    async def generate(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self._model
        loop = asyncio.get_running_loop()
        start = time.monotonic()
        content = await asyncio.wait_for(
            loop.run_in_executor(None, self._sync_call, request, model),
            timeout=(request.timeout_s + 5) if request.timeout_s is not None else None,
        )
        return LLMResponse(
            content=content,
            model_used=model,
            provider="ollama",
            latency_s=time.monotonic() - start,
        )

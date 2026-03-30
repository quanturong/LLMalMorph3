"""
Async wrapper around the existing src/ollama_api.py OllamaProvider.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from .provider import (
    LLMError,
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
    LLMProviderInterface,
)

logger = logging.getLogger(__name__)


class OllamaProvider(LLMProviderInterface):
    """
    Async provider wrapping the synchronous Ollama client in src/ollama_api.py.
    Falls back gracefully if Ollama is unavailable.
    """

    def __init__(
        self,
        model: str = "qwen2.5-coder:7b-instruct-q4_K_M",
        base_url: str = "http://localhost:11434",
    ) -> None:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

        self._model = model
        self._base_url = base_url
        self._available: Optional[bool] = None  # lazy check

    def _get_sync_client(self):
        try:
            from ollama_api import OllamaProvider as _Ollama
            return _Ollama(model=self._model)
        except ImportError:
            return None

    async def generate(self, request: LLMRequest) -> LLMResponse:
        client = self._get_sync_client()
        if client is None:
            raise LLMError("Ollama not available (ollama package not installed)")

        model = request.model or self._model
        loop = asyncio.get_running_loop()
        start = time.monotonic()

        try:
            content = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: client.generate(
                        system_prompt=request.system_prompt,
                        user_prompt=request.user_prompt,
                        model=model,
                        temperature=request.temperature,
                    ),
                ),
                timeout=request.timeout_s + 10,
            )
        except asyncio.TimeoutError:
            raise LLMTimeoutError(f"Ollama call timed out after {request.timeout_s}s")
        except Exception as exc:
            raise LLMError(f"Ollama error: {exc}")

        return LLMResponse(
            content=content,
            model_used=model,
            provider="ollama",
            latency_s=time.monotonic() - start,
        )

"""
Provider factory — builds the correct LLMProviderInterface based on config/env.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from .provider import CachingLLMProvider, LLMProviderInterface

logger = logging.getLogger(__name__)


def build_provider(
    mode: str = "local_only",
    redis_client: Optional[Any] = None,
    cache_ttl_s: int = 3600,
    local_model: str = "qwen2.5-coder:7b-instruct-q4_K_M",
    cloud_model: Optional[str] = None,
    api_key: Optional[str] = None,
    cloud_provider: str = "mistral",
    cloud_base_url: Optional[str] = None,
    fallback_provider: str = "deepseek",
    fallback_model: Optional[str] = None,
) -> LLMProviderInterface:
    """
    Build and return an LLM provider.

    Modes:
        "local_only"   → OllamaProvider
        "cloud_only"   → MistralProvider or OpenAI-compatible provider
        "hybrid"       → tries local first, falls back to cloud
        "deepseek"     → DeepSeekProvider
        "mistral"      → MistralProvider

    If redis_client is provided, wraps result in CachingLLMProvider.
    """
    provider: LLMProviderInterface

    if mode in ("local_only",):
        from .ollama_provider import OllamaProvider
        provider = OllamaProvider(model=local_model)
        logger.info("LLM provider: OllamaProvider(model=%s)", local_model)

    elif mode == "deepseek":
        from .deepseek_provider import DeepSeekProvider
        resolved_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        provider = DeepSeekProvider(api_key=resolved_key, default_model=cloud_model or "deepseek-chat")
        logger.info("LLM provider: DeepSeekProvider(model=%s)", cloud_model)

    elif mode in ("cloud_only", "mistral"):
        if cloud_provider in ("runpod", "openai_compatible"):
            from .openai_compatible_provider import OpenAICompatibleProvider

            resolved_key = api_key or os.getenv("RUNPOD_API_KEY", "")
            resolved_url = cloud_base_url or os.getenv("RUNPOD_OPENAI_BASE_URL", "")
            provider = OpenAICompatibleProvider(
                api_key=resolved_key,
                base_url=resolved_url,
                default_model=cloud_model or "Qwen/Qwen2.5-Coder-32B-Instruct",
                provider_name="runpod",
            )
            logger.info("LLM provider: RunPod(OpenAI-compatible, model=%s)", cloud_model)
        else:
            from .mistral_provider import MistralProvider
            resolved_key = api_key or os.getenv("MISTRAL_API_KEY", "")
            provider = MistralProvider(api_key=resolved_key, default_model=cloud_model or "codestral-latest")
            logger.info("LLM provider: MistralProvider(model=%s)", cloud_model)

    elif mode == "hybrid":
        provider = _build_hybrid(
            local_model=local_model,
            cloud_model=cloud_model,
            api_key=api_key,
            cloud_provider=cloud_provider,
            cloud_base_url=cloud_base_url,
            fallback_provider=fallback_provider,
            fallback_model=fallback_model,
        )
        logger.info("LLM provider: HybridProvider(primary=%s, fallback=%s)", cloud_provider, fallback_provider)

    else:
        raise ValueError(f"Unknown LLM provider mode: '{mode}'")

    if redis_client is not None:
        provider = CachingLLMProvider(
            inner=provider,
            redis_client=redis_client,
            ttl_s=cache_ttl_s,
        )
        logger.info("LLM provider wrapped with CachingLLMProvider(ttl=%ds)", cache_ttl_s)

    return provider


def _build_hybrid(
    local_model: str,
    cloud_model: Optional[str],
    api_key: Optional[str],
    cloud_provider: str,
    cloud_base_url: Optional[str],
    fallback_provider: str = "deepseek",
    fallback_model: Optional[str] = None,
) -> LLMProviderInterface:
    """Build a hybrid provider that tries local first, falls back to cloud."""

    class _HybridProvider(LLMProviderInterface):
        def __init__(self, primary, fallback, primary_name="primary", fallback_name="fallback"):
            self._primary = primary
            self._fallback = fallback
            self._primary_name = primary_name
            self._fallback_name = fallback_name

        async def generate(self, request):
            from .provider import LLMError
            try:
                return await self._primary.generate(request)
            except Exception as primary_err:
                logger.warning("%s LLM failed (%s), falling back to %s.", self._primary_name, primary_err, self._fallback_name)
                return await self._fallback.generate(request)

    # Build primary provider
    if cloud_provider == "deepseek":
        from .deepseek_provider import DeepSeekProvider
        resolved_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        primary = DeepSeekProvider(api_key=resolved_key, default_model=cloud_model or "deepseek-chat")
    elif cloud_provider in ("runpod", "openai_compatible"):
        from .openai_compatible_provider import OpenAICompatibleProvider
        resolved_key = api_key or os.getenv("RUNPOD_API_KEY", "")
        resolved_url = cloud_base_url or os.getenv("RUNPOD_OPENAI_BASE_URL", "")
        primary = OpenAICompatibleProvider(
            api_key=resolved_key,
            base_url=resolved_url,
            default_model=cloud_model or "Qwen/Qwen2.5-Coder-32B-Instruct",
            provider_name="runpod",
        )
    elif cloud_provider == "local":
        from .ollama_provider import OllamaProvider
        primary = OllamaProvider(model=local_model)
    else:
        from .mistral_provider import MistralProvider
        resolved_key = api_key or os.getenv("MISTRAL_API_KEY", "")
        primary = MistralProvider(api_key=resolved_key, default_model=cloud_model or "codestral-latest")

    # Build fallback provider
    if fallback_provider == "deepseek":
        from .deepseek_provider import DeepSeekProvider
        fallback_key = os.getenv("DEEPSEEK_API_KEY", "")
        fallback = DeepSeekProvider(api_key=fallback_key, default_model=fallback_model or "deepseek-chat")
    elif fallback_provider in ("runpod", "openai_compatible"):
        from .openai_compatible_provider import OpenAICompatibleProvider
        fallback_key = os.getenv("RUNPOD_API_KEY", "")
        fallback_url = os.getenv("RUNPOD_OPENAI_BASE_URL", "")
        fallback = OpenAICompatibleProvider(
            api_key=fallback_key,
            base_url=fallback_url,
            default_model=fallback_model or "Qwen/Qwen2.5-Coder-32B-Instruct",
            provider_name="runpod",
        )
    elif fallback_provider == "local":
        from .ollama_provider import OllamaProvider
        fallback = OllamaProvider(model=fallback_model or local_model)
    else:
        from .mistral_provider import MistralProvider
        fallback_key = os.getenv("MISTRAL_API_KEY", "")
        fallback = MistralProvider(api_key=fallback_key, default_model=fallback_model or "codestral-latest")

    return _HybridProvider(primary, fallback, cloud_provider, fallback_provider)

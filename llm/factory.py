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
    cloud_extra_urls: Optional[list[str]] = None,
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
        if cloud_provider in ("runpod", "openai_compatible", "salad"):
            from .openai_compatible_provider import OpenAICompatibleProvider

            if cloud_provider == "salad":
                resolved_key = api_key or os.getenv("SALAD_API_KEY", "") or os.getenv("RUNPOD_API_KEY", "")
                resolved_url = cloud_base_url or os.getenv("SALAD_URL", "") or os.getenv("CLOUD_URL", "")
                prov_name = "salad"
            else:
                resolved_key = api_key or os.getenv("RUNPOD_API_KEY", "")
                resolved_url = cloud_base_url or os.getenv("CLOUD_URL", "")
                prov_name = "runpod"
            provider = OpenAICompatibleProvider(
                api_key=resolved_key,
                base_url=resolved_url,
                default_model=cloud_model or "Qwen/Qwen2.5-Coder-32B-Instruct",
                provider_name=prov_name,
            )
            logger.info("LLM provider: %s(OpenAI-compatible, model=%s)", prov_name, cloud_model)
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
            cloud_extra_urls=cloud_extra_urls,
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
    cloud_extra_urls: Optional[list[str]] = None,
) -> LLMProviderInterface:
    """Build a hybrid provider that tries cloud first (racing all URLs), falls back to another provider."""
    import asyncio

    class _HybridProvider(LLMProviderInterface):
        def __init__(self, primary, fallback, primary_name="primary", fallback_name="fallback"):
            self._primary = primary
            self._fallback = fallback
            self._primary_name = primary_name
            self._fallback_name = fallback_name

        async def generate(self, request):
            try:
                return await self._primary.generate(request)
            except Exception as primary_err:
                logger.warning("%s LLM failed (%s), falling back to %s.", self._primary_name, primary_err, self._fallback_name)
                return await self._fallback.generate(request)

    class _RacePrimaryProvider(LLMProviderInterface):
        """Race multiple cloud endpoints; first success wins. Retries before giving up."""

        def __init__(self, providers: list, label: str = "cloud_race", max_retries: int = 2, retry_delay: float = 5.0):
            self._providers = providers
            self._label = label
            self._max_retries = max_retries
            self._retry_delay = retry_delay
            logger.info("%s: %d contestants, max_retries=%d", label, len(providers), max_retries)

        async def _race_once(self, request):
            """Run one race round across all providers. Returns result or raises."""
            if len(self._providers) == 1:
                return await self._providers[0].generate(request)

            tasks = [asyncio.ensure_future(p.generate(request)) for p in self._providers]
            errors = []
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                # Check completed tasks for a success
                result = None
                for task in done:
                    try:
                        result = task.result()
                        break
                    except Exception as e:
                        logger.debug("%s: contestant failed: %s", self._label, e)
                        errors.append(e)

                if result is not None:
                    for task in pending:
                        task.cancel()
                    return result

                # First batch all failed, wait for remaining
                if pending:
                    done2, _ = await asyncio.wait(pending, return_when=asyncio.ALL_COMPLETED)
                    for task in done2:
                        try:
                            result = task.result()
                            break
                        except Exception as e:
                            logger.debug("%s: contestant failed: %s", self._label, e)
                            errors.append(e)

                if result is not None:
                    return result
            except Exception as e:
                errors.append(e)
                for task in tasks:
                    task.cancel()

            raise errors[0] if errors else RuntimeError(f"{self._label}: all contestants failed")

        async def generate(self, request):
            last_err = None
            for attempt in range(1 + self._max_retries):
                try:
                    return await self._race_once(request)
                except Exception as e:
                    last_err = e
                    if attempt < self._max_retries:
                        logger.warning("%s: all endpoints failed (attempt %d/%d: %s), retrying in %.0fs...",
                                       self._label, attempt + 1, 1 + self._max_retries, e, self._retry_delay)
                        await asyncio.sleep(self._retry_delay)
                    else:
                        logger.warning("%s: all endpoints failed after %d attempts: %s",
                                       self._label, 1 + self._max_retries, e)
            raise last_err

    # Build primary provider
    if cloud_provider == "deepseek":
        from .deepseek_provider import DeepSeekProvider
        resolved_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        primary = DeepSeekProvider(api_key=resolved_key, default_model=cloud_model or "deepseek-chat")
    elif cloud_provider in ("runpod", "openai_compatible", "salad"):
        from .openai_compatible_provider import OpenAICompatibleProvider
        if cloud_provider == "salad":
            resolved_key = api_key or os.getenv("SALAD_API_KEY", "") or os.getenv("RUNPOD_API_KEY", "")
            resolved_url = cloud_base_url or os.getenv("SALAD_URL", "") or os.getenv("CLOUD_URL", "")
            prov_name = "salad"
        else:
            resolved_key = api_key or os.getenv("RUNPOD_API_KEY", "")
            resolved_url = cloud_base_url or os.getenv("CLOUD_URL", "")
            prov_name = "runpod"

        # Build list of all cloud URLs for racing
        all_urls = [resolved_url] if resolved_url else []
        for u in (cloud_extra_urls or []):
            u = u.strip().rstrip("/")
            if u and u not in all_urls:
                all_urls.append(u)

        if len(all_urls) > 1:
            race_providers = [
                OpenAICompatibleProvider(
                    api_key=resolved_key,
                    base_url=url,
                    default_model=cloud_model or "Qwen/Qwen2.5-Coder-32B-Instruct",
                    provider_name=f"{prov_name}_{i}",
                )
                for i, url in enumerate(all_urls)
            ]
            primary = _RacePrimaryProvider(race_providers, label=f"{prov_name}_race")
            logger.info("Hybrid primary: racing %d %s endpoints", len(all_urls), prov_name)
        else:
            primary = OpenAICompatibleProvider(
                api_key=resolved_key,
                base_url=resolved_url,
                default_model=cloud_model or "Qwen/Qwen2.5-Coder-32B-Instruct",
                provider_name=prov_name,
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
    elif fallback_provider in ("runpod", "openai_compatible", "salad"):
        from .openai_compatible_provider import OpenAICompatibleProvider
        if fallback_provider == "salad":
            fallback_key = os.getenv("SALAD_API_KEY", "") or os.getenv("RUNPOD_API_KEY", "")
            fallback_url = os.getenv("SALAD_URL", "") or os.getenv("CLOUD_URL", "")
            fb_prov_name = "salad"
        else:
            fallback_key = os.getenv("RUNPOD_API_KEY", "")
            fallback_url = os.getenv("CLOUD_URL", "")
            fb_prov_name = "runpod"
        fallback = OpenAICompatibleProvider(
            api_key=fallback_key,
            base_url=fallback_url,
            default_model=fallback_model or "Qwen/Qwen2.5-Coder-32B-Instruct",
            provider_name=fb_prov_name,
        )
    elif fallback_provider == "local":
        from .ollama_provider import OllamaProvider
        fallback = OllamaProvider(model=fallback_model or local_model)
    else:
        from .mistral_provider import MistralProvider
        fallback_key = os.getenv("MISTRAL_API_KEY", "")
        fallback = MistralProvider(api_key=fallback_key, default_model=fallback_model or "codestral-latest")

    return _HybridProvider(primary, fallback, cloud_provider, fallback_provider)

"""
LLM abstraction layer.

Usage:
    from llm import build_provider, LLMRequest

    provider = build_provider("hybrid")
    result = await provider.generate_structured(request, MyOutputSchema)
"""

from .provider import (
    LLMRequest,
    LLMResponse,
    LLMProviderInterface,
    LLMStructuredOutputError,
    CachingLLMProvider,
)
from .factory import build_provider

__all__ = [
    "LLMRequest",
    "LLMResponse",
    "LLMProviderInterface",
    "LLMStructuredOutputError",
    "CachingLLMProvider",
    "build_provider",
]

"""
Performance optimization module for LLMalMorph.
Provides parallel processing and caching.
"""
from .parallel_processor import (
    ParallelProcessor,
    mutate_function_async,
    mutate_function_sync,
)
from .cache_manager import CacheManager

__all__ = [
    'ParallelProcessor',
    'mutate_function_async',
    'mutate_function_sync',
    'CacheManager',
]


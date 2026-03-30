"""
Caching system for LLMalMorph.
Caches parsed results, LLM responses, and compilation results.
"""
import hashlib
import json
import logging
import os
import pickle
from typing import Optional, Any, Dict
from pathlib import Path
import time

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Cache manager for LLMalMorph.
    Supports file-based caching with TTL (time-to-live).
    """
    
    def __init__(
        self,
        cache_dir: str = ".llmalmorph_cache",
        default_ttl: int = 3600,  # 1 hour
    ):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Cache directory path
            default_ttl: Default TTL in seconds
        """
        self.cache_dir = Path(cache_dir)
        self.default_ttl = default_ttl
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Subdirectories for different cache types
        self.parse_cache_dir = self.cache_dir / "parsed"
        self.llm_cache_dir = self.cache_dir / "llm"
        self.compilation_cache_dir = self.cache_dir / "compilation"
        
        for dir_path in [self.parse_cache_dir, self.llm_cache_dir, self.compilation_cache_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized cache manager: {cache_dir}")
    
    def _get_hash(self, data: str) -> str:
        """Generate hash for cache key"""
        return hashlib.md5(data.encode()).hexdigest()
    
    def _get_cache_path(self, cache_type: str, key: str) -> Path:
        """Get cache file path"""
        if cache_type == "parsed":
            return self.parse_cache_dir / f"{key}.pkl"
        elif cache_type == "llm":
            return self.llm_cache_dir / f"{key}.json"
        elif cache_type == "compilation":
            return self.compilation_cache_dir / f"{key}.json"
        else:
            return self.cache_dir / f"{key}.pkl"
    
    def _is_expired(self, cache_path: Path, ttl: int) -> bool:
        """Check if cache entry is expired"""
        if not cache_path.exists():
            return True
        
        file_age = time.time() - cache_path.stat().st_mtime
        return file_age > ttl
    
    def cache_parse_result(
        self,
        source_file: str,
        content: str,
        result: Any,
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Cache parsed code structure.
        
        Args:
            source_file: Source file path
            content: File content
            result: Parsed result
            ttl: Time-to-live in seconds
        
        Returns:
            True if cached successfully
        """
        cache_key = self._get_hash(f"{source_file}:{content[:1000]}")
        cache_path = self._get_cache_path("parsed", cache_key)
        
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump({
                    'source_file': source_file,
                    'result': result,
                    'timestamp': time.time(),
                }, f)
            
            logger.debug(f"Cached parse result: {cache_key}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to cache parse result: {e}")
            return False
    
    def get_cached_parse_result(
        self,
        source_file: str,
        content: str,
        ttl: Optional[int] = None,
    ) -> Optional[Any]:
        """
        Get cached parse result.
        
        Args:
            source_file: Source file path
            content: File content
            ttl: Time-to-live in seconds
        
        Returns:
            Cached result or None
        """
        cache_key = self._get_hash(f"{source_file}:{content[:1000]}")
        cache_path = self._get_cache_path("parsed", cache_key)
        
        if not cache_path.exists():
            return None
        
        ttl = ttl or self.default_ttl
        if self._is_expired(cache_path, ttl):
            logger.debug(f"Cache expired: {cache_key}")
            cache_path.unlink()
            return None
        
        try:
            with open(cache_path, 'rb') as f:
                data = pickle.load(f)
                logger.debug(f"Cache hit: {cache_key}")
                return data['result']
        
        except Exception as e:
            logger.error(f"Failed to load cached parse result: {e}")
            return None
    
    def cache_llm_response(
        self,
        prompt: str,
        response: str,
        model: str = "default",
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Cache LLM response.
        
        Args:
            prompt: User prompt
            response: LLM response
            model: Model name
            ttl: Time-to-live in seconds
        
        Returns:
            True if cached successfully
        """
        cache_key = self._get_hash(f"{model}:{prompt}")
        cache_path = self._get_cache_path("llm", cache_key)
        
        try:
            with open(cache_path, 'w') as f:
                json.dump({
                    'prompt': prompt[:500],  # Store truncated prompt for reference
                    'response': response,
                    'model': model,
                    'timestamp': time.time(),
                }, f, indent=2)
            
            logger.debug(f"Cached LLM response: {cache_key}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to cache LLM response: {e}")
            return False
    
    def get_cached_llm_response(
        self,
        prompt: str,
        model: str = "default",
        ttl: Optional[int] = None,
    ) -> Optional[str]:
        """
        Get cached LLM response.
        
        Args:
            prompt: User prompt
            model: Model name
            ttl: Time-to-live in seconds
        
        Returns:
            Cached response or None
        """
        cache_key = self._get_hash(f"{model}:{prompt}")
        cache_path = self._get_cache_path("llm", cache_key)
        
        if not cache_path.exists():
            return None
        
        ttl = ttl or self.default_ttl
        if self._is_expired(cache_path, ttl):
            logger.debug(f"Cache expired: {cache_key}")
            cache_path.unlink()
            return None
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
                logger.debug(f"Cache hit: {cache_key}")
                return data['response']
        
        except Exception as e:
            logger.error(f"Failed to load cached LLM response: {e}")
            return None
    
    def cache_compilation_result(
        self,
        source_file: str,
        result: Dict,
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Cache compilation result.
        
        Args:
            source_file: Source file path
            result: Compilation result dictionary
            ttl: Time-to-live in seconds
        
        Returns:
            True if cached successfully
        """
        cache_key = self._get_hash(source_file)
        cache_path = self._get_cache_path("compilation", cache_key)
        
        try:
            with open(cache_path, 'w') as f:
                json.dump({
                    'source_file': source_file,
                    'result': result,
                    'timestamp': time.time(),
                }, f, indent=2)
            
            logger.debug(f"Cached compilation result: {cache_key}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to cache compilation result: {e}")
            return False
    
    def get_cached_compilation_result(
        self,
        source_file: str,
        ttl: Optional[int] = None,
    ) -> Optional[Dict]:
        """
        Get cached compilation result.
        
        Args:
            source_file: Source file path
            ttl: Time-to-live in seconds
        
        Returns:
            Cached result or None
        """
        cache_key = self._get_hash(source_file)
        cache_path = self._get_cache_path("compilation", cache_key)
        
        if not cache_path.exists():
            return None
        
        ttl = ttl or self.default_ttl
        if self._is_expired(cache_path, ttl):
            logger.debug(f"Cache expired: {cache_key}")
            cache_path.unlink()
            return None
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
                logger.debug(f"Cache hit: {cache_key}")
                return data['result']
        
        except Exception as e:
            logger.error(f"Failed to load cached compilation result: {e}")
            return None
    
    def clear_cache(self, cache_type: Optional[str] = None):
        """
        Clear cache.
        
        Args:
            cache_type: Type of cache to clear (None = all)
        """
        if cache_type is None:
            # Clear all
            for dir_path in [self.parse_cache_dir, self.llm_cache_dir, self.compilation_cache_dir]:
                for file_path in dir_path.glob("*"):
                    file_path.unlink()
            logger.info("Cleared all caches")
        else:
            dir_path = self._get_cache_path(cache_type, "").parent
            for file_path in dir_path.glob("*"):
                file_path.unlink()
            logger.info(f"Cleared {cache_type} cache")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        stats = {
            'parsed': 0,
            'llm': 0,
            'compilation': 0,
            'total_size': 0,
        }
        
        for cache_type in ['parsed', 'llm', 'compilation']:
            dir_path = self._get_cache_path(cache_type, "").parent
            files = list(dir_path.glob("*"))
            stats[cache_type] = len(files)
            stats['total_size'] += sum(f.stat().st_size for f in files)
        
        return stats


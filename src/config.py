"""
Configuration management for LLMalMorph.
Supports environment variables and config files.
"""
import os
import json
import logging
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class Config:
    """Configuration manager for LLMalMorph"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Optional path to JSON config file
        """
        self.config: Dict[str, Any] = {}
        
        # Load from file if provided
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
        
        # Load from environment variables (overrides file config)
        self.load_from_env()
    
    def load_from_file(self, config_file: str) -> None:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                self.config.update(json.load(f))
            logger.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            logger.warning(f"Failed to load config file {config_file}: {str(e)}")
    
    def load_from_env(self) -> None:
        """Load configuration from environment variables"""
        env_mappings = {
            'MISTRAL_API_KEY': 'mistral_api_key',
            'OLLAMA_BASE_URL': 'ollama_base_url',
            'LOG_LEVEL': 'log_level',
            'LOG_FILE': 'log_file',
            'MAX_RETRIES': 'max_retries',
            'REQUEST_TIMEOUT': 'request_timeout',
        }
        
        for env_var, config_key in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                # Convert string numbers to int/float
                if config_key in ['max_retries', 'request_timeout']:
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                self.config[config_key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        self.config[key] = value
    
    def get_mistral_api_key(self) -> Optional[str]:
        """Get Mistral API key"""
        return self.get('mistral_api_key') or os.getenv('MISTRAL_API_KEY')
    
    def get_ollama_base_url(self) -> str:
        """Get Ollama base URL"""
        return self.get('ollama_base_url', 'http://localhost:11434')
    
    def get_log_level(self) -> str:
        """Get log level"""
        return self.get('log_level', 'INFO')
    
    def get_log_file(self) -> Optional[str]:
        """Get log file path"""
        return self.get('log_file')
    
    def get_max_retries(self) -> int:
        """Get maximum retry attempts"""
        return self.get('max_retries', 3)
    
    def get_request_timeout(self) -> int:
        """Get request timeout in seconds"""
        return self.get('request_timeout', 60)


# Global config instance
_config: Optional[Config] = None


def get_config(config_file: Optional[str] = None) -> Config:
    """Get global configuration instance"""
    global _config
    if _config is None:
        _config = Config(config_file)
    return _config


def setup_logging(config: Optional[Config] = None) -> None:
    """
    Setup logging configuration.
    
    Args:
        config: Optional Config instance. If None, uses global config.
    """
    if config is None:
        config = get_config()
    
    log_level = getattr(logging, config.get_log_level().upper(), logging.INFO)
    log_file = config.get_log_file()
    
    # Configure logging
    handlers = [logging.StreamHandler()]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers,
    )
    
    logger.info(f"Logging configured. Level: {log_level}, File: {log_file}")


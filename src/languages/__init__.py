"""
Language plugins for LLMalMorph.
Supports multiple programming languages through plugin architecture.
"""
from typing import Dict, Optional, Type
from .base import Language, CodeStructure, Function, Class, Module

# Language registry
_language_registry: Dict[str, Type[Language]] = {}


def register_language(extensions: list, language_class: Type[Language]):
    """
    Register a language plugin.
    
    Args:
        extensions: List of file extensions (e.g., ['.py', '.pyw'])
        language_class: Language plugin class
    """
    for ext in extensions:
        _language_registry[ext.lower()] = language_class


def get_language(file_path: str, content: Optional[str] = None) -> Optional[Language]:
    """
    Get language plugin for a file.
    
    Args:
        file_path: Path to source file
        content: Optional file content for detection
    
    Returns:
        Language instance or None if not supported
    """
    import os
    
    # Try file extension first
    ext = os.path.splitext(file_path)[1].lower()
    if ext in _language_registry:
        return _language_registry[ext]()
    
    # Try content-based detection
    if content:
        for lang_class in _language_registry.values():
            lang = lang_class()
            if lang.can_parse(content):
                return lang
    
    return None


def get_supported_languages() -> list:
    """Get list of supported language extensions"""
    return list(_language_registry.keys())


# Import language plugins (will be registered automatically)
try:
    from .c_language import CLanguage
    register_language(['.c'], CLanguage)
except ImportError:
    pass

try:
    from .cpp_language import CppLanguage
    register_language(['.cpp', '.cxx', '.cc', '.hpp', '.h'], CppLanguage)
except ImportError:
    pass

try:
    from .python_language import PythonLanguage
    register_language(['.py', '.pyw'], PythonLanguage)
except ImportError:
    pass

try:
    from .javascript_language import JavaScriptLanguage
    register_language(['.js', '.mjs'], JavaScriptLanguage)
except ImportError:
    pass


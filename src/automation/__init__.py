"""
Automation module for LLMalMorph.
Provides automated compilation, testing, and error fixing.
"""
from .compilation_pipeline import (
    CompilationPipeline,
    CompilationResult,
    CompilationStatus,
    TestResult,
)
from .auto_fixer import AutoFixer
from .quality_assurance import (
    QualityAssurance,
    QualityIssue,
    IssueSeverity,
)
try:
    from .integrated_pipeline import IntegratedPipeline
except ImportError:
    IntegratedPipeline = None
from .error_analyzer import (
    ErrorAnalyzer, ErrorType, ErrorInfo,
    detect_compiler_from_errors,
    COMPILER_MSVC, COMPILER_GCC, COMPILER_CLANG, COMPILER_AUTO,
)
from .fix_strategies import FixStrategies
try:
    from .mahoraga_fixer import MahoragaAdaptiveFixer, FixMemory
except ImportError:
    MahoragaAdaptiveFixer = None
    FixMemory = None
from .semantic_validator import SemanticValidator, get_semantic_validator

__all__ = [
    'CompilationPipeline',
    'CompilationResult',
    'CompilationStatus',
    'TestResult',
    'AutoFixer',
    'MahoragaAdaptiveFixer',
    'FixMemory',
    'QualityAssurance',
    'QualityIssue',
    'IssueSeverity',
    'IntegratedPipeline',
    'ErrorAnalyzer',
    'ErrorType',
    'ErrorInfo',
    'detect_compiler_from_errors',
    'COMPILER_MSVC',
    'COMPILER_GCC',
    'COMPILER_CLANG',
    'COMPILER_AUTO',
    'FixStrategies',
]


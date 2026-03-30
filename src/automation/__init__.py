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
from .integrated_pipeline import IntegratedPipeline
from .error_analyzer import ErrorAnalyzer, ErrorType, ErrorInfo
from .fix_strategies import FixStrategies
from .mahoraga_fixer import MahoragaAdaptiveFixer, FixMemory

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
    'FixStrategies',
]


"""
Error analysis and classification module.
Helps identify error types and suggest appropriate fix strategies.
"""
import re
import logging
from typing import List, Dict, Tuple, Optional
from enum import Enum


logger = logging.getLogger(__name__)


class ErrorType(Enum):
    """Types of compilation errors"""
    MISSING_HEADER = "missing_header"
    UNDEFINED_SYMBOL = "undefined_symbol"
    SYNTAX_ERROR = "syntax_error"
    TYPE_MISMATCH = "type_mismatch"
    LINKING_ERROR = "linking_error"
    UNKNOWN = "unknown"


class ErrorInfo:
    """Information about a compilation error"""
    def __init__(self, error_text: str, error_type: ErrorType, line_num: Optional[int] = None):
        self.error_text = error_text
        self.error_type = error_type
        self.line_num = line_num
        self.header_name = None
        self.symbol_name = None
        
        # Extract additional info based on error type
        if error_type == ErrorType.MISSING_HEADER:
            self._extract_header_name()
        elif error_type == ErrorType.UNDEFINED_SYMBOL:
            self._extract_symbol_name()
    
    def _extract_header_name(self):
        """Extract header file name from error message"""
        # Pattern: "fatal error: header.h: No such file or directory"
        patterns = [
            r"fatal error:\s*([^:]+\.h[^:]*):",
            r"no such file or directory:\s*([^:]+\.h[^:]*)",
            r"cannot open source file\s*['\"]([^'\"]+\.h[^'\"]*)['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, self.error_text, re.IGNORECASE)
            if match:
                self.header_name = match.group(1).strip()
                break
    
    def _extract_symbol_name(self):
        """Extract symbol name from error message"""
        # Pattern: "undefined reference to 'symbol'"
        patterns = [
            r"undefined reference to\s*['\"]([^'\"]+)['\"]",
            r"undefined symbol:\s*['\"]?([^'\"]+)['\"]?",
            r"'([^']+)' undeclared",
        ]
        for pattern in patterns:
            match = re.search(pattern, self.error_text, re.IGNORECASE)
            if match:
                self.symbol_name = match.group(1).strip()
                break
    
    def __repr__(self):
        return f"ErrorInfo(type={self.error_type.value}, line={self.line_num}, text={self.error_text[:50]}...)"


class ErrorAnalyzer:
    """Analyzes compilation errors and classifies them"""
    
    @staticmethod
    def classify_errors(errors: List[str]) -> List[ErrorInfo]:
        """
        Classify compilation errors into different types.
        
        Args:
            errors: List of error messages from compiler
            
        Returns:
            List of ErrorInfo objects
        """
        error_infos = []
        
        for error in errors:
            error_type = ErrorAnalyzer._classify_error(error)
            line_num = ErrorAnalyzer._extract_line_number(error)
            error_info = ErrorInfo(error, error_type, line_num)
            error_infos.append(error_info)
        
        return error_infos
    
    @staticmethod
    def _classify_error(error: str) -> ErrorType:
        """Classify a single error message"""
        error_lower = error.lower()
        
        # Missing header files
        if any(keyword in error_lower for keyword in [
            'no such file or directory',
            'fatal error',
            'cannot open source file',
            'file not found'
        ]) and ('.h' in error_lower or '.hpp' in error_lower):
            return ErrorType.MISSING_HEADER
        
        # Undefined symbols
        if any(keyword in error_lower for keyword in [
            'undefined reference',
            'undefined symbol',
            'undeclared identifier',
            'was not declared',
        ]):
            return ErrorType.UNDEFINED_SYMBOL
        
        # Type mismatches
        if any(keyword in error_lower for keyword in [
            'incompatible types',
            'cannot convert',
            'type mismatch',
            'invalid conversion',
        ]):
            return ErrorType.TYPE_MISMATCH
        
        # Linking errors
        if any(keyword in error_lower for keyword in [
            'undefined reference',
            'multiple definition',
            'duplicate symbol',
        ]):
            return ErrorType.LINKING_ERROR
        
        # Syntax errors (catch-all for common syntax issues)
        if any(keyword in error_lower for keyword in [
            'expected',
            'missing',
            'parse error',
            'syntax error',
        ]):
            return ErrorType.SYNTAX_ERROR
        
        return ErrorType.UNKNOWN
    
    @staticmethod
    def _extract_line_number(error: str) -> Optional[int]:
        """Extract line number from error message"""
        # Pattern: "file.c:123:45: error: ..."
        match = re.search(r':(\d+):\d+:', error)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                pass
        return None
    
    @staticmethod
    def group_errors_by_type(error_infos: List[ErrorInfo]) -> Dict[ErrorType, List[ErrorInfo]]:
        """Group errors by type"""
        grouped = {}
        for error_info in error_infos:
            if error_info.error_type not in grouped:
                grouped[error_info.error_type] = []
            grouped[error_info.error_type].append(error_info)
        return grouped
    
    @staticmethod
    def get_fix_strategy(error_infos: List[ErrorInfo]) -> Dict[str, any]:
        """
        Suggest fix strategy based on error types.
        
        Returns:
            Dictionary with strategy information
        """
        grouped = ErrorAnalyzer.group_errors_by_type(error_infos)
        
        strategy = {
            'has_missing_headers': ErrorType.MISSING_HEADER in grouped,
            'has_undefined_symbols': ErrorType.UNDEFINED_SYMBOL in grouped,
            'has_syntax_errors': ErrorType.SYNTAX_ERROR in grouped,
            'has_type_mismatches': ErrorType.TYPE_MISMATCH in grouped,
            'missing_headers': [e.header_name for e in grouped.get(ErrorType.MISSING_HEADER, []) if e.header_name],
            'undefined_symbols': [e.symbol_name for e in grouped.get(ErrorType.UNDEFINED_SYMBOL, []) if e.symbol_name],
            'total_errors': len(error_infos),
            'error_types': {et.value: len(grouped[et]) for et in grouped},
        }
        
        return strategy


"""
Advanced fix strategies for compilation errors.
Includes fallback strategies and pattern-based fixes.
"""
import re
import logging
from typing import List, Tuple, Optional, Dict
from .error_analyzer import ErrorAnalyzer, ErrorType, ErrorInfo

logger = logging.getLogger(__name__)


class FixStrategies:
    """Advanced fix strategies for handling compilation errors"""
    
    @staticmethod
    def calculate_adaptive_attempts(errors: List[str], base_attempts: int = 3) -> int:
        """
        Calculate adaptive number of fix attempts based on error count and types.
        
        Args:
            errors: List of error messages
            base_attempts: Base number of attempts
            
        Returns:
            Adaptive number of attempts
        """
        if not errors:
            return 1
        
        error_count = len(errors)
        
        # Analyze error types
        if ErrorAnalyzer:
            try:
                error_infos = ErrorAnalyzer.classify_errors(errors)
                strategy = ErrorAnalyzer.get_fix_strategy(error_infos)
                
                # More attempts for complex errors
                if strategy.get('has_undefined_symbols') and error_count > 10:
                    return base_attempts + 2
                elif strategy.get('has_missing_headers') and error_count > 5:
                    return base_attempts + 1
                elif error_count > 20:
                    return base_attempts + 2
                elif error_count > 10:
                    return base_attempts + 1
            except Exception:
                pass
        
        # Simple heuristic based on error count
        if error_count > 20:
            return base_attempts + 2
        elif error_count > 10:
            return base_attempts + 1
        elif error_count > 5:
            return base_attempts
        
        return base_attempts
    
    @staticmethod
    def get_permissive_compiler_flags(language: str) -> List[str]:
        """
        Get compiler flags that allow more permissive compilation.
        
        Args:
            language: Programming language
            
        Returns:
            List of compiler flags
        """
        flags = []
        
        if language == 'cpp':
            flags.extend([
                '-fpermissive',  # Downgrade errors to warnings
                '-Wno-error',    # Don't treat warnings as errors
            ])
        elif language == 'c':
            flags.extend([
                '-Wno-error',    # Don't treat warnings as errors
                '-Wno-implicit-function-declaration',  # Allow implicit declarations
            ])
        
        return flags
    
    @staticmethod
    def apply_fallback_strategy(
        source_code: str,
        errors: List[str],
        language: str = "c"
    ) -> str:
        """
        Apply aggressive fallback strategy: comment out problematic sections.
        
        Args:
            source_code: Original source code
            errors: List of error messages
            language: Programming language
            
        Returns:
            Code with problematic sections commented out
        """
        if not errors:
            return source_code
        
        try:
            lines = source_code.split('\n')
            lines_to_comment = set()
            comment_char = "//" if language in ['c', 'cpp'] else "#"
            
            # Extract line numbers from errors
            # Only comment out the exact line with error, not surrounding lines
            # to avoid creating new errors
            for error in errors:
                # Pattern 1: "file.c:123:45: error: ..." or "file.c:123: error: ..."
                match = re.search(r':(\d+)(?::\d+)?:\s*(?:error|warning|fatal)', error)
                if match:
                    try:
                        line_num = int(match.group(1))
                        if 1 <= line_num <= len(lines):
                            line_idx = line_num - 1
                            # Only comment out the exact line, not surrounding lines
                            # to avoid breaking related code
                            lines_to_comment.add(line_idx)
                    except (ValueError, IndexError):
                        continue
                
                # Pattern 2: "At line 123" or "line 123"
                match = re.search(r'(?:at\s+)?line\s+(\d+)', error, re.IGNORECASE)
                if match:
                    try:
                        line_num = int(match.group(1))
                        if 1 <= line_num <= len(lines):
                            line_idx = line_num - 1
                            lines_to_comment.add(line_idx)
                    except (ValueError, IndexError):
                        continue
            
            # If ErrorAnalyzer is available, use it for better analysis
            if ErrorAnalyzer:
                try:
                    error_infos = ErrorAnalyzer.classify_errors(errors)
                    strategy = ErrorAnalyzer.get_fix_strategy(error_infos)
                    
                    # For missing headers, comment out the include lines
                    missing_headers = strategy.get('missing_headers', [])
                    if missing_headers:
                        for i, line in enumerate(lines):
                            if line.strip().startswith('#include'):
                                # Check if this include matches any missing header
                                for header in missing_headers:
                                    # Match header name (handle both <header> and "header" formats)
                                    header_basename = header.split('/')[-1].split('\\')[-1]
                                    if header_basename in line or header in line:
                                        lines_to_comment.add(i)
                                        break
                    
                    # For undefined symbols, try to comment out function calls or declarations
                    undefined_symbols = strategy.get('undefined_symbols', [])
                    if undefined_symbols and not lines_to_comment:
                        # If we don't have line numbers, try to find and comment out symbol usage
                        for symbol in undefined_symbols[:3]:  # Limit to first 3 to avoid over-commenting
                            symbol_escaped = re.escape(symbol)
                            # Pattern to find function calls or declarations
                            for i, line in enumerate(lines):
                                # Comment out function calls (e.g., "function_name(")
                                if re.search(rf'\b{symbol_escaped}\s*\(', line):
                                    lines_to_comment.add(i)
                                    break
                                # Comment out variable usage (e.g., "variable_name;")
                                elif re.search(rf'\b{symbol_escaped}\s*[;=]', line):
                                    lines_to_comment.add(i)
                                    break
                except Exception as e:
                    logger.debug(f"ErrorAnalyzer failed in fallback: {e}")
                    pass
            
            # If no lines were identified but we have errors, try a more aggressive approach
            if not lines_to_comment and errors:
                # Try to find and comment out lines with common error patterns
                for error in errors:
                    # Look for undefined symbols in the error
                    undefined_match = re.search(r"undefined reference to\s*['\"]([^'\"]+)['\"]", error, re.IGNORECASE)
                    if undefined_match:
                        symbol = undefined_match.group(1)
                        # Find lines using this symbol
                        for i, line in enumerate(lines):
                            if symbol in line and not line.strip().startswith(comment_char):
                                # Only comment out if it's a function call or assignment
                                if re.search(rf'\b{re.escape(symbol)}\s*[\(=;]', line):
                                    lines_to_comment.add(i)
                                    if len(lines_to_comment) >= 3:  # Limit to 3 lines
                                        break
                        if len(lines_to_comment) >= 3:
                            break
                    
                    # Look for missing headers in the error
                    header_match = re.search(r"fatal error:\s*([^:]+\.h[^:]*):", error, re.IGNORECASE)
                    if header_match:
                        header_name = header_match.group(1).strip()
                        # Find include lines
                        for i, line in enumerate(lines):
                            if line.strip().startswith('#include') and header_name in line:
                                lines_to_comment.add(i)
                                break
            
            # Comment out problematic lines
            result_lines = []
            for i, line in enumerate(lines):
                if i in lines_to_comment and line.strip() and not line.strip().startswith(comment_char):
                    # Comment out the line
                    result_lines.append(f"{comment_char} FIXME: Commented out due to compilation error")
                    result_lines.append(f"{comment_char} {line}")
                else:
                    result_lines.append(line)
            
            return '\n'.join(result_lines)
        
        except Exception as e:
            logger.warning(f"Fallback strategy failed: {e}")
            return source_code
    
    @staticmethod
    def create_minimal_working_version(
        source_code: str,
        errors: List[str],
        language: str = "c"
    ) -> str:
        """
        Create a minimal working version by removing problematic code.
        
        Args:
            source_code: Original source code
            errors: List of error messages
            language: Programming language
            
        Returns:
            Minimal working version of code
        """
        if not ErrorAnalyzer:
            return source_code
        
        try:
            error_infos = ErrorAnalyzer.classify_errors(errors)
            strategy = ErrorAnalyzer.get_fix_strategy(error_infos)
            
            lines = source_code.split('\n')
            result_lines = []
            
            # Keep only essential parts
            for i, line in enumerate(lines):
                # Check if this line has an error
                has_error = any(
                    error_info.line_num == i + 1
                    for error_info in error_infos
                )
                
                if has_error:
                    # Skip this line and related code
                    continue
                
                # Keep includes (but comment out missing ones)
                if line.strip().startswith('#include'):
                    if strategy.get('has_missing_headers'):
                        missing_headers = strategy.get('missing_headers', [])
                        header_name = re.search(r'<([^>]+)>|"([^"]+)"', line)
                        if header_name:
                            header = header_name.group(1) or header_name.group(2)
                            if any(mh in header for mh in missing_headers):
                                result_lines.append(f"// {line}  // Commented: missing header")
                                continue
                    result_lines.append(line)
                else:
                    result_lines.append(line)
            
            return '\n'.join(result_lines)
        
        except Exception as e:
            logger.warning(f"Minimal version creation failed: {e}")
            return source_code
    
    @staticmethod
    def apply_pattern_fixes(source_code: str, errors: List[str], language: str = "c") -> str:
        """
        Apply pattern-based fixes for common error patterns.
        
        Args:
            source_code: Original source code
            errors: List of error messages
            language: Programming language
            
        Returns:
            Code with pattern-based fixes applied
        """
        fixed_code = source_code
        comment_char = "//" if language in ['c', 'cpp'] else "#"
        
        # Pattern 0: Non-standard Microsoft functions
        # These are easy replacements that don't need LLM
        non_standard_replacements = {
            r'\b_halloc\b': 'malloc',      # Huge memory allocation -> standard malloc
            r'\b_hfree\b': 'free',          # Huge memory free -> standard free
            r'\b_memccpy\b': 'memccpy',     # Remove underscore prefix
            r'\b_memicmp\b': 'memcmp',      # Case-insensitive -> standard (may need manual fix)
            r'\b_strdup\b': 'strdup',       # Remove underscore prefix
            r'\b_stricmp\b': 'strcasecmp',  # Case-insensitive compare (POSIX)
            r'\b_strnicmp\b': 'strncasecmp',# Case-insensitive n-compare (POSIX)
            r'\b_snprintf\b': 'snprintf',   # Remove underscore prefix
            r'\b_vsnprintf\b': 'vsnprintf', # Remove underscore prefix
        }
        
        replacements_made = []
        for pattern, replacement in non_standard_replacements.items():
            if re.search(pattern, fixed_code):
                # Check if this function is in the errors
                func_name = pattern.strip('\\b')
                if any(func_name in error for error in errors):
                    old_code = fixed_code
                    fixed_code = re.sub(pattern, replacement, fixed_code)
                    if fixed_code != old_code:
                        replacements_made.append(f"{func_name} -> {replacement}")
        
        if replacements_made:
            logger.info(f"Applied non-standard function fixes: {', '.join(replacements_made)}")
        
        # Pattern 1: Missing header - comment out
        missing_header_patterns = [
            r"fatal error:\s*([^:]+\.h[^:]*):",
            r"no such file or directory:\s*['\"]?([^:'\"]+\.h[^:'\"]*)['\"]?",
            r"cannot open source file\s*['\"]([^'\"]+\.h[^'\"]*)['\"]",
        ]
        
        commented_headers = set()
        for error in errors:
            for pattern in missing_header_patterns:
                match = re.search(pattern, error, re.IGNORECASE)
                if match:
                    header_name = match.group(1).strip()
                    if header_name not in commented_headers:
                        commented_headers.add(header_name)
                        # Find and comment out the include (handle both <header> and "header" formats)
                        include_patterns = [
                            rf'#include\s*<{re.escape(header_name)}>',
                            rf'#include\s*"{re.escape(header_name)}"',
                            rf'#include\s*<[^>]*{re.escape(header_name.split("/")[-1])}[^>]*>',  # Partial match
                            rf'#include\s*"[^"]*{re.escape(header_name.split("/")[-1])}[^"]*"',  # Partial match
                        ]
                        for include_pattern in include_patterns:
                            fixed_code = re.sub(
                                include_pattern,
                                lambda m: f"{comment_char} {m.group(0)}  // Commented: missing header",
                                fixed_code,
                                flags=re.IGNORECASE
                            )
        
        # Pattern 2: Undefined function - add forward declaration (only for C, not C++)
        if language == 'c':
            undefined_func_pattern = r"undefined reference to ['\"]([^'\"]+)['\"]"
            forward_decls = []
            seen_funcs = set()
            for error in errors:
                match = re.search(undefined_func_pattern, error, re.IGNORECASE)
                if match:
                    func_name = match.group(1)
                    # Skip C++ mangled names and common library functions
                    if func_name not in seen_funcs and not func_name.startswith('_Z'):
                        seen_funcs.add(func_name)
                        forward_decls.append(f"{comment_char} Forward declaration for {func_name}\nvoid {func_name}();")
            
            if forward_decls:
                # Add forward declarations after includes
                include_end = fixed_code.rfind('#include')
                if include_end != -1:
                    # Find end of last include block
                    next_line = fixed_code.find('\n', include_end)
                    while next_line != -1 and next_line < len(fixed_code) - 1:
                        next_char = fixed_code[next_line + 1]
                        if next_char == '#':
                            # Check if it's another include
                            if fixed_code[next_line + 1:next_line + 9] == '#include':
                                next_line = fixed_code.find('\n', next_line + 1)
                            else:
                                break
                        else:
                            break
                    
                    if next_line != -1:
                        fixed_code = (
                            fixed_code[:next_line + 1] +
                            '\n'.join(forward_decls) + '\n' +
                            fixed_code[next_line + 1:]
                        )
        
        return fixed_code


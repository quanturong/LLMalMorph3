"""
Error analysis and classification module — multi-compiler.

Classifies MSVC, GCC, and Clang compiler/linker errors into semantic types
and builds a fix strategy dict consumed by auto_fixer to steer prompts.

Supports compiler_type: 'msvc' (default), 'gcc', 'clang'.
When compiler_type is 'auto', the analyzer detects the compiler from
error message format heuristics.
"""
import re
import logging
from typing import List, Dict, Optional, Set
from enum import Enum


logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# Error taxonomy
# ═══════════════════════════════════════════════════════════════════

class ErrorType(Enum):
    """Semantic types of compilation/link errors."""
    MISSING_HEADER = "missing_header"
    UNDEFINED_SYMBOL = "undefined_symbol"
    SYNTAX_ERROR = "syntax_error"
    TYPE_MISMATCH = "type_mismatch"
    LINKING_ERROR = "linking_error"
    REDEFINITION = "redefinition"
    ENVIRONMENT = "environment"       # SDK/toolchain issue, NOT code bug
    UNKNOWN = "unknown"


# ═══════════════════════════════════════════════════════════════════
# Compiler type constants
# ═══════════════════════════════════════════════════════════════════

COMPILER_MSVC = 'msvc'
COMPILER_GCC = 'gcc'
COMPILER_CLANG = 'clang'
COMPILER_AUTO = 'auto'


# ═══════════════════════════════════════════════════════════════════
# MSVC error-code → ErrorType mapping (authoritative)
# ═══════════════════════════════════════════════════════════════════

_MSVC_ERROR_MAP: Dict[str, ErrorType] = {
    # ── Missing header / cannot open include file ──
    'C1083': ErrorType.MISSING_HEADER,   # cannot open include file
    'C1189': ErrorType.MISSING_HEADER,   # #error directive (often "include guard" issues)

    # ── Undefined symbols ──
    'C2065': ErrorType.UNDEFINED_SYMBOL,  # undeclared identifier
    'C3861': ErrorType.UNDEFINED_SYMBOL,  # identifier not found
    'C2059': ErrorType.UNDEFINED_SYMBOL,  # syntax error on token (often undefined type)
    'C2057': ErrorType.UNDEFINED_SYMBOL,  # expected constant expression (VLA / undef const)
    'C2466': ErrorType.UNDEFINED_SYMBOL,  # cannot allocate array of constant size 0
    'C2133': ErrorType.UNDEFINED_SYMBOL,  # unknown size

    # ── Syntax errors ──
    'C2143': ErrorType.SYNTAX_ERROR,      # syntax error: missing 'X' before 'Y'
    'C2061': ErrorType.SYNTAX_ERROR,      # syntax error: identifier
    'C2146': ErrorType.SYNTAX_ERROR,      # syntax error: missing ';' before
    'C2059': ErrorType.SYNTAX_ERROR,      # syntax error: 'token' (also used for undef types)
    'C1075': ErrorType.SYNTAX_ERROR,      # unmatched left brace
    'C2449': ErrorType.SYNTAX_ERROR,      # illegal declaration in file scope
    'C4430': ErrorType.SYNTAX_ERROR,      # missing type specifier (int assumed)

    # ── Type mismatches ──
    'C2440': ErrorType.TYPE_MISMATCH,     # cannot convert from X to Y
    'C2664': ErrorType.TYPE_MISMATCH,     # cannot convert argument N from X to Y
    'C4133': ErrorType.TYPE_MISMATCH,     # incompatible types
    'C2373': ErrorType.TYPE_MISMATCH,     # redefinition; different type modifiers
    'C2220': ErrorType.TYPE_MISMATCH,     # warning treated as error (often type warnings)

    # ── Linker errors ──
    'LNK2019': ErrorType.LINKING_ERROR,   # unresolved external symbol
    'LNK2001': ErrorType.LINKING_ERROR,   # unresolved external symbol
    'LNK1120': ErrorType.LINKING_ERROR,   # N unresolved externals
    'LNK2005': ErrorType.LINKING_ERROR,   # symbol already defined (duplicate)
    'LNK1169': ErrorType.LINKING_ERROR,   # multiply defined symbols found

    # ── Redefinition ──
    'C2370': ErrorType.REDEFINITION,      # redefinition; different storage class
    'C2371': ErrorType.REDEFINITION,      # redefinition; different basic types
    'C2011': ErrorType.REDEFINITION,      # 'X' : 'class/struct' type redefinition
    'C2086': ErrorType.REDEFINITION,      # 'X' : redefinition

    # ── Environment (SDK / toolchain) ──
    'C1034': ErrorType.ENVIRONMENT,       # no include path set
    'C1902': ErrorType.ENVIRONMENT,       # program database manager mismatch
    'D8016': ErrorType.ENVIRONMENT,       # incompatible command-line options
}

# ═══════════════════════════════════════════════════════════════════
# GCC/Clang error-code → ErrorType mapping
# GCC uses -Werror= flags; Clang uses -W flags and diagnostic groups.
# Both share similar keyword-based error messages.
# ═══════════════════════════════════════════════════════════════════

_GCC_CLANG_KEYWORD_PATTERNS: List[tuple] = [
    # ── Missing header ──
    # GCC/Clang: fatal error: foo.h: No such file or directory
    (ErrorType.MISSING_HEADER, re.compile(
        r'fatal error:.*no such file|cannot find include file|'
        r'file not found|\'[^\']+\.h(?:pp)?\' file not found',
        re.IGNORECASE)),

    # ── Linker errors (check BEFORE undefined symbols — both say "undefined") ──
    # ld: undefined reference to 'symbol'
    # collect2: error: ld returned 1 exit status
    # multiple definition of 'symbol'
    (ErrorType.LINKING_ERROR, re.compile(
        r'undefined reference to|multiple definition of|'
        r'ld returned \d+ exit status|duplicate symbol|'
        r'relocation .* against .* can not be used',
        re.IGNORECASE)),

    # ── Undefined symbols ──
    # GCC: 'foo' undeclared / was not declared in this scope / use of undeclared
    # Clang: use of undeclared identifier 'foo'
    (ErrorType.UNDEFINED_SYMBOL, re.compile(
        r'undeclared identifier|was not declared in this scope|'
        r'has not been declared|use of undeclared|'
        r'implicit declaration of function|'
        r'unknown type name',
        re.IGNORECASE)),

    # ── Redefinition ──
    # GCC/Clang: redefinition of 'struct foo' / redefined / previous definition
    (ErrorType.REDEFINITION, re.compile(
        r'redefinition of|previous definition|'
        r'redefined|conflicting types for',
        re.IGNORECASE)),

    # ── Type mismatches ──
    # GCC: incompatible types / invalid conversion / cannot convert
    # Clang: incompatible pointer types / implicit conversion
    (ErrorType.TYPE_MISMATCH, re.compile(
        r'incompatible (?:pointer )?types?|cannot convert|'
        r'invalid conversion|incompatible integer to pointer|'
        r'pointer type mismatch|implicit conversion',
        re.IGNORECASE)),

    # ── Syntax errors ──
    # GCC/Clang: expected ';' / expected declaration / parse error
    (ErrorType.SYNTAX_ERROR, re.compile(
        r'expected [\'\"][;\}\)\{]|expected declaration|'
        r'parse error|extraneous closing brace|'
        r'expected expression|expected identifier|'
        r'expected \';\' after',
        re.IGNORECASE)),
]

# GCC/Clang diagnostic flag → ErrorType (for -Werror=xxx patterns)
_GCC_DIAG_MAP: Dict[str, ErrorType] = {
    'implicit-function-declaration': ErrorType.UNDEFINED_SYMBOL,
    'implicit-int': ErrorType.SYNTAX_ERROR,
    'incompatible-pointer-types': ErrorType.TYPE_MISMATCH,
    'int-conversion': ErrorType.TYPE_MISMATCH,
    'return-type': ErrorType.TYPE_MISMATCH,
    'missing-declarations': ErrorType.UNDEFINED_SYMBOL,
    'missing-prototypes': ErrorType.UNDEFINED_SYMBOL,
}

_GCC_DIAG_RE = re.compile(r'\[-W([\w-]+)\]')

_MSVC_CODE_RE = re.compile(r'\b(C\d{4}|LNK\d{4}|D\d{4})\b')


def detect_compiler_from_errors(errors: List[str]) -> str:
    """Detect compiler type from error message format heuristics.

    Returns: 'msvc', 'gcc', 'clang', or 'auto' (unknown).
    """
    msvc_score = 0
    gcc_score = 0
    clang_score = 0
    for err in errors[:30]:  # sample first 30 for speed
        # MSVC: file.c(123) : error C2065: ...
        if _MSVC_CODE_RE.search(err):
            msvc_score += 2
        if re.search(r'\(\d+\)\s*:', err):
            msvc_score += 1
        # GCC: file.c:123:45: error: ...
        if re.search(r':\d+:\d+:\s*(?:error|warning):', err):
            gcc_score += 1
        # Clang-specific: often includes [-Wfoo] and "note:" lines
        if '[-W' in err:
            clang_score += 1
            gcc_score += 1  # Clang shares GCC format
        if 'clang' in err.lower():
            clang_score += 3
        if 'gcc' in err.lower() or 'collect2' in err.lower():
            gcc_score += 2
        # ld / linker patterns
        if 'undefined reference to' in err.lower():
            gcc_score += 1
        if 'unresolved external symbol' in err.lower():
            msvc_score += 1

    if msvc_score > gcc_score and msvc_score > clang_score:
        return COMPILER_MSVC
    if clang_score > gcc_score:
        return COMPILER_CLANG
    if gcc_score > 0:
        return COMPILER_GCC
    return COMPILER_AUTO  # unable to determine

# SDK headers that missing → environment problem, not code bug
_SDK_HEADERS: Set[str] = {
    'windows.h', 'winsock2.h', 'ws2tcpip.h', 'wininet.h', 'wincrypt.h',
    'shlwapi.h', 'shellapi.h', 'shlobj.h', 'tlhelp32.h', 'psapi.h',
    'iphlpapi.h', 'winhttp.h', 'wtsapi32.h', 'userenv.h', 'dbghelp.h',
    'ntstatus.h', 'winternl.h', 'intrin.h', 'process.h', 'io.h',
    'direct.h', 'tchar.h', 'conio.h', 'mbstring.h',
    'stdio.h', 'stdlib.h', 'string.h', 'math.h', 'time.h', 'errno.h',
    'stdint.h', 'stddef.h', 'limits.h', 'ctype.h', 'signal.h', 'assert.h',
    'stdbool.h', 'locale.h', 'float.h', 'stdarg.h',
}


# ═══════════════════════════════════════════════════════════════════
# ErrorInfo
# ═══════════════════════════════════════════════════════════════════

class ErrorInfo:
    """Parsed information about a single compilation error."""

    __slots__ = ('error_text', 'error_type', 'line_num', 'error_code',
                 'header_name', 'symbol_name')

    def __init__(self, error_text: str, error_type: ErrorType,
                 line_num: Optional[int] = None,
                 error_code: Optional[str] = None):
        self.error_text = error_text
        self.error_type = error_type
        self.line_num = line_num
        self.error_code = error_code
        self.header_name: Optional[str] = None
        self.symbol_name: Optional[str] = None

        # Auto-extract detail fields
        if error_type == ErrorType.MISSING_HEADER:
            self._extract_header_name()
        elif error_type in (ErrorType.UNDEFINED_SYMBOL, ErrorType.TYPE_MISMATCH,
                            ErrorType.REDEFINITION):
            self._extract_symbol_name()
        elif error_type == ErrorType.LINKING_ERROR:
            self._extract_linker_symbol()

    # ── MSVC-first extractors ──

    def _extract_header_name(self):
        """Extract header filename from MSVC C1083 or GCC 'No such file' messages."""
        patterns = [
            # MSVC: error C1083: cannot open include file: 'header.h': No such file
            r"C1083.*?['\"]([^'\"]+)['\"]",
            # GCC: fatal error: header.h: No such file or directory
            r"fatal error:\s*([^:]+\.[hH][^:]*)\s*:",
            # GCC variant
            r"no such file or directory.*?['\"]?([^'\":\s]+\.[hH][^'\":\s]*)",
            # MSVC: cannot open source file "header.h"
            r'cannot open source file\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, self.error_text, re.IGNORECASE)
            if match:
                self.header_name = match.group(1).strip()
                break

    def _extract_symbol_name(self):
        """Extract symbol name from MSVC C2065/C3861/C2440 or GCC undefined messages."""
        patterns = [
            # MSVC C2065: 'symbol' : undeclared identifier
            r"['\"]([^'\"]+)['\"]\s*:\s*undeclared",
            # MSVC C3861: 'func': identifier not found
            r"['\"]([^'\"]+)['\"]\s*:\s*identifier not found",
            # MSVC C2440/C2664: 'symbol' — general quoted identifier
            r"(?:C2440|C2664|C2373|C2011|C2086|C2370|C2371).*?['\"]([^'\"]+)['\"]",
            # GCC: 'symbol' undeclared / was not declared
            r"['\"]([^'\"]+)['\"]\s+(?:undeclared|was not declared)",
            # GCC: undefined reference to 'symbol'
            r"undefined reference to\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, self.error_text, re.IGNORECASE)
            if match:
                self.symbol_name = match.group(1).strip()
                break

    def _extract_linker_symbol(self):
        """Extract unresolved symbol from MSVC LNK2019/LNK2001."""
        patterns = [
            # MSVC LNK2019: unresolved external symbol _FuncName referenced in ...
            r'unresolved external symbol\s+_?(\S+)',
            # MSVC LNK2005: symbol already defined in obj
            r'LNK2005.*?["\']?(\S+)["\']?\s+already defined',
            # GCC: undefined reference to 'sym'
            r"undefined reference to\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, self.error_text, re.IGNORECASE)
            if match:
                self.symbol_name = match.group(1).strip()
                break

    def __repr__(self):
        code_str = f" [{self.error_code}]" if self.error_code else ""
        return (f"ErrorInfo(type={self.error_type.value}{code_str}, "
                f"line={self.line_num}, text={self.error_text[:60]}...)")


# ═══════════════════════════════════════════════════════════════════
# ErrorAnalyzer
# ═══════════════════════════════════════════════════════════════════

class ErrorAnalyzer:
    """Analyzes compilation errors and classifies them — multi-compiler."""

    @staticmethod
    def classify_errors(errors: List[str], compiler_type: str = 'auto') -> List[ErrorInfo]:
        """Classify compilation errors into semantic types.

        Args:
            errors: List of raw error message strings.
            compiler_type: 'msvc', 'gcc', 'clang', or 'auto' (auto-detect).
        """
        # Resolve 'auto' to a concrete compiler type
        if compiler_type == COMPILER_AUTO or compiler_type not in (
            COMPILER_MSVC, COMPILER_GCC, COMPILER_CLANG,
        ):
            compiler_type = detect_compiler_from_errors(errors)

        error_infos = []
        for error in errors:
            error_code = ErrorAnalyzer._extract_error_code(error, compiler_type)
            error_type = ErrorAnalyzer._classify_error(error, error_code, compiler_type)
            line_num = ErrorAnalyzer._extract_line_number(error)
            ei = ErrorInfo(error, error_type, line_num, error_code)

            # Post-classify: C1083 on SDK header → ENVIRONMENT, not MISSING_HEADER
            if (ei.error_type == ErrorType.MISSING_HEADER
                    and ei.header_name
                    and ei.header_name.lower() in _SDK_HEADERS):
                ei.error_type = ErrorType.ENVIRONMENT

            error_infos.append(ei)
        return error_infos

    @staticmethod
    def _extract_error_code(error: str, compiler_type: str = COMPILER_MSVC) -> Optional[str]:
        """Extract the first error code from a compiler message.

        MSVC: C####/LNK####/D####
        GCC/Clang: -Wfoo-bar diagnostic flag (returned as 'W:foo-bar')
        """
        # Always try MSVC code first (fast regex)
        m = _MSVC_CODE_RE.search(error)
        if m:
            return m.group(1)

        # GCC/Clang: extract -Wfoo from [-Wfoo]
        if compiler_type in (COMPILER_GCC, COMPILER_CLANG, COMPILER_AUTO):
            dm = _GCC_DIAG_RE.search(error)
            if dm:
                return f'W:{dm.group(1)}'

        return None

    @staticmethod
    def _classify_error(error: str, error_code: Optional[str] = None,
                        compiler_type: str = COMPILER_MSVC) -> ErrorType:
        """Classify a single error — routes to compiler-specific logic."""

        # ── 1. MSVC code-based classification (reliable) ──
        if error_code and error_code in _MSVC_ERROR_MAP:
            return _MSVC_ERROR_MAP[error_code]

        # ── 2. GCC/Clang: diagnostic flag lookup ──
        if error_code and error_code.startswith('W:'):
            diag_name = error_code[2:]  # strip 'W:' prefix
            if diag_name in _GCC_DIAG_MAP:
                return _GCC_DIAG_MAP[diag_name]

        # ── 3. Keyword-based classification (works for all compilers) ──
        # GCC/Clang structured keyword patterns (higher precision)
        for etype, pattern in _GCC_CLANG_KEYWORD_PATTERNS:
            if pattern.search(error):
                return etype

        # ── 4. Legacy keyword fallback for any unlisted pattern ──
        error_lower = error.lower()

        # Missing headers
        if ('no such file or directory' in error_lower
                or 'cannot open source file' in error_lower):
            if '.h' in error_lower or '.hpp' in error_lower:
                return ErrorType.MISSING_HEADER

        # Linker errors — check BEFORE undefined symbols (both say "undefined")
        if any(kw in error_lower for kw in (
            'unresolved external', 'multiple definition',
            'duplicate symbol', 'multiply defined',
        )):
            return ErrorType.LINKING_ERROR

        # Undefined symbols
        if any(kw in error_lower for kw in (
            'undeclared identifier', 'was not declared in this scope',
            'has not been declared', 'use of undeclared',
        )):
            return ErrorType.UNDEFINED_SYMBOL

        # Type mismatches
        if any(kw in error_lower for kw in (
            'incompatible types', 'cannot convert',
            'invalid conversion', 'type mismatch',
        )):
            return ErrorType.TYPE_MISMATCH

        # Syntax errors
        if any(kw in error_lower for kw in (
            'syntax error', 'parse error',
            "expected ';'", 'expected declaration',
        )):
            return ErrorType.SYNTAX_ERROR

        return ErrorType.UNKNOWN

    @staticmethod
    def _extract_line_number(error: str) -> Optional[int]:
        """Extract line number — supports MSVC file(line) and GCC file:line:col formats."""
        # MSVC: file.c(123) : error C2065: ...
        m = re.search(r'\((\d+)\)\s*:', error)
        if m:
            return int(m.group(1))
        # GCC: file.c:123:45: error: ...
        m = re.search(r':(\d+):\d+:', error)
        if m:
            return int(m.group(1))
        return None

    @staticmethod
    def group_errors_by_type(error_infos: List[ErrorInfo]) -> Dict[ErrorType, List[ErrorInfo]]:
        """Group errors by their semantic type."""
        grouped: Dict[ErrorType, List[ErrorInfo]] = {}
        for ei in error_infos:
            grouped.setdefault(ei.error_type, []).append(ei)
        return grouped

    @staticmethod
    def get_fix_strategy(error_infos: List[ErrorInfo], compiler_type: str = COMPILER_MSVC) -> Dict[str, object]:
        """Build a fix strategy dict consumed by auto_fixer prompt builder."""
        grouped = ErrorAnalyzer.group_errors_by_type(error_infos)

        # Deduplicate symbol/header names
        missing_headers = list(dict.fromkeys(
            e.header_name for e in grouped.get(ErrorType.MISSING_HEADER, [])
            if e.header_name
        ))
        undefined_symbols = list(dict.fromkeys(
            e.symbol_name for e in grouped.get(ErrorType.UNDEFINED_SYMBOL, [])
            if e.symbol_name
        ))
        linker_symbols = list(dict.fromkeys(
            e.symbol_name for e in grouped.get(ErrorType.LINKING_ERROR, [])
            if e.symbol_name
        ))

        # Collect all error codes seen
        all_codes = [ei.error_code for ei in error_infos if ei.error_code]

        strategy = {
            'has_missing_headers': ErrorType.MISSING_HEADER in grouped,
            'has_undefined_symbols': ErrorType.UNDEFINED_SYMBOL in grouped,
            'has_syntax_errors': ErrorType.SYNTAX_ERROR in grouped,
            'has_type_mismatches': ErrorType.TYPE_MISMATCH in grouped,
            'has_linking_errors': ErrorType.LINKING_ERROR in grouped,
            'has_redefinitions': ErrorType.REDEFINITION in grouped,
            'has_environment_issues': ErrorType.ENVIRONMENT in grouped,
            'missing_headers': missing_headers,
            'undefined_symbols': undefined_symbols,
            'linker_symbols': linker_symbols,
            'error_codes': list(dict.fromkeys(all_codes)),
            'msvc_codes': list(dict.fromkeys(all_codes)),  # legacy compat
            'compiler_type': compiler_type,
            'total_errors': len(error_infos),
            'error_types': {et.value: len(errs) for et, errs in grouped.items()},
        }

        return strategy


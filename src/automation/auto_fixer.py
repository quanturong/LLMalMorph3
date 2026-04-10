"""
Automatic error fixing using LLM.
Fixes compilation errors and code issues automatically.
"""
import json
import logging
import os
import re
from typing import Dict, List, Optional, Tuple
from llm_api import get_llm_provider, LLMAPIError
try:
    from .error_analyzer import (
        ErrorAnalyzer, ErrorType,
        detect_compiler_from_errors,
        COMPILER_MSVC, COMPILER_GCC, COMPILER_CLANG, COMPILER_AUTO,
    )
except ImportError:
    # Fallback if error_analyzer is not available
    ErrorAnalyzer = None
    ErrorType = None
    detect_compiler_from_errors = None
    COMPILER_MSVC = 'msvc'
    COMPILER_GCC = 'gcc'
    COMPILER_CLANG = 'clang'
    COMPILER_AUTO = 'auto'

try:
    from .fix_history_rag import FixHistoryRAG
except (ImportError, SystemError):
    try:
        from fix_history_rag import FixHistoryRAG
    except ImportError:
        FixHistoryRAG = None

try:
    from .semantic_validator import get_semantic_validator, SemanticValidator
except (ImportError, SystemError):
    try:
        from semantic_validator import get_semantic_validator, SemanticValidator
    except ImportError:
        get_semantic_validator = None  # type: ignore
        SemanticValidator = None  # type: ignore

logger = logging.getLogger(__name__)

# ── AST availability check ─────────────────────────────────────────
# When tree-sitter is not available, validation runs in DEGRADED MODE:
# all thresholds become stricter to compensate for losing structural analysis.
_AST_AVAILABLE: bool = False
try:
    _sv = get_semantic_validator() if get_semantic_validator else None
    _AST_AVAILABLE = bool(_sv and _sv.available)
    del _sv
except Exception:
    pass

if not _AST_AVAILABLE:
    logger.warning(
        "⚠️  auto_fixer: tree-sitter NOT available — running in DEGRADED MODE. "
        "Validation will use stricter heuristic thresholds to compensate. "
        "Install tree-sitter + tree-sitter-c/cpp for full semantic validation."
    )


# ── Win32 domain knowledge (loaded from external JSON config) ──────
_WIN32_KNOWLEDGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'configs', 'win32_knowledge.json'
)
_win32_knowledge_cache: Optional[dict] = None


def _load_win32_knowledge() -> dict:
    """Lazy-load Win32 domain tables from configs/win32_knowledge.json."""
    global _win32_knowledge_cache
    if _win32_knowledge_cache is not None:
        return _win32_knowledge_cache
    try:
        with open(_WIN32_KNOWLEDGE_PATH, 'r', encoding='utf-8') as f:
            _win32_knowledge_cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Could not load win32_knowledge.json: {e}. Using empty tables.")
        _win32_knowledge_cache = {}
    return _win32_knowledge_cache


# ── Error line parser ──────────────────────────────────────────────
_MSVC_LINE_RE  = re.compile(r'\((\d+)\)\s*:\s*(?:error|warning|fatal error|note)')  # file(106): error ...
_GCC_LINE_RE   = re.compile(r':(\d+):\d*:\s*(?:error|warning|fatal error|note)')    # file:106:15: error ...
_GENERIC_LINE_RE = re.compile(r'[:\(](\d+)[:\)]')                                   # fallback
_BARE_LINE_RE  = re.compile(r'line\s+(\d+)', re.IGNORECASE)                          # "line 106"


def _parse_error_line_numbers(errors: List[str]) -> List[int]:
    """Extract unique, sorted line numbers from compiler error messages."""
    lines: set = set()
    for err in errors:
        m = (_MSVC_LINE_RE.search(err) or _GCC_LINE_RE.search(err)
             or _GENERIC_LINE_RE.search(err) or _BARE_LINE_RE.search(err))
        if m:
            lines.add(int(m.group(1)))
    return sorted(lines)


def _group_into_regions(line_numbers: List[int], margin: int = 40, max_region_lines: int = 200) -> List[Tuple[int, int]]:
    """Merge nearby error lines into (start, end) regions.

    Adjacent errors within *margin* lines of each other are merged.
    Each region is expanded by *margin* lines on both sides.
    Regions exceeding *max_region_lines* are split.
    """
    if not line_numbers:
        return []

    regions: List[Tuple[int, int]] = []
    current_start = line_numbers[0] - margin
    current_end   = line_numbers[0] + margin

    for ln in line_numbers[1:]:
        if ln - margin <= current_end:
            # Merge — extend end
            current_end = ln + margin
        else:
            regions.append((max(1, current_start), current_end))
            current_start = ln - margin
            current_end   = ln + margin

    regions.append((max(1, current_start), current_end))

    # Split any region that is too large
    final: List[Tuple[int, int]] = []
    for s, e in regions:
        while e - s + 1 > max_region_lines:
            final.append((s, s + max_region_lines - 1))
            s += max_region_lines
        final.append((s, e))

    return final


# ── Surgical fix helpers ───────────────────────────────────────────

def _extract_global_declarations(source_lines: List[str], max_lines: int = 150) -> str:
    """Extract #include, #define, typedef, extern declarations from file header.

    Returns a compact summary of the first *max_lines* lines that contain
    global declarations.  This is provided as read-only context to each
    region fix so the LLM knows what is available globally.
    """
    decl_lines: List[str] = []
    for line in source_lines[:max_lines]:
        stripped = line.strip()
        if (stripped.startswith('#include') or stripped.startswith('#define')
                or stripped.startswith('#pragma') or stripped.startswith('#ifndef')
                or stripped.startswith('#ifdef') or stripped.startswith('#endif')
                or stripped.startswith('typedef ')
                or stripped.startswith('extern ')
                or stripped.startswith('using namespace')
                or stripped.startswith('namespace ')):
            decl_lines.append(line)
    return '\n'.join(decl_lines)


def _extract_function_signatures(section_text: str, language: str = "c") -> List[str]:
    """Extract function names from a code section using AST, with regex fallback.

    Uses tree-sitter AST when available; falls back to regex heuristic otherwise.
    """
    # ── AST path (preferred) ──
    sv = get_semantic_validator() if get_semantic_validator else None
    if sv and sv.available:
        names = sv.extract_function_names(section_text, language)
        if names:
            return names

    # ── Regex fallback ──
    pattern = re.compile(
        r'^[ \t]*'
        r'(?:static\s+|inline\s+|extern\s+|virtual\s+|__declspec\([^)]*\)\s+)*'
        r'(?:(?:unsigned|signed|const|volatile|struct|enum|union|class)\s+)*'
        r'(\w[\w:*&\s<>,]*?)\s+'
        r'(\w+)\s*'
        r'\([^)]*\)'
        r'(?:\s*(?:const|override|noexcept|final))*'
        r'\s*[{;]',
        re.MULTILINE
    )
    sigs = []
    for m in pattern.finditer(section_text):
        func_name = m.group(2)
        if func_name not in ('if', 'for', 'while', 'switch', 'return', 'sizeof',
                             'catch', 'throw', 'delete', 'new', 'else'):
            sigs.append(func_name)
    return sigs


def _check_brace_balance(text: str) -> int:
    """Return net brace balance ({  minus }) ignoring braces inside strings/comments."""
    balance = 0
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False
    prev = ''
    for ch in text:
        if in_line_comment:
            if ch == '\n':
                in_line_comment = False
        elif in_block_comment:
            if prev == '*' and ch == '/':
                in_block_comment = False
        elif in_string:
            if ch == '"' and prev != '\\':
                in_string = False
        elif in_char:
            if ch == "'" and prev != '\\':
                in_char = False
        else:
            if ch == '/' and prev == '/':
                in_line_comment = True
                balance -= 0  # no-op, just entering comment
            elif ch == '*' and prev == '/':
                in_block_comment = True
            elif ch == '"':
                in_string = True
            elif ch == "'":
                in_char = True
            elif ch == '{':
                balance += 1
            elif ch == '}':
                balance -= 1
        prev = ch
    return balance


def _extract_defined_symbols(section_text: str, language: str = "c") -> set:
    """Extract symbols (function names, global vars, macros, typedefs) defined in a section.

    Uses AST when available; regex fallback otherwise.
    These are symbols that OTHER regions may depend on, so they must be preserved.
    """
    # ── AST path (preferred) ──
    sv = get_semantic_validator() if get_semantic_validator else None
    if sv and sv.available:
        snap = sv.extract_snapshot(section_text, language)
        if snap is not None:
            symbols: set = set()
            symbols.update(snap.functions.keys())
            symbols.update(snap.types.keys())
            symbols.update(snap.globals.keys())
            symbols.update(snap.macros)
            return symbols

    # ── Regex fallback ──
    symbols = set()

    # Function definitions
    for name in _extract_function_signatures(section_text):
        symbols.add(name)

    # #define MACRO
    for m in re.finditer(r'^\s*#\s*define\s+(\w+)', section_text, re.MULTILINE):
        symbols.add(m.group(1))

    # typedef ... NAME ;
    for m in re.finditer(r'typedef\s+[^;]+\b(\w+)\s*;', section_text):
        symbols.add(m.group(1))

    # Global variable: TYPE NAME = ... or TYPE NAME;
    for m in re.finditer(
        r'^(?:static\s+|extern\s+|const\s+|volatile\s+)*'
        r'(?:unsigned\s+|signed\s+)?'
        r'(?:int|char|long|short|float|double|DWORD|HANDLE|BOOL|BYTE|WORD|LPSTR|LPCSTR|HMODULE|HKEY|SIZE_T|UINT|ULONG|LPBYTE|void)\s*\*?\s*'
        r'(\w+)\s*[=;]',
        section_text, re.MULTILINE):
        name = m.group(1)
        if name not in ('if', 'for', 'while', 'return'):
            symbols.add(name)

    return symbols


def _find_symbols_used_elsewhere(source_lines: List[str], reg_start: int, reg_end: int,
                                  defined_symbols: set) -> List[str]:
    """Find which symbols defined in [reg_start, reg_end] are referenced outside that region.

    AST-first: uses tree-sitter to find real identifier tokens (ignoring
    comments and string literals).  Falls back to regex word-boundary if
    AST is unavailable.
    """
    sv = get_semantic_validator() if get_semantic_validator else None
    if sv and sv.available:
        full_code = '\n'.join(source_lines)
        used_elsewhere: List[str] = []
        for sym in defined_symbols:
            if len(sym) < 2:
                continue
            ref_lines = sv.find_symbol_references(full_code, sym)
            # Check if any reference is outside the region
            if any(ln < reg_start or ln > reg_end for ln in ref_lines):
                used_elsewhere.append(sym)
        return used_elsewhere

    # ── Regex fallback (degraded mode) ──
    if not _AST_AVAILABLE:
        logger.debug("[degraded] _find_symbols_used_elsewhere: using regex word-boundary fallback")
    used_elsewhere = []
    for sym in defined_symbols:
        if len(sym) < 2:
            continue
        pattern = re.compile(r'\b' + re.escape(sym) + r'\b')
        for i, line in enumerate(source_lines, 1):
            if reg_start <= i <= reg_end:
                continue
            if pattern.search(line):
                used_elsewhere.append(sym)
                break
    return used_elsewhere


class AutoFixer:
    """
    Automatically fix compilation errors and code issues using LLM.
    """
    
    # Pattern to match project-specific includes (quoted includes)
    PROJECT_INCLUDE_PATTERN = re.compile(r'^(\s*#\s*include\s*"[^"]+"\s*)$', re.MULTILINE)
    
    @classmethod
    def _extract_project_includes(cls, code: str) -> set:
        """Extract all project-specific includes (quoted #include "...")"""
        includes = set()
        for match in cls.PROJECT_INCLUDE_PATTERN.finditer(code):
            includes.add(match.group(1).strip())
        return includes
    
    @classmethod
    def _extract_all_includes(cls, code: str) -> set:
        """Extract ALL #include lines (both quoted and angle bracket)"""
        includes = set()
        for m in re.finditer(r'^\s*(#\s*include\s*(?:["<][^">]+[">]))', code, re.MULTILINE):
            includes.add(m.group(1).strip())
        return includes

    @classmethod
    def _restore_removed_includes(cls, original_code: str, fixed_code: str) -> str:
        """
        Ensure no includes were removed by the LLM — both project-specific AND system.
        Critical system headers like <windows.h> must never be removed.
        """
        # Restore project-specific quoted includes
        original_includes = cls._extract_project_includes(original_code)
        fixed_includes = cls._extract_project_includes(fixed_code)
        removed = original_includes - fixed_includes

        # Also restore critical system includes if removed
        CRITICAL_SYSTEM_INCLUDES = {
            '<windows.h>', '<winsock2.h>', '<winsock.h>', '<wininet.h>',
            '<wincrypt.h>', '<shlobj.h>', '<tlhelp32.h>', '<psapi.h>',
            '<ws2tcpip.h>', '<iphlpapi.h>', '<objbase.h>', '<ole2.h>',
        }
        orig_sys = {m.group(1).strip() for m in re.finditer(
            r'^\s*(#\s*include\s*<[^>]+>)', original_code, re.MULTILINE)}
        fixed_sys = {m.group(1).strip() for m in re.finditer(
            r'^\s*(#\s*include\s*<[^>]+>)', fixed_code, re.MULTILINE)}
        removed_sys = set()
        for inc in (orig_sys - fixed_sys):
            # Normalize to just the bracket form for comparison
            bracket_form = re.sub(r'#\s*include\s*', '#include ', inc)
            angle = re.search(r'<([^>]+)>', inc)
            if angle:
                short = f'<{angle.group(1)}>'
                if any(short == c or short.lower() == c.lower() for c in CRITICAL_SYSTEM_INCLUDES):
                    removed_sys.add(inc)
        if removed_sys:
            logger.warning(f"\u26a0\ufe0f LLM removed {len(removed_sys)} critical system include(s), restoring:")
            for inc in removed_sys:
                logger.warning(f"   Restoring system: {inc}")
            removed = removed | removed_sys

        if not removed:
            return fixed_code
        
        logger.warning(f"⚠️ LLM removed {len(removed)} include(s), restoring them:")
        for inc in removed:
            logger.warning(f"   Restoring: {inc}")
        
        # Also check for commented-out includes and uncomment them
        for inc in removed:
            # Check if it was commented out (// #include or /* #include)
            commented_pattern = inc.replace('#', r'#').replace('"', r'"')
            commented_re = re.compile(r'(//\s*' + commented_pattern + r'|/\*\s*' + commented_pattern + r'\s*\*/)', re.IGNORECASE)
            if commented_re.search(fixed_code):
                # Uncomment by replacing the commented version with original
                fixed_code = commented_re.sub(inc, fixed_code)
            else:
                # Include was completely removed - add it back after #pragma once or at start
                if '#pragma once' in fixed_code:
                    fixed_code = fixed_code.replace('#pragma once', f'#pragma once\n{inc}', 1)
                else:
                    # Find first include and add before it
                    first_include = re.search(r'^(\s*#\s*include\s)', fixed_code, re.MULTILINE)
                    if first_include:
                        pos = first_include.start()
                        fixed_code = fixed_code[:pos] + inc + '\n' + fixed_code[pos:]
                    else:
                        # Add at the very beginning
                        fixed_code = inc + '\n' + fixed_code
        
        return fixed_code

    # ── Windows SDK collision sanitizer ────────────────────────────────
    # Loaded from configs/win32_knowledge.json — identifiers that MUST NOT
    # be #define'd or typedef'd in user code.
    _forbidden_defines_cache: Optional[set] = None
    _lowercase_to_correct_cache: Optional[Dict[str, str]] = None

    @classmethod
    def _get_forbidden_defines(cls) -> set:
        """Lazy-load forbidden defines from external config."""
        if cls._forbidden_defines_cache is None:
            data = _load_win32_knowledge()
            cls._forbidden_defines_cache = set(data.get('forbidden_defines', []))
        return cls._forbidden_defines_cache

    @classmethod
    def _get_lowercase_to_correct(cls) -> Dict[str, str]:
        """Lazy-load lowercase→correct casing map from external config."""
        if cls._lowercase_to_correct_cache is None:
            data = _load_win32_knowledge()
            cls._lowercase_to_correct_cache = data.get('lowercase_to_correct', {})
        return cls._lowercase_to_correct_cache

    @classmethod
    def _sanitize_dangerous_patterns(cls, code: str) -> str:
        """Remove #define / typedef that re-define Windows SDK identifiers.

        LLMs sometimes inject lines like ``#define string char*`` or
        ``typedef int BOOL;`` which break hundreds of SDK headers.  This
        pass strips them **before** the code is written to disk.
        """
        lines = code.split('\n')
        cleaned: list = []
        removed = 0

        for line in lines:
            stripped = line.strip()

            # #define FORBIDDEN ...
            m = re.match(r'^#\s*define\s+(\w+)', stripped)
            if m and m.group(1) in cls._get_forbidden_defines():
                logger.warning(f"   \U0001f6e1 Sanitizer: removed '#define {m.group(1)}' (Windows SDK conflict)")
                removed += 1
                continue

            # typedef ... FORBIDDEN ;
            m = re.match(r'^typedef\s+.*\b(\w+)\s*;', stripped)
            if m and m.group(1) in cls._get_forbidden_defines():
                logger.warning(f"   \U0001f6e1 Sanitizer: removed 'typedef ... {m.group(1)}' (Windows SDK conflict)")
                removed += 1
                continue

            # #define __STDC__  /  #undef __STDC__  (breaks MSVC internal headers)
            if re.match(r'^#\s*(?:define|undef)\s+__STDC__\b', stripped):
                logger.warning("   \U0001f6e1 Sanitizer: removed __STDC__ redefinition")
                removed += 1
                continue

            cleaned.append(line)

        if removed > 0:
            logger.info(f"   \U0001f6e1 Sanitizer removed {removed} dangerous definition(s)")

        # ── Remove typedef struct blocks that redefine Win32 types ─────
        # LLMs sometimes add "typedef struct tagXXX { ... } XXX, *PXXX;"
        # for types already in <windows.h>, causing C2371.
        result = '\n'.join(cleaned)
        _SDK_STRUCT_NAMES = {
            'MEMORY_BASIC_INFORMATION', 'PMEMORY_BASIC_INFORMATION',
            'SECURITY_ATTRIBUTES', 'LPSECURITY_ATTRIBUTES',
            'PROCESS_INFORMATION', 'STARTUPINFO', 'STARTUPINFOA', 'STARTUPINFOW',
            'PROCESSENTRY32', 'MODULEENTRY32', 'THREADENTRY32',
            'WIN32_FIND_DATA', 'WIN32_FIND_DATAA', 'WIN32_FIND_DATAW',
            'OVERLAPPED', 'CRITICAL_SECTION', 'WSADATA', 'SOCKADDR_IN',
            'FILETIME', 'SYSTEMTIME', 'LARGE_INTEGER', 'ULARGE_INTEGER',
            'COORD', 'SMALL_RECT', 'CONSOLE_SCREEN_BUFFER_INFO',
            'OSVERSIONINFO', 'OSVERSIONINFOA', 'OSVERSIONINFOW',
            'OSVERSIONINFOEX', 'OSVERSIONINFOEXA', 'OSVERSIONINFOEXW',
        }
        # Match multi-line typedef struct blocks ending with a SDK name
        import re as _re
        _struct_pattern = _re.compile(
            r'typedef\s+struct\s+\w*\s*\{[^}]*\}\s*'
            r'([A-Z_][A-Z0-9_]*(?:\s*,\s*\*?[A-Z_][A-Z0-9_]*)*)\s*;',
            _re.DOTALL
        )
        def _remove_sdk_struct_typedef(match):
            names_part = match.group(1)
            # Parse all names from "NAME1, *PNAME2"
            names = [n.strip().lstrip('*') for n in names_part.split(',')]
            if any(n in _SDK_STRUCT_NAMES for n in names):
                logger.warning(f"   \U0001f6e1 Sanitizer: removed typedef struct redefining {', '.join(names)} (SDK type)")
                return ''  # Remove the entire block
            return match.group(0)  # Keep non-SDK structs

        result = _struct_pattern.sub(_remove_sdk_struct_typedef, result)

        # ── Remove extern "C" blocks that redeclare known Win32 API functions ──
        # LLMs sometimes inject:
        #   extern "C" {
        #       BOOL CryptUnprotectData(...);
        #       BOOL CryptAcquireContextW(...);
        #   }
        # These conflict with the SDK declarations once the proper header is included.
        _KNOWN_WIN32_FUNCS = {
            # WinCrypt / DPAPI
            'CryptAcquireContext', 'CryptAcquireContextA', 'CryptAcquireContextW',
            'CryptReleaseContext', 'CryptCreateHash', 'CryptHashData',
            'CryptGetHashParam', 'CryptDestroyHash', 'CryptDeriveKey', 'CryptDestroyKey',
            'CryptEncrypt', 'CryptDecrypt', 'CryptGenRandom', 'CryptGenKey',
            'CryptImportKey', 'CryptExportKey', 'CryptSetKeyParam', 'CryptGetKeyParam',
            'CryptUnprotectData', 'CryptProtectData',
            'CryptStringToBinaryA', 'CryptStringToBinaryW',
            'CryptBinaryToStringA', 'CryptBinaryToStringW',
            'CertOpenStore', 'CertCloseStore', 'CertEnumCertificatesInStore',
            # Process / Thread
            'CreateProcessA', 'CreateProcessW', 'OpenProcess', 'TerminateProcess',
            'CreateThread', 'GetExitCodeProcess', 'GetCurrentProcessId',
            # Module
            'LoadLibraryA', 'LoadLibraryW', 'GetModuleHandleA', 'GetModuleHandleW',
            'GetProcAddress', 'FreeLibrary',
            # File
            'CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile', 'CloseHandle',
            'CopyFileA', 'CopyFileW', 'DeleteFileA', 'DeleteFileW', 'MoveFileA', 'MoveFileW',
            'GetFileAttributesA', 'GetFileAttributesW', 'FindFirstFileA', 'FindFirstFileW',
            'FindNextFileA', 'FindNextFileW', 'FindClose',
            # Registry
            'RegOpenKeyExA', 'RegOpenKeyExW', 'RegQueryValueExA', 'RegQueryValueExW',
            'RegSetValueExA', 'RegSetValueExW', 'RegCloseKey', 'RegCreateKeyExA', 'RegCreateKeyExW',
            # Network
            'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
            'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW',
            'InternetReadFile', 'InternetCloseHandle',
            'WSAStartup', 'WSACleanup',
            # Shell
            'ShellExecuteA', 'ShellExecuteW', 'SHGetFolderPathA', 'SHGetFolderPathW',
            # COM
            'CoInitialize', 'CoInitializeEx', 'CoUninitialize', 'CoCreateInstance',
            'OleInitialize', 'OleUninitialize',
            'SafeArrayCreateVector', 'SafeArrayAccessData', 'SafeArrayUnaccessData',
            'VariantInit', 'VariantClear', 'SysAllocString', 'SysFreeString',
            # DNS / IP
            'DnsQuery', 'DnsQuery_A', 'DnsQuery_W', 'DnsFree',
            'GetAdaptersInfo', 'GetAdaptersAddresses',
            # Credential
            'CredEnumerateA', 'CredEnumerateW', 'CredFree', 'CredReadA', 'CredReadW',
            # VFW
            'capCreateCaptureWindowA', 'capCreateCaptureWindowW', 'capCreateCaptureWindow',
            # Misc
            'GetTickCount', 'Sleep', 'ExitProcess', 'GetLastError',
        }

        # Remove individual lines declaring known functions (standalone or in extern blocks)
        result_lines = result.split('\n')
        cleaned_lines = []
        removed_extern_decls = 0
        for line in result_lines:
            stripped = line.strip()
            # Check for function declaration lines that redeclare Win32 APIs
            # Patterns: "BOOL CryptUnprotectData(...);" or "extern BOOL Crypt..."
            is_sdk_redecl = False
            for func_name in _KNOWN_WIN32_FUNCS:
                if func_name in stripped:
                    # Check if it's a declaration (not a definition or call)
                    # Declaration: has func name, parentheses, ends with ;, NO opening brace
                    if _re.search(r'\b' + _re.escape(func_name) + r'\s*\(', stripped) and \
                       stripped.endswith(';') and '{' not in stripped:
                        # Make sure it's not a call (must have a return type before it)
                        before_func = stripped.split(func_name)[0].strip()
                        # If there's a type keyword before the function name, it's a redeclaration
                        if before_func and _re.match(
                            r'^(?:extern\s+(?:"C"\s+)?)?'
                            r'(?:BOOL|DWORD|HANDLE|HMODULE|HINSTANCE|HINTERNET|HKEY|'
                            r'LONG|LPVOID|FARPROC|void|int|unsigned|SOCKET|HRESULT|'
                            r'HWND|HDC|HICON|HMENU|HCRYPTPROV|HCRYPTHASH|HCRYPTKEY|'
                            r'SIZE_T|LPCSTR|LPSTR|LPCWSTR|LPWSTR|LPBYTE|LPDWORD|'
                            r'HLOCAL|HGLOBAL|PCERT_CONTEXT|PCCERT_CONTEXT|'
                            r'__declspec\([^)]*\)\s+)?'
                            r'(?:__stdcall\s+|__cdecl\s+|WINAPI\s+|CALLBACK\s+)?$',
                            before_func
                        ):
                            is_sdk_redecl = True
                            break
                    # Also catch "const DWORD PROV_RSA_FULL;" style
                    if _re.match(r'^(?:const\s+)?(?:DWORD|int|unsigned)\s+' + _re.escape(func_name) + r'\s*;', stripped):
                        is_sdk_redecl = True
                        break
            if is_sdk_redecl:
                removed_extern_decls += 1
                continue
            cleaned_lines.append(line)
        
        if removed_extern_decls > 0:
            logger.info(f"   \U0001f6e1 Sanitizer: removed {removed_extern_decls} Win32 API redeclaration(s)")
            result = '\n'.join(cleaned_lines)

        # Remove empty extern "C" { } blocks left after cleaning
        result = _re.sub(r'extern\s+"C"\s*\{[\s\n]*\}', '', result)
        # Also remove "// Forward declarations for missing symbols" comments left orphaned
        result = _re.sub(r'//\s*Forward declarations for missing symbols\s*\n(?=\s*\n)', '', result)

        return result

    # ── Generic pattern-based fixes (no LLM) ──────────────────────────
    # Return type lookup loaded from configs/win32_knowledge.json
    _func_return_types_cache: Optional[Dict[str, str]] = None

    @classmethod
    def _get_func_return_types(cls) -> Dict[str, str]:
        """Lazy-load Win32/CRT function return type map from external config."""
        if cls._func_return_types_cache is None:
            data = _load_win32_knowledge()
            cls._func_return_types_cache = data.get('func_return_types', {})
        return cls._func_return_types_cache

    @classmethod
    def _infer_variable_type(cls, ident: str, lines: List[str], usage_lines: List[int],
                             errors: Optional[List[str]] = None) -> str:
        """Infer the probable C type of *ident* from how it is used."""

        # ── 0. Check C2440 conversion errors for direct type hints ──
        # e.g. "C2440: '=': cannot convert from 'int' to 'SECURITY_ATTRIBUTES'"
        # The target type is what we need.
        if errors:
            for err in errors:
                if ident not in err:
                    continue
                m2440 = re.search(r'C2440.*cannot convert.*to\s*\'([^\']+)\'', err)
                if m2440:
                    target_type = m2440.group(1)
                    # Make sure it's a real type, not a function name
                    if re.match(r'^[A-Z_][A-Z_0-9]*$', target_type) or target_type in (
                        'SECURITY_ATTRIBUTES', 'PROCESS_INFORMATION', 'STARTUPINFO',
                        'MEMORY_BASIC_INFORMATION', 'HANDLE', 'DWORD', 'BOOL',
                        'HMODULE', 'HKEY', 'HWND', 'HDC',
                    ):
                        return target_type

        for line_num in usage_lines:
            idx = line_num - 1
            if idx < 0 or idx >= len(lines):
                continue
            line = lines[idx]

            # IDENT = KnownFunc(...)  →  return type of KnownFunc
            m = re.search(re.escape(ident) + r'\s*=\s*\(?\s*(\w+)\s*\)', line)
            if not m:
                m = re.search(re.escape(ident) + r'\s*=\s*(\w+)\s*\(', line)
            if m:
                func = m.group(1)
                ret = cls._get_func_return_types().get(func)
                if ret and ret != 'void':
                    return ret

            # IDENT = KNOWN_CONSTANT
            m = re.search(re.escape(ident) + r'\s*=\s*(\w+)\s*;', line)
            if m:
                val = m.group(1)
                if val in ('TRUE', 'FALSE'):
                    return 'BOOL'
                if val in ('NULL', 'INVALID_HANDLE_VALUE'):
                    return 'HANDLE'
                if val.startswith('CSIDL_'):
                    return 'int'
                if val.startswith(('ERROR_', 'STATUS_', 'FILE_', 'GENERIC_',
                                   'PROCESS_', 'THREAD_', 'STD_')):
                    return 'DWORD'
                if val.startswith(('HKEY_',)):
                    return 'HKEY'

            # IDENT = <number>
            if re.search(re.escape(ident) + r'\s*=\s*(?:0x[0-9a-fA-F]+|\d+)\s*;', line):
                return 'int'

            # if (IDENT == TRUE/FALSE)
            if re.search(r'\b' + re.escape(ident) + r'\s*[!=]=\s*(?:TRUE|FALSE)\b', line):
                return 'BOOL'

        # ── AST-based type inference (preferred over naming heuristics) ──
        sv = get_semantic_validator() if get_semantic_validator else None
        if sv and sv.available and usage_lines:
            full_code = '\n'.join(lines)
            for line_num in usage_lines:
                ast_type = sv.infer_type_at_usage(full_code, ident, line_num)
                if ast_type:
                    return ast_type

        # No reliable inference — return None rather than guessing from
        # naming conventions (hX→HANDLE, dwX→DWORD, etc.) which can make
        # the code compile but silently break runtime semantics.
        return None

    @classmethod
    def _find_function_body_start(cls, lines: List[str], usage_line: int) -> Optional[int]:
        """Return the 0-based line index just after the opening '{' of the
        function that contains *usage_line* (1-based).

        AST-first: uses tree-sitter to walk function_definition nodes.
        Falls back to brace-counting heuristic if AST is unavailable.
        """
        # ── AST path (preferred) ──
        sv = get_semantic_validator() if get_semantic_validator else None
        if sv and sv.available:
            full_code = '\n'.join(lines)
            ast_line = sv.find_function_body_start(full_code, usage_line)
            if ast_line is not None:
                return ast_line - 1  # convert 1-based → 0-based

        # ── Brace-counting fallback (degraded mode) ──
        if not _AST_AVAILABLE:
            logger.debug("[degraded] _find_function_body_start: using brace-counting fallback")
        brace_depth = 0
        func_brace_line: Optional[int] = None
        for i in range(min(usage_line - 1, len(lines) - 1), -1, -1):
            line = lines[i]
            brace_depth += line.count('}') - line.count('{')
            if brace_depth < 0:
                context = ' '.join(lines[max(0, i - 5):i + 1])
                if ')' in context:
                    stripped_ctx = context.lstrip()
                    control_kw = re.match(
                        r'.*\b(if|else\s*if|while|for|switch|do)\s*\(', stripped_ctx
                    )
                    if control_kw:
                        if func_brace_line is None:
                            func_brace_line = i + 1
                        brace_depth = 0
                        continue
                    return i + 1
                else:
                    if func_brace_line is None:
                        func_brace_line = i + 1
                    brace_depth = 0
                    continue
        return func_brace_line

    @classmethod
    def apply_generic_pattern_fixes(
        cls,
        source_code: str,
        errors: List[str],
        language: str = "c",
        file_path: str = "",
    ) -> Tuple[str, int, set]:
        """Apply pattern-based compilation-error fixes that work for any project.

        Currently handles:
        1. VLA (C99 variable-length arrays) — MSVC C2065 + C2057/C2466/C2133
        2. Undeclared local variables — C2065 alone (mutation deleted a decl)
        3. Missing ``#include`` for known Win32 symbols — C2065 for API types
        4. C2143 "missing ';' before …" — insert semicolons
        5. C1075 unmatched braces — attempt brace balancing

        Returns
        -------
        (fixed_code, num_fixes, lnk_missing_libs)
            lnk_missing_libs is a set of library names (e.g. 'kernel32.lib')
            detected from LNK2019/LNK2001 errors.
        """
        if language.lower() not in ('c', 'cpp', 'c++'):
            return source_code, 0, set()

        fixes = 0
        lines = source_code.split('\n')

        # ── 0. Fix C2143 "missing ';' before" errors ──
        c2143_fixes: List[Tuple[int, str]] = []  # (line_num, before_what)
        for err in errors:
            m = re.search(r'[\(:]\s*(\d+)\s*[\):].*C2143.*missing\s*\';\'\s*before\s*\'([^\']+)\'', err)
            if m:
                line_num = int(m.group(1))
                before_what = m.group(2)
                c2143_fixes.append((line_num, before_what))

        # Sort by line number descending so insertions don't shift later lines
        c2143_fixes.sort(key=lambda x: x[0], reverse=True)
        for line_num, before_what in c2143_fixes:
            idx = line_num - 1  # 0-based
            if 0 <= idx < len(lines):
                line = lines[idx]
                stripped = line.rstrip()
                # Only add ';' if the line doesn't already end with one (or with '{', '}', ')')
                if stripped and not stripped.endswith((';', '{', '}', ')', ',', ':', '#')):
                    lines[idx] = stripped + ';'
                    fixes += 1
                    logger.info(f"      \U0001f527 Pattern fix (C2143): added ';' at end of line {line_num}")
                elif before_what == '{' and stripped:
                    # Special case: missing ';' before '{' might mean a broken function signature
                    # Try inserting ';' before the '{' on this line if '{' is present
                    brace_pos = stripped.find('{')
                    if brace_pos > 0:
                        before = stripped[:brace_pos].rstrip()
                        if before and not before.endswith((';', ')', ':', ',')):
                            lines[idx] = before + '; ' + stripped[brace_pos:]
                            fixes += 1
                            logger.info(f"      \U0001f527 Pattern fix (C2143): inserted ';' before '{{' at line {line_num}")

        # ── 0b. Fix C1075 unmatched braces ──
        # Also handles the case where C2143 "missing ';' before '{'" appears on
        # a valid function definition — which means the PREVIOUS function has
        # unclosed braces (LLM mutation broke brace balance).
        _func_def_re = re.compile(
            r'^\s*(?:static\s+|inline\s+|extern\s+|__declspec\([^)]*\)\s+)*'
            r'(?:BOOL|DWORD|HANDLE|HMODULE|LPVOID|LRESULT|UINT|ULONG|'
            r'void|int|char|long|short|unsigned|signed|float|double|size_t|'
            r'PVOID|LPSTR|LPCSTR|LPWSTR|LPCWSTR|NTSTATUS|HRESULT|SOCKET|'
            r'HHOOK|HWND|HINSTANCE|LPARAM|WPARAM|ATOM|WORD|BYTE|LONGLONG)\s+'  # noqa: E501
            r'\w+\s*\([^)]*\)\s*\{', re.IGNORECASE
        )

        # First, check for C2143 "missing ';' before '{'" on function definition
        # lines — this means the previous function has unclosed braces.
        for line_num, before_what in c2143_fixes:
            if before_what != '{':
                continue
            idx = line_num - 1
            if idx < 0 or idx >= len(lines):
                continue
            if not _func_def_re.match(lines[idx]):
                continue
            # This IS a valid function definition at line_num.
            # Count brace depth from the start of file to this line.
            depth = 0
            for i in range(idx):
                for ch in lines[i]:
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
            if depth > 0:
                # Previous code has 'depth' unclosed braces.
                # Insert closing braces just before this function definition.
                insert_braces = '}\n' * depth
                lines.insert(idx, insert_braces.rstrip('\n'))
                fixes += depth
                logger.info(
                    f"      \U0001f527 Pattern fix (C2143/C1075): inserted {depth} "
                    f"closing brace(s) before function at line {line_num} "
                    f"(previous function had unclosed braces)"
                )
                # Don't apply normal C1075 logic below if we fixed here
                break

        for err in errors:
            if 'C1075' in err and ("'{'" in err or "no matching token" in err):
                # Count braces using string/comment-aware counter
                full_text = '\n'.join(lines)
                brace_balance = _check_brace_balance(full_text)
                open_count = full_text.count('{')
                close_count = full_text.count('}')
                # Use the string/comment-aware balance to decide direction,
                # but keep raw counts for backward compat in the insertion logic.
                if brace_balance > 0:
                    open_count = close_count + brace_balance
                elif brace_balance < 0:
                    close_count = open_count + abs(brace_balance)
                if open_count > close_count:
                    diff = open_count - close_count
                    # Try to find a function definition line where the depth is wrong
                    # and insert the brace before it (smarter than end-of-file).
                    inserted = False
                    depth = 0
                    for i, line in enumerate(lines):
                        for ch in line:
                            if ch == '{':
                                depth += 1
                            elif ch == '}':
                                depth -= 1
                        # Check if next line starts a new function while depth > 0
                        if depth > 0 and i + 1 < len(lines) and _func_def_re.match(lines[i + 1]):
                            for _ in range(depth):
                                lines.insert(i + 1, '}')
                                fixes += 1
                            inserted = True
                            logger.info(
                                f"      \U0001f527 Pattern fix (C1075): added {depth} closing "
                                f"brace(s) before function at line {i + 2}"
                            )
                            break
                    if not inserted:
                        # Fallback: add missing closing braces at end of file
                        last_nonempty = len(lines) - 1
                        while last_nonempty > 0 and not lines[last_nonempty].strip():
                            last_nonempty -= 1
                        for _ in range(diff):
                            lines.insert(last_nonempty + 1, '}')
                            fixes += 1
                        if diff > 0:
                            logger.info(f"      \U0001f527 Pattern fix (C1075): added {diff} closing brace(s) for brace imbalance")
                elif close_count > open_count:
                    diff = close_count - open_count
                    # Remove extra closing braces from the end
                    removed = 0
                    for i in range(len(lines) - 1, -1, -1):
                        if removed >= diff:
                            break
                        if lines[i].strip() == '}':
                            lines.pop(i)
                            removed += 1
                    if removed > 0:
                        fixes += removed
                        logger.info(f"      \U0001f527 Pattern fix (C1075): removed {removed} extra closing brace(s)")
                break  # Only process C1075 once

        # ── 1. Collect all C2065 undeclared identifiers ──
        undeclared: Dict[str, List[int]] = {}   # ident → [line_numbers]
        # Also collect C2146 errors to detect cascading patterns
        c2146_lines: Dict[int, str] = {}   # line_num → ident (from "missing ';' before identifier 'X'")
        for err in errors:
            # C2146: syntax error: missing ';' before identifier 'X'
            m2146 = re.search(r'[\(:]\s*(\d+)\s*[\):].*C2146.*before identifier\s*\'([^\']+)\'', err)
            if m2146:
                c2146_lines[int(m2146.group(1))] = m2146.group(2)

            m = re.search(r'[\(:]\s*(\d+)\s*[\):].*C2065.*\'([^\']+)\'.*undeclared', err)
            if not m:
                m = re.search(r'C2065.*\'([^\']+)\'', err)  # without line number
                if m:
                    undeclared.setdefault(m.group(1), [])
                    continue
            if m:
                line_num = int(m.group(1))
                ident = m.group(2)
                undeclared.setdefault(ident, []).append(line_num)

        # ── 2. Separate VLA idents (have C2057/C2466/C2133) from plain undeclared ──
        # (Only if there are C2065 undeclared identifiers)
        if undeclared:
            vla_idents: set = set()
            for err in errors:
                for vid in list(undeclared.keys()):
                    if vid in err and any(code in err for code in ('C2057', 'C2466', 'C2133')):
                        vla_idents.add(vid)

            # ── 3. Fix VLA identifiers: add #define ──
            vla_defines_to_add: List[str] = []
            for vid in vla_idents:
                # Skip if already defined
                if re.search(r'^\s*#\s*define\s+' + re.escape(vid) + r'\b', source_code, re.MULTILINE):
                    continue
                vla_defines_to_add.append(vid)

            if vla_defines_to_add:
                define_block = "/* Auto-fix: VLA constants */\n"
                for vid in vla_defines_to_add:
                    _default = 256
                    if re.search(r'(?i)(t1|track1|card|pan)', vid): _default = 128
                    elif re.search(r'(?i)(t2|track2)', vid): _default = 40
                    elif re.search(r'(?i)(t3|track3)', vid): _default = 128
                    elif re.search(r'(?i)(max|len|size|buf)', vid): _default = 512
                    elif re.search(r'(?i)(min|small)', vid): _default = 32
                    define_block += f"#ifndef {vid}\n#define {vid} {_default}\n#endif\n"
                define_block += "\n"
                # Insert after last #include
                last_inc = -1
                for i, l in enumerate(lines):
                    if l.strip().startswith('#include'):
                        last_inc = i
                insert_at = last_inc + 1 if last_inc >= 0 else 0
                lines.insert(insert_at, define_block)
                fixes += len(vla_defines_to_add)
                logger.info(f"      \U0001f527 Pattern fix (VLA): added #define for {', '.join(vla_defines_to_add)}")

            # ── 4. Fix plain undeclared identifiers: add local variable declaration ──
            plain_undeclared = {k: v for k, v in undeclared.items() if k not in vla_idents}

            # ── 4a. Restore lowercased Win32 types to correct casing ──
            # LLMs (especially strat_5 obfuscation) rename DWORD → dword,
            # HANDLE → handle, MEMORY_BASIC_INFORMATION → memory_basic_information, etc.
            # Instead of declaring them as 'int dword;', we replace in-code to restore casing.
            win32_case_restored: set = set()
            for ident in list(plain_undeclared.keys()):
                correct = cls._get_lowercase_to_correct().get(ident)
                if correct and ident != correct:
                    # Verify the lowercase form is not a legitimate user variable
                    # (it's only a Win32 type rename if it's used in a type context:
                    #  e.g. "dword x;", "memory_basic_information mbi;", etc.)
                    is_type_usage = False
                    for ln_num in plain_undeclared[ident]:
                        idx = ln_num - 1
                        if 0 <= idx < len(lines):
                            line = lines[idx]
                            # Check if ident is used as a type (followed by an identifier, *, or &)
                            type_pattern = re.compile(
                                r'\b' + re.escape(ident) + r'\s+[\*&]?\s*[a-zA-Z_]\w*\s*[;,=\[\(]'
                            )
                            if type_pattern.search(line):
                                is_type_usage = True
                                break
                            # Also check: is it a standalone identifier that matches a Win32 type
                            # used in a context like "sizeof(ident)" or "(ident)" cast
                            if re.search(r'sizeof\s*\(\s*' + re.escape(ident) + r'\s*\)', line):
                                is_type_usage = True
                                break
                            if re.search(r'\(\s*' + re.escape(ident) + r'\s*\)', line):
                                is_type_usage = True
                                break
                
                    if is_type_usage:
                        # Replace all occurrences as whole words in the source
                        word_re = re.compile(r'\b' + re.escape(ident) + r'\b')
                        new_lines = []
                        for line in lines:
                            new_lines.append(word_re.sub(correct, line))
                        lines = new_lines
                        fixes += 1
                        win32_case_restored.add(ident)
                        logger.info(f"      \U0001f527 Pattern fix: restored Win32 type '{ident}' → '{correct}'")
                        # Also remove any cascading C2146 identifiers on the same lines
                        for ln_num in plain_undeclared[ident]:
                            if ln_num in c2146_lines:
                                cascaded_ident = c2146_lines[ln_num]
                                if cascaded_ident in plain_undeclared and cascaded_ident not in win32_case_restored:
                                    win32_case_restored.add(cascaded_ident)
                                    logger.info(f"      ⏭ Skipping '{cascaded_ident}' — cascading from Win32 type restore")

            # Remove restored identifiers from plain_undeclared
            for ident in win32_case_restored:
                plain_undeclared.pop(ident, None)

            # Known API types / macros that need an #include rather than a declaration
            # Loaded from configs/win32_knowledge.json
            _API_TYPES_NEEDING_INCLUDE = _load_win32_knowledge().get('types_needing_include', {})

            includes_to_add: set = set()

            for ident, usage_lns in list(plain_undeclared.items()):
                # Skip identifiers that are #defined as macros in this file
                # (e.g. APPEND_STRING is a macro, not a variable)
                current_code = '\n'.join(lines)
                if re.search(r'^\s*#\s*define\s+' + re.escape(ident) + r'\b',
                             current_code, re.MULTILINE):
                    logger.info(f"      \u23ed Skipping '{ident}' \u2014 it is #defined as a macro in this file")
                    continue

                # Already declared? Check CURRENT lines (not original source_code),
                # because a previous fix pass may have already added a declaration.
                decl_re = re.compile(
                    r'\b(?:int|unsigned|signed|long|short|char|void|float|double|'
                    r'DWORD|HANDLE|BOOL|BYTE|WORD|UINT|LONG|ULONG|USHORT|HMODULE|'
                    r'HINSTANCE|HKEY|HINTERNET|HCRYPTPROV|LPVOID|SIZE_T|SOCKET|'
                    r'FARPROC|size_t|WCHAR|TCHAR|HDC|HWND|HMENU|HICON|HCURSOR|'
                    r'HBITMAP|HBRUSH|HPEN|HFONT|COLORREF|LRESULT|WPARAM|LPARAM)'
                    r'\s+\*?\s*' + re.escape(ident) + r'\b'
                )
                if decl_re.search(current_code):
                    continue

                # Is it a type/struct that needs an #include?
                if ident in _API_TYPES_NEEDING_INCLUDE:
                    inc = _API_TYPES_NEEDING_INCLUDE[ident]
                    # Check if already included
                    inc_check = inc.replace('<', '').replace('>', '')
                    if inc_check not in source_code:
                        includes_to_add.add(f'#include {inc}')
                    continue  # Don't add a variable declaration for a type name

                # Skip cascading errors: if identifier X appears in C2146
                # "missing ';' before identifier 'X'" on the same line as another
                # undeclared type (which will be resolved by include), skip X.
                # Example: `uint32_t v3;` → C2065 uint32_t, C2146 before 'v3', C2065 v3
                # Once uint32_t is resolved via <stdint.h>, v3 is automatically declared.
                if usage_lns:
                    is_cascading = False
                    for ln in usage_lns:
                        if ln in c2146_lines and c2146_lines[ln] == ident:
                            # Check if there's an undeclared TYPE on the same line being fixed by include
                            for other_ident in undeclared:
                                if other_ident == ident:
                                    continue
                                if other_ident in _API_TYPES_NEEDING_INCLUDE:
                                    if ln in undeclared.get(other_ident, []):
                                        is_cascading = True
                                        break
                        if is_cascading:
                            break
                    if is_cascading:
                        logger.info(f"      ⏭ Skipping '{ident}' — cascading error (will resolve after include fix)")
                        continue

                # Infer type from usage
                inferred = cls._infer_variable_type(ident, lines, usage_lns, errors=errors)
                if inferred is None:
                    logger.info(f"      ⏭ Skipping '{ident}' — could not confidently infer type")
                    continue

                # Find enclosing function body start
                target_line = min(usage_lns) if usage_lns else 1
                insert_idx = cls._find_function_body_start(lines, target_line)

                if insert_idx is not None:
                    # Detect indentation from context
                    if insert_idx < len(lines):
                        ctx_line = lines[insert_idx]
                        leading = len(ctx_line) - len(ctx_line.lstrip())
                        indent = ' ' * leading if leading > 0 else '    '
                    else:
                        indent = '    '
                    decl_line = f"{indent}{inferred} {ident};"
                    lines.insert(insert_idx, decl_line)
                    # Shift subsequent usage lines
                    for other_id in plain_undeclared:
                        if other_id != ident:
                            plain_undeclared[other_id] = [
                                l + 1 if l >= insert_idx + 1 else l
                                for l in plain_undeclared[other_id]
                            ]
                    fixes += 1
                    logger.info(f"      \U0001f527 Pattern fix: added '{inferred} {ident};' "
                               f"at line {insert_idx + 1}")

            # ── 5. Add missing includes ──
            if includes_to_add:
                inc_block = '\n'.join(sorted(includes_to_add)) + '\n'
                # Insert after last existing #include
                last_inc_idx = -1
                for i, l in enumerate(lines):
                    if l.strip().startswith('#include'):
                        last_inc_idx = i
                pos = last_inc_idx + 1 if last_inc_idx >= 0 else 0
                lines.insert(pos, inc_block)
                fixes += len(includes_to_add)
                logger.info(f"      \U0001f527 Pattern fix: added {len(includes_to_add)} include(s): "
                           f"{', '.join(sorted(includes_to_add))}")

        # ── 6. Fix C1083 "cannot open include file" ──
        # Strategy: NEVER delete or comment out #include lines automatically.
        # - SDK headers missing → environment problem, log and skip.
        # - Non-SDK headers missing → keep include, log as unresolved.
        #   The cascading C2065/C3861 errors from undefined symbols will be
        #   handled by the LLM with semantic-preserving forward declarations.
        # - .tlb type libraries → comment out #import (only exception: these
        #   are COM-specific and have no simple forward-declaration equivalent).
        _SDK_HEADERS = {'stdio.h', 'stdlib.h', 'string.h', 'windows.h',
                        'winsock2.h', 'ws2tcpip.h', 'wininet.h',
                        'tlhelp32.h', 'shlobj.h', 'wincrypt.h', 'dpapi.h',
                        'psapi.h', 'iphlpapi.h', 'math.h', 'time.h',
                        'stdint.h', 'stddef.h', 'assert.h', 'errno.h',
                        'ctype.h', 'limits.h', 'signal.h', 'setjmp.h',
                        'windns.h', 'shlwapi.h', 'ole2.h', 'oleauto.h',
                        'oaidl.h', 'wtypes.h', 'vfw.h', 'wincred.h',
                        'atlbase.h', 'activscp.h', 'exdisp.h',
                        'shellapi.h', 'commctrl.h', 'commdlg.h',
                        'dbghelp.h', 'winternl.h', 'ntstatus.h'}
        for err in errors:
            m = re.search(r'C1083.*cannot open (?:include|type library) file.*[\'"]([^\'"]+)[\'"]', err)
            if m:
                bad_inc = m.group(1)
                # Handle .tlb (type library) files — comment out #import lines
                # (COM type libraries have no forward-declaration equivalent)
                if bad_inc.lower().endswith('.tlb'):
                    for i in range(len(lines) - 1, -1, -1):
                        line_stripped = lines[i].strip()
                        if line_stripped.startswith('#import') and bad_inc in lines[i]:
                            lines[i] = f'// {lines[i]}  // Commented: missing type library'
                            fixes += 1
                            logger.info(f"      \U0001f527 Pattern fix (C1083): commented out #import '{bad_inc}'")
                    continue

                if bad_inc.lower() in _SDK_HEADERS:
                    # SDK header missing → environment problem, not code bug.
                    logger.warning(
                        f"      ⚠️  C1083: standard SDK header '{bad_inc}' not found — "
                        f"likely an SDK/environment issue, NOT a code problem. "
                        f"Keeping #include untouched."
                    )
                    continue

                # Non-SDK header (third-party / project-specific that wasn't found).
                # Do NOT comment out or delete — the include is intentional and
                # the header may define macros, inline functions, struct layouts,
                # or constants that affect behavior.  Keep it, and let the LLM
                # resolve the cascading undefined-symbol errors by adding forward
                # declarations above the include.
                logger.info(
                    f"      ℹ️  C1083: non-SDK header '{bad_inc}' not found — "
                    f"keeping #include untouched. Cascading undefined-symbol errors "
                    f"will be resolved by LLM with forward declarations."
                )

        # ── 6b. Fix C4430 "missing type specifier" for bare main() ──
        # Old C code with `main()` instead of `int main()` triggers C4430 in MSVC C++ mode
        for err in errors:
            if 'C4430' in err or ('missing type specifier' in err and 'main' in err):
                for i, line in enumerate(lines):
                    stripped = line.lstrip()
                    # Match bare "main(" or "main (", not "int main" / "void main" / "wmain"
                    if re.match(r'^main\s*\(', stripped):
                        indent = line[:len(line) - len(stripped)]
                        lines[i] = indent + 'int ' + stripped
                        fixes += 1
                        logger.info(f"      \U0001f527 Pattern fix (C4430): added 'int' return type to main()")
                        break

        # ── Sections 7-11 removed: structural/semantic fixes now handled by LLM ──
        # Previous pattern-based handlers for C2039, C2084, C2143, C2365, C2371,
        # C2373, C2491, C2561, C2664, C2733, C3861 have been removed.
        # The LLM fixer (fix_compilation_errors) handles these via multi-turn
        # conversation with error context, few-shot examples, and RAG retrieval.


        # ── 12. Fix LNK2019/LNK2001 — detect arch mismatch and missing libs ──
        # Map loaded from configs/win32_knowledge.json
        _SYMBOL_TO_LIB = _load_win32_knowledge().get('symbol_to_lib', {})
        lnk_errors: list = []
        lnk_missing_libs: set = set()
        lnk_arch_mismatch = False
        for err in errors:
            # LNK4272: library machine type 'x86' conflicts with target machine type 'x64'
            if 'LNK4272' in err:
                lnk_arch_mismatch = True
            # LNK2019/LNK2001: unresolved external symbol
            m = re.search(r'LNK20(?:19|01).*unresolved external symbol\s+(?:__imp_)?(\w+)', err)
            if m:
                sym = m.group(1)
                if sym in _SYMBOL_TO_LIB:
                    lnk_missing_libs.add(_SYMBOL_TO_LIB[sym])
                lnk_errors.append(err)

        if lnk_arch_mismatch:
            logger.warning("      \u26a0\ufe0f LNK4272: architecture mismatch detected (x86 libs vs x64 target or vice versa)")
            logger.warning("         This is a compiler configuration issue, not a source code issue.")
            logger.warning("         Fix: set msvc_arch to match the project target in project_config.json")

        # Return detected libraries so callers can add them to linker flags.
        if lnk_missing_libs:
            logger.info(f"      \U0001f527 LNK diagnostic: missing libraries detected: {', '.join(sorted(lnk_missing_libs))}")

        if fixes > 0:
            return '\n'.join(lines), fixes, lnk_missing_libs
        return source_code, 0, lnk_missing_libs

    @classmethod
    def _validate_header_structure(cls, original_code: str, fixed_code: str,
                                    language: str = "c") -> Tuple[bool, str]:
        """
        Validate that LLM didn't break the header file structure.
        Uses AST snapshots when available; regex counters as fallback.
        Returns (is_valid, error_message).
        """
        # ── AST path (preferred) ──
        sv = get_semantic_validator() if get_semantic_validator else None
        if sv and sv.available:
            orig_snap = sv.extract_snapshot(original_code, language)
            fix_snap = sv.extract_snapshot(fixed_code, language)
            if orig_snap and fix_snap:
                # Functions must be preserved
                missing_funcs = orig_snap.function_names - fix_snap.function_names
                if missing_funcs:
                    return False, (
                        f"Header validation (AST): {len(missing_funcs)} function(s) "
                        f"removed: {', '.join(sorted(list(missing_funcs)[:5]))}"
                    )
                # Types must be preserved
                missing_types = orig_snap.type_names - fix_snap.type_names
                if missing_types:
                    return False, (
                        f"Header validation (AST): {len(missing_types)} type(s) "
                        f"removed: {', '.join(sorted(list(missing_types)[:5]))}"
                    )
                # Parse errors must not increase
                if fix_snap.error_count > orig_snap.error_count + 2:
                    return False, (
                        f"Header validation (AST): parse errors increased "
                        f"({orig_snap.error_count} → {fix_snap.error_count})"
                    )
                return True, ""

        # ── Regex fallback ──
        # Count namespace declarations
        orig_ns = len(re.findall(r'\bnamespace\s+\w+\s*\{', original_code))
        fixed_ns = len(re.findall(r'\bnamespace\s+\w+\s*\{', fixed_code))
        if fixed_ns != orig_ns:
            return False, f"Namespace count changed: {orig_ns} -> {fixed_ns}"
        
        # Check that no excessive #ifdef was added
        orig_ifdefs = len(re.findall(r'#\s*if(?:def|ndef)?', original_code))
        fixed_ifdefs = len(re.findall(r'#\s*if(?:def|ndef)?', fixed_code))
        if fixed_ifdefs > orig_ifdefs + 2:
            return False, f"Too many #ifdef added: {orig_ifdefs} -> {fixed_ifdefs}"
        
        # Function signature preservation (regex fallback)
        orig_funcs = set(_extract_function_signatures(original_code))
        fixed_funcs = set(_extract_function_signatures(fixed_code))
        missing = orig_funcs - fixed_funcs
        if missing:
            return False, (
                f"Header function(s) removed: {', '.join(sorted(list(missing)[:5]))}"
            )
        
        return True, ""
    
    def __init__(
        self, 
        llm_model: str = "codestral-2508", 
        api_key: Optional[str] = None,
        use_hybrid: bool = False,
        local_model: str = "qwen2.5-coder:7b-instruct-q4_K_M",
        cloud_file_size_limit: int = 15000,
        mode: str = "hybrid",
        fix_history_path: Optional[str] = None,
        compiler_type: str = 'auto',
    ):
        """
        Initialize auto-fixer.
        
        Args:
            llm_model: LLM model to use (for cloud)
            api_key: Optional API key for Mistral
            use_hybrid: Enable hybrid mode (Ollama + Mistral)
            local_model: Local Ollama model name
            cloud_file_size_limit: Files BELOW this use cloud, ABOVE use local
            mode: Operation mode ("hybrid", "local_only", "cloud_only")
            compiler_type: 'msvc', 'gcc', 'clang', or 'auto' (auto-detect from errors)
        """
        self.llm_model = llm_model
        self.api_key = api_key
        self.llm_provider = None
        self.use_hybrid = use_hybrid
        self._fix_mode = mode  # store for tracking
        self.compiler_type = compiler_type

        # ── Fix History RAG ──
        self.fix_history_rag = None
        if fix_history_path and FixHistoryRAG:
            try:
                self.fix_history_rag = FixHistoryRAG(fix_history_path)
                logger.info(f"[RAG] Fix history RAG initialized: {fix_history_path}")
            except Exception as e:
                logger.warning(f"[RAG] Failed to initialize fix history RAG: {e}")

        # ── Fix path tracking ──
        self.fix_tracking = {
            'surgical_local': {'attempts': 0, 'successes': 0, 'errors_before': 0, 'errors_after': 0},
            'surgical_cloud': {'attempts': 0, 'successes': 0, 'errors_before': 0, 'errors_after': 0},
            'normal_local':   {'attempts': 0, 'successes': 0, 'errors_before': 0, 'errors_after': 0},
            'normal_cloud':   {'attempts': 0, 'successes': 0, 'errors_before': 0, 'errors_after': 0},
            'pattern_only':   {'attempts': 0, 'successes': 0, 'errors_before': 0, 'errors_after': 0},
        }

        try:
            if use_hybrid:
                # Import HybridLLMProvider
                import sys
                import os
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
                from llm_api import HybridLLMProvider
                
                self.llm_provider = HybridLLMProvider(
                    local_model=local_model,
                    cloud_model=llm_model,
                    api_key=api_key,
                    cloud_file_size_limit=cloud_file_size_limit,
                    mode=mode
                )
                logger.info(f"Auto-fixer initialized with HYBRID mode")
                logger.info(f"  Local: {local_model}")
                logger.info(f"  Cloud: {llm_model}")
            else:
                from llm_api import get_llm_provider
                self.llm_provider = get_llm_provider(llm_model, api_key=api_key)
                logger.info(f"Auto-fixer initialized with model: {llm_model}")
        except Exception as e:
            logger.warning(f"Failed to initialize LLM provider: {e}")

    def _detect_provider_tag(self, file_size: int = 10000, error_count: int = 3) -> str:
        """Detect which LLM provider would be used and return 'local' or 'cloud'."""
        if not self.use_hybrid or not hasattr(self.llm_provider, 'choose_provider'):
            return 'cloud'  # non-hybrid = cloud only
        try:
            _, reason = self.llm_provider.choose_provider(file_size, error_count)
            if 'local' in reason or reason == 'local_only_mode' or reason == 'file_too_large_use_local' or reason == 'cloud_cooldown' or reason == 'cloud_unavailable':
                return 'local'
            return 'cloud'
        except Exception:
            return 'local'

    def print_fix_tracking_summary(self):
        """Print a summary of all fix paths used and their success rates."""
        logger.info("\n" + "="*70)
        logger.info("📊 FIX PATH TRACKING SUMMARY")
        logger.info("="*70)
        total_attempts = 0
        total_successes = 0
        for path_name, stats in self.fix_tracking.items():
            if stats['attempts'] > 0:
                rate = (stats['successes'] / stats['attempts'] * 100) if stats['attempts'] > 0 else 0
                logger.info(f"  {path_name:20s}: {stats['attempts']} attempts, "
                           f"{stats['successes']} successes ({rate:.0f}%), "
                           f"errors_in={stats['errors_before']}")
                total_attempts += stats['attempts']
                total_successes += stats['successes']
        if total_attempts == 0:
            logger.info("  (no fix attempts recorded)")
        else:
            overall_rate = total_successes / total_attempts * 100
            logger.info(f"  {'TOTAL':20s}: {total_attempts} attempts, "
                       f"{total_successes} successes ({overall_rate:.0f}%)")
        logger.info("="*70)
    
    def _clean_llm_artifacts(self, code: str) -> str:
        """
        Clean up common LLM artifacts from generated code.
        
        Args:
            code: Generated code that may have artifacts
            
        Returns:
            Cleaned code
        """
        original_length = len(code)
        
        # Remove stray backticks (common LLM formatting artifact)
        if '`' in code:
            # Count backticks (excluding markdown code blocks)
            backtick_count = code.count('`') - code.count('```') * 3
            
            if backtick_count > 0:
                # Remove all single backticks
                code = code.replace('`', '')
                logger.info(f"Cleaned {backtick_count} stray backtick(s) from LLM output")
        
        # Remove markdown artifacts that might slip through
        # Look for patterns like: "```c\n" or "```\n" at start
        if code.startswith('```'):
            lines = code.split('\n')
            if len(lines) > 1:
                # Remove first line (language marker)
                code = '\n'.join(lines[1:])
                logger.debug("Removed markdown code block start")
        
        # Remove trailing markdown
        if code.endswith('```'):
            code = code[:-3]
            logger.debug("Removed markdown code block end")
        
        # Remove any remaining triple backticks
        code = code.replace('```', '')
        
        # CRITICAL: Remove instruction-style lines that LLM sometimes adds
        # Pattern: "Add #include", "Remove line", "Change to", etc.
        lines = code.split('\n')
        cleaned_lines = []
        removed_instructions = 0
        
        for line in lines:
            stripped = line.strip()
            
            # Check if line starts with instruction pattern (order matters!)
            is_instruction = False
            extracted_code = None
            
            if stripped.startswith('Add #include '):
                is_instruction = True
                removed_instructions += 1
                extracted_code = '#include ' + stripped[len('Add #include '):]
                logger.debug(f"Extracted: {stripped} -> {extracted_code}")
            elif stripped.startswith('Add include '):
                is_instruction = True
                removed_instructions += 1
                extracted_code = '#include ' + stripped[len('Add include '):]
                logger.debug(f"Extracted: {stripped} -> {extracted_code}")
            elif stripped.startswith('Remove #include '):
                is_instruction = True
                removed_instructions += 1
                # Skip remove instructions
            elif stripped.startswith('Add #define '):
                is_instruction = True
                removed_instructions += 1
                extracted_code = '#define ' + stripped[len('Add #define '):]
            elif stripped.startswith('Add define '):
                is_instruction = True
                removed_instructions += 1
                extracted_code = '#define ' + stripped[len('Add define '):]
            elif any(stripped.startswith(p) for p in [
                'Change line', 'Replace with', 'Insert at', 
                'Delete line', 'Modify to', 'Update to',
                'Fix by adding', 'Add the following', 'Include the following'
            ]):
                is_instruction = True
                removed_instructions += 1
                # Skip these instructions
            
            if is_instruction:
                if extracted_code:
                    cleaned_lines.append(extracted_code)
                # Otherwise skip instruction line
            else:
                cleaned_lines.append(line)
        
        if removed_instructions > 0:
            code = '\n'.join(cleaned_lines)
            logger.warning(f"Removed {removed_instructions} instruction-style line(s) from LLM output")
        
        # AGGRESSIVE REGEX CLEANING (final pass)
        import re
        code = re.sub(r'^\s*Add\s+include\s+', '#include ', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*Add\s+define\s+', '#define ', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*Remove\s+include\s+.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*Remove\s+define\s+.*$', '', code, flags=re.MULTILINE)
        
        # Remove explanation comments LLMs sometimes add
        code = re.sub(r'^\s*//\s*(Here|This|Note|Important|Warning):.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*/\*\s*(Here|This|Note|Important|Warning):.*?\*/', '', code, flags=re.DOTALL)
        
        # Clean up multiple blank lines
        code = re.sub(r'\n\n\n+', '\n\n', code)
        
        if len(code) != original_length:
            logger.info(f"Cleaned LLM artifacts: {original_length} → {len(code)} chars")
        
        return code
    
    def validate_fixed_code(
        self,
        original_code: str,
        fixed_code: str,
        language: str = "c"
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate LLM-generated fix before applying.
        Rejects catastrophic changes that would destroy the file.
        
        Args:
            original_code: Original source code
            fixed_code: LLM-generated fixed code
            language: Programming language
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import re
        
        orig_len = len(original_code)
        fix_len = len(fixed_code)
        
        # Gate 1: SIZE RATIO — reject massive shrinkage or bloat
        if orig_len > 500:  # Only validate non-trivial files
            size_ratio = fix_len / orig_len if orig_len > 0 else 0
            if size_ratio < 0.30:
                return False, (
                    f"Fix rejected: file shrunk to {size_ratio:.0%} of original "
                    f"({fix_len} vs {orig_len} chars). Likely LLM replaced file with stubs."
                )
            if size_ratio > 5.0:
                return False, (
                    f"Fix rejected: file bloated to {size_ratio:.0%} of original "
                    f"({fix_len} vs {orig_len} chars). Likely LLM duplicated code."
                )
        
        # Gate 2: LINE COUNT RATIO — reject massive line loss
        orig_lines = len(original_code.splitlines())
        fix_lines = len(fixed_code.splitlines())
        if orig_lines > 20:
            line_ratio = fix_lines / orig_lines if orig_lines > 0 else 0
            if line_ratio < 0.30:
                return False, (
                    f"Fix rejected: line count dropped to {line_ratio:.0%} "
                    f"({fix_lines} vs {orig_lines} lines). Likely code was deleted."
                )
        
        # Gate 3: INCLUDE PRESERVATION — all original #includes must survive
        orig_includes = set()
        for line in original_code.splitlines():
            stripped = line.strip()
            if stripped.startswith('#include'):
                normalized = re.sub(r'\s+', ' ', stripped)
                orig_includes.add(normalized)
        
        fix_includes = set()
        for line in fixed_code.splitlines():
            stripped = line.strip()
            if stripped.startswith('#include'):
                normalized = re.sub(r'\s+', ' ', stripped)
                fix_includes.add(normalized)
        
        missing_includes = orig_includes - fix_includes
        if len(missing_includes) > 2:
            return False, (
                f"Fix rejected: {len(missing_includes)} #include directives were removed: "
                f"{', '.join(list(missing_includes)[:3])}"
            )
        
        # Gate 4: BRACE BALANCE — fixed code must have balanced braces
        def _count_brace_depth(code: str) -> int:
            depth = 0
            in_str = in_chr = in_lc = in_bc = False
            prev = ''
            for ch in code:
                if in_lc:
                    if ch == '\n': in_lc = False
                elif in_bc:
                    if prev == '*' and ch == '/': in_bc = False
                elif in_str:
                    if ch == '"' and prev != '\\': in_str = False
                elif in_chr:
                    if ch == "'" and prev != '\\': in_chr = False
                else:
                    if prev == '/' and ch == '/': in_lc = True
                    elif prev == '/' and ch == '*': in_bc = True
                    elif ch == '"': in_str = True
                    elif ch == "'": in_chr = True
                    elif ch == '{': depth += 1
                    elif ch == '}': depth -= 1
                prev = ch
            return depth

        brace_depth = _count_brace_depth(fixed_code)
        orig_brace_depth = _count_brace_depth(original_code)
        
        # Only reject if the fix made brace balance WORSE than original
        if brace_depth != 0 and abs(brace_depth) > abs(orig_brace_depth):
            return False, (
                f"Fix rejected: unbalanced braces (depth={brace_depth}, "
                f"original={orig_brace_depth}). "
                f"LLM likely added/removed braces incorrectly."
            )
        
        # Gate 5: STUB DETECTION — reject if output is mostly stubs
        stub_markers = [
            '// implementation goes here', '// todo:', '// stub',
            '/* implementation */', '// placeholder', '// not implemented',
        ]
        fix_lower = fixed_code.lower()
        stub_count = sum(1 for m in stub_markers if m in fix_lower)
        if stub_count >= 2:
            return False, (
                f"Fix rejected: contains {stub_count} stub/placeholder markers. "
                f"LLM replaced real code with stubs."
            )
        
        # Gate 6: AST-BASED SEMANTIC VALIDATION — uses tree-sitter to compare
        # original vs fixed AST for structural equivalence.
        if language.lower() in ('c', 'cpp', 'c++'):
            sv = get_semantic_validator() if get_semantic_validator else None
            if sv and sv.available:
                is_valid, reason, sem_diff = sv.validate_fix(
                    original_code, fixed_code, language
                )
                if not is_valid and reason:
                    return False, f"Fix rejected (semantic): {reason}"
                # Even if AST validation passed, log if diff detected changes
                if sem_diff and (sem_diff.added_functions or sem_diff.signature_changes):
                    logger.info(
                        "AST diff: added_funcs=%s, sig_changes=%s",
                        sem_diff.added_functions, sem_diff.signature_changes,
                    )
            else:
                # DEGRADED MODE: Regex fallback when tree-sitter unavailable.
                # Use STRICTER thresholds to compensate for loss of AST analysis.
                logger.debug("Gate 6: using regex fallback (degraded mode)")
                orig_funcs_set = set(_extract_function_signatures(original_code))
                fix_funcs_set  = set(_extract_function_signatures(fixed_code))
                missing_funcs = orig_funcs_set - fix_funcs_set
                missing_funcs.discard('main')
                # Degraded: reject if ANY function was removed (vs 30% in AST mode)
                if missing_funcs:
                    return False, (
                        f"Fix rejected [degraded mode]: {len(missing_funcs)} function(s) removed: "
                        f"{', '.join(sorted(list(missing_funcs)[:5]))}. "
                        f"(Stricter threshold because AST validation is unavailable.)"
                    )
                # Degraded: also reject if line count dropped more than 15%
                # (AST mode checks this structurally; regex mode compensates with tighter bound)
                if orig_lines > 30:
                    if line_ratio < 0.50:
                        return False, (
                            f"Fix rejected [degraded mode]: "
                            f"line count dropped to {line_ratio:.0%} "
                            f"({fix_lines} vs {orig_lines} lines). "
                            f"(Stricter threshold because AST validation is unavailable.)"
                        )

        # All gates passed
        return True, None
    
    def safe_header_fix(
        self,
        header_code: str,
        errors: List[str],
        language: str = "c",
        max_attempts: int = 2
    ) -> Tuple[str, bool, List[str]]:
        """
        Safely fix header files with restricted modifications.
        Only allows adding includes and forward declarations.
        
        Args:
            header_code: Original header code
            errors: List of errors
            language: Programming language
            max_attempts: Maximum attempts
            
        Returns:
            Tuple of (fixed_code, success, remaining_errors)
        """
        logger.info("Using protected mode for header file")
        
        if not self.llm_provider:
            return header_code, False, errors
        
        # Build conservative system prompt
        system_prompt = f"""You are a C/C++ compilation error fixer specialized in header files.

CRITICAL RULES FOR HEADER FILES:
1. DO NOT modify or remove existing declarations
2. DO NOT add function implementations (only declarations allowed)
3. ONLY add missing #include directives AT THE TOP of the file
4. ONLY add forward declarations (struct/typedef/function declarations)
5. DO NOT change existing function signatures
6. Be EXTREMELY conservative - only make minimal necessary changes

ABSOLUTE PROHIBITIONS:
- NEVER comment out or remove existing #include directives
- NEVER add #ifdef/#endif blocks around existing code
- NEVER modify namespace structure or indentation
- NEVER change existing function return types or parameters
- Keep ALL existing #include statements exactly as they are
- ESPECIALLY keep project-specific includes like "memory.h", "common.h", etc.

You can ONLY:
- ADD new #include directives at the top (after #pragma once or existing includes)
- ADD forward declarations before the namespace or at file start

Return ONLY the fixed header file code within code blocks (```{language} ... ```).
"""
        
        error_text = "\n".join([f"  - {error}" for error in errors[:10]])
        
        user_prompt = f"""
The following header file has compilation errors:

```{language}
{header_code}
```

ERRORS:
{error_text}

Fix ONLY by adding:
1. Missing #include directives (e.g., #include <windows.h>, #include <shlobj.h>)
2. Forward declarations (e.g., struct MyStruct; or int MyFunction();)

DO NOT:
- Modify existing declarations
- Remove any code
- Add implementations
- Change signatures

Return the fixed header code.
"""
        
        try:
            # Prepare params
            gen_params = {
                'system_prompt': system_prompt,
                'user_prompt': user_prompt,
            }
            
            # Only pass model for non-hybrid mode
            if not self.use_hybrid or not hasattr(self.llm_provider, 'choose_provider'):
                try:
                    from llm_api import MistralAPIProvider, DeepSeekProvider as _DeepSeekProvider
                    _needs_hyphen = isinstance(self.llm_provider, (MistralAPIProvider, _DeepSeekProvider))
                except Exception:
                    _needs_hyphen = False
                gen_params['model'] = self.llm_model.replace(":", "-") if _needs_hyphen else self.llm_model
            
            response = self.llm_provider.generate(**gen_params)
            
            fixed_code = self._extract_code_from_response(response, language)
            
            if fixed_code:
                # CRITICAL: Restore any project includes that were removed
                fixed_code = self._restore_removed_includes(header_code, fixed_code)
                
                # Validate header structure wasn't broken
                struct_valid, struct_error = self._validate_header_structure(header_code, fixed_code)
                if not struct_valid:
                    logger.warning(f"⚠️ Header structure broken: {struct_error}, rejecting fix")
                    return header_code, False, errors
                
                # Validate the fix
                is_valid, error_msg = self.validate_fixed_code(header_code, fixed_code, language)
                if not is_valid:
                    logger.warning(f"Header fix validation failed: {error_msg}")
                    return header_code, False, errors
                
                logger.info("✓ Header file safely fixed")
                return fixed_code, True, []
            
        except Exception as e:
            logger.error(f"Safe header fix failed: {e}")
        
        return header_code, False, errors
    
    # ── Surgical fix for large files ──────────────────────────────────
    def fix_large_file_surgically(
        self,
        source_code: str,
        errors: List[str],
        language: str = "c",
        project_context: Optional[str] = None,
        file_context: Optional[str] = None,
        margin: int = 15,
        max_region_lines: int = 40,
        clang_analysis = None,
        source_file_path: Optional[str] = None,
    ) -> Tuple[str, bool, List[str]]:
        """Fix a file that is too large to send in its entirety to the LLM.

        Strategy
        --------
        1. Parse error messages to extract line numbers.
        2. Merge nearby error lines into *regions* (each ≤ max_region_lines).
        3. For each region, extract the source section and its errors.
        4. Ask the LLM to fix *only* that section.
        5. Splice the fixed section back into the full file.

        Returns:
            (fixed_code, any_fix_applied, remaining_errors)
        """
        if not self.llm_provider:
            return source_code, False, errors

        # ── Track which provider is used for surgical fix ──
        _surgical_provider_tag = self._detect_provider_tag(len(source_code), len(errors))
        _track_key = f'surgical_{_surgical_provider_tag}'
        if _track_key in self.fix_tracking:
            self.fix_tracking[_track_key]['attempts'] += 1
            self.fix_tracking[_track_key]['errors_before'] += len(errors)
        logger.info(f"[TRACK] Surgical fix path: {_track_key} | errors_in={len(errors)}")

        # DEBUG: Print actual errors received for surgical fix
        logger.info(f"Surgical fix received {len(errors)} error(s):")
        for i, err in enumerate(errors[:5]):  # Print first 5
            logger.info(f"  [{i+1}] {err[:200]}")

        error_line_nums = _parse_error_line_numbers(errors)
        if not error_line_nums:
            logger.warning(f"Surgical fix: could not parse line numbers from {len(errors)} errors — using truncated-file fallback")
            # Fallback: send the first ~1500 lines (≈ 45K chars max) to the LLM.
            # Most errors (missing headers, global declarations) occur early in the file.
            source_lines = source_code.split('\n')
            max_lines = min(1500, len(source_lines))
            truncated = '\n'.join(source_lines[:max_lines])
            if len(truncated) > 48000:
                # Further trim to stay under LLM context limits
                truncated = truncated[:48000]
                max_lines = truncated.count('\n') + 1

            error_text = "\n".join([f"  - {e}" for e in errors[:20]])
            sys_prompt = (
                f"You are an expert {language} programmer fixing compilation errors.\n"
                "You are given the FIRST PORTION of a large source file.\n"
                "Fix the compilation errors visible in this portion.\n"
                "Return ONLY the fixed portion wrapped in ```" + language + "``` blocks.\n"
            )
            user_prompt = (
                f"This is the first {max_lines} lines of a {len(source_lines)}-line {language} file.\n\n"
                f"```{language}\n{truncated}\n```\n\n"
                f"COMPILATION ERRORS:\n{error_text}\n\n"
                f"Fix the errors and return the fixed portion."
            )
            try:
                gen_params = {'system_prompt': sys_prompt, 'user_prompt': user_prompt}
                if not self.use_hybrid or not hasattr(self.llm_provider, 'choose_provider'):
                    try:
                        from llm_api import MistralAPIProvider, DeepSeekProvider as _DeepSeekProvider
                        _needs_hyphen = isinstance(self.llm_provider, (MistralAPIProvider, _DeepSeekProvider))
                    except Exception:
                        _needs_hyphen = False
                    gen_params['model'] = self.llm_model.replace(":", "-") if _needs_hyphen else self.llm_model
                elif self.use_hybrid:
                    gen_params.update({'file_size': len(truncated), 'error_count': len(errors), 'is_header': False})
                response = self.llm_provider.generate(**gen_params)
                fixed_section = self._extract_code_from_response(response, language)
                if fixed_section:
                    fixed_section = self._clean_llm_artifacts(fixed_section)
                    fixed_section = self._sanitize_dangerous_patterns(fixed_section)
                    if len(fixed_section) > len(truncated) * 0.15:
                        fixed_lines = fixed_section.split('\n')
                        source_lines[:max_lines] = fixed_lines
                        logger.info(f"   ✓ Truncated-file fallback applied ({max_lines} lines fixed)")
                        return '\n'.join(source_lines), True, errors
            except Exception as e:
                logger.error(f"   Truncated-file fallback failed: {e}")
            return source_code, False, errors

        regions = _group_into_regions(error_line_nums, margin=margin, max_region_lines=max_region_lines)
        logger.info(
            f"Surgical fix: {len(error_line_nums)} error lines → {len(regions)} region(s)"
        )

        source_lines = source_code.split('\n')
        total_lines = len(source_lines)
        any_fix_applied = False

        # ── NEW: Extract global declarations for context ──
        global_decls = _extract_global_declarations(source_lines)
        # Limit global declarations to avoid overwhelming prompt
        if len(global_decls) > 600:
            global_decls = global_decls[:600] + '\n// ... (truncated)'
        global_decls_section = ""
        if global_decls:
            global_decls_section = (
                "\nGLOBAL DECLARATIONS (READ ONLY — do NOT duplicate):\n"
                f"```\n{global_decls}\n```\n"
            )

        # Hybrid params — base; will be overridden per-region with actual region size
        _use_hybrid_routing = self.use_hybrid and hasattr(self.llm_provider, 'choose_provider')

        # ── NEW: Context window size for surrounding lines ──
        CONTEXT_LINES = 10  # lines shown before/after region as read-only context

        for region_idx, (reg_start, reg_end) in enumerate(regions):
            # Clamp to file boundaries
            reg_start = max(1, reg_start)
            reg_end = min(total_lines, reg_end)

            # Extract the section (1-based → 0-based)
            section_lines = source_lines[reg_start - 1 : reg_end]
            section_text = '\n'.join(section_lines)

            # ── NEW: Extract surrounding context (read-only) ──
            ctx_before_start = max(0, reg_start - 1 - CONTEXT_LINES)
            ctx_after_end = min(total_lines, reg_end + CONTEXT_LINES)
            context_before = '\n'.join(source_lines[ctx_before_start : reg_start - 1])
            context_after = '\n'.join(source_lines[reg_end : ctx_after_end])

            surrounding_context = ""
            if context_before.strip():
                surrounding_context += (
                    f"\nCODE BEFORE THIS SECTION (lines {ctx_before_start+1}–{reg_start-1}, READ ONLY — do NOT include in output):\n"
                    f"```{language}\n{context_before}\n```\n"
                )
            if context_after.strip():
                surrounding_context += (
                    f"\nCODE AFTER THIS SECTION (lines {reg_end+1}–{ctx_after_end}, READ ONLY — do NOT include in output):\n"
                    f"```{language}\n{context_after}\n```\n"
                )

            # ── NEW: Cross-region symbol protection ──
            defined_syms = _extract_defined_symbols(section_text)
            cross_region_syms = _find_symbols_used_elsewhere(
                source_lines, reg_start, reg_end, defined_syms
            )
            symbol_warning = ""
            if cross_region_syms:
                sym_list = ', '.join(cross_region_syms[:20])
                symbol_warning = (
                    f"\n⚠️  PROTECTED SYMBOLS — these are defined in this section but used "
                    f"ELSEWHERE in the file. You MUST preserve their names and signatures:\n"
                    f"   {sym_list}\n"
                    f"   Do NOT rename, remove, or change the return type / parameters of these symbols.\n"
                )
                logger.info(
                    f"   Region {region_idx+1}: {len(cross_region_syms)} cross-region symbols protected: "
                    f"{', '.join(cross_region_syms[:10])}"
                )

            # ── NEW: Capture original structural metrics for validation ──
            orig_brace_balance = _check_brace_balance(section_text)
            orig_func_sigs = _extract_function_signatures(section_text)
            orig_includes = set(re.findall(r'^\s*#\s*include\s+[<"][^>"]+[>"]', section_text, re.MULTILINE))

            # Filter errors relevant to this region
            region_errors: List[str] = []
            for err in errors:
                m = (_MSVC_LINE_RE.search(err) or _GCC_LINE_RE.search(err)
                     or _GENERIC_LINE_RE.search(err) or _BARE_LINE_RE.search(err))
                if m:
                    ln = int(m.group(1))
                    if reg_start <= ln <= reg_end:
                        region_errors.append(err)
                else:
                    # Errors without line numbers — include them (may be relevant)
                    region_errors.append(err)

            if not region_errors:
                continue

            error_text = "\n".join([f"  - {e}" for e in region_errors[:15]])

            context_section = ""
            if project_context:
                context_section += f"\nPROJECT CONTEXT:\n{project_context}\n"
            if file_context:
                context_section += f"\nFILE CONTEXT:\n{file_context}\n"

            # ── Per-region AST/semantic context from Clang analysis ──
            region_ast_context = ""
            if clang_analysis and source_file_path:
                try:
                    region_ast_ctx = clang_analysis.get_region_semantic_context(
                        source_file_path, reg_start, reg_end, max_length=2500
                    )
                    if region_ast_ctx:
                        region_ast_context = f"\nAST SEMANTIC CONTEXT (for this region):\n{region_ast_ctx}\n"
                        logger.info(
                            f"   Region {region_idx+1}: AST context injected "
                            f"({len(region_ast_ctx)} chars)"
                        )
                except Exception as e:
                    logger.debug(f"   Region {region_idx+1}: Clang context error: {e}")

            # Detect if this is a header file
            _is_hdr = source_file_path and os.path.splitext(source_file_path)[1].lower() in ('.h', '.hh', '.hpp', '.hxx')
            _hdr_surgical_warning = ""
            if _is_hdr:
                _hdr_surgical_warning = (
                    "\n⚠️ THIS IS A HEADER FILE included by a .c/.cpp file that already includes system headers.\n"
                    "DO NOT add #include, typedef struct for SDK types, or forward-declare Win32 API functions.\n"
                    "All system types and functions are already available from the parent .c file's includes.\n"
                )

            system_prompt = (
                f"You are a {language} compiler error fixer. "
                "Fix ONLY the errors in the given code section. "
                "Return the COMPLETE fixed section with the SAME number of lines.\n\n"
                "RULES:\n"
                "1. Keep ALL existing code — do NOT delete or compress lines.\n"
                "2. Fix errors by MODIFYING lines, not removing them.\n"
                "3. Keep the same line count (±10%).\n"
                "4. For undeclared identifiers: add a forward declaration, do NOT remove usage.\n"
                "5. NEVER remove #include, function definitions, or variable declarations.\n"
                "6. Preserve brace balance ({/}).\n"
                "7. Wrap output in: ```" + language + "\\n<code>\\n```\n"
                + _hdr_surgical_warning +
                "\nFEW-SHOT PATTERNS:\n"
                "- Brace mismatch: add the missing } at the right scope, never delete lines.\n"
                "- Undeclared type X: add 'typedef struct X X;' before usage, not remove usage.\n"
                "- Missing #include cascade: restore the #include, do not strip dependent code.\n"
            )

            # ── Build DO_NOT_TOUCH list from structural info ──
            do_not_touch = ""
            protected_items = []
            if cross_region_syms:
                protected_items.extend(cross_region_syms[:15])
            if orig_includes:
                protected_items.append("all #include directives")
            if orig_func_sigs:
                for sig in list(orig_func_sigs)[:5]:
                    protected_items.append(f"signature: {sig}")
            if protected_items:
                do_not_touch = (
                    "\nDO NOT TOUCH (these must remain unchanged):\n"
                    + "".join(f"  - {item}\n" for item in protected_items)
                )

            user_prompt = (
                f"EDIT WINDOW: lines {reg_start}–{reg_end} (of {total_lines} total). "
                f"You may ONLY modify code within this range.\n\n"
                f"Fix errors in lines {reg_start}–{reg_end} of a {total_lines}-line {language} file.\n"
                f"{global_decls_section}"
                f"{surrounding_context}"
                f"{symbol_warning}"
                f"{do_not_touch}"
                f"{region_ast_context}"
                f"\nSECTION TO FIX:\n"
                f"```{language}\n{section_text}\n```\n\n"
                f"ERRORS:\n{error_text}\n"
                f"{context_section}\n"
                f"Return the COMPLETE fixed section in ```{language}``` blocks. Keep ALL lines."
            )

            try:
                # ── Per-region hybrid routing: pass REGION size, not full file ──
                region_hybrid_params: Dict = {}
                if _use_hybrid_routing:
                    region_hybrid_params = {
                        'file_size': len(section_text),  # region size, NOT full file
                        'error_count': len(region_errors),
                        'is_header': False,
                    }

                gen_params = {
                    'system_prompt': system_prompt,
                    'user_prompt': user_prompt,
                }
                if not self.use_hybrid or not hasattr(self.llm_provider, 'choose_provider'):
                    try:
                        from llm_api import MistralAPIProvider, DeepSeekProvider as _DeepSeekProvider
                        _needs_hyphen = isinstance(self.llm_provider, (MistralAPIProvider, _DeepSeekProvider))
                    except Exception:
                        _needs_hyphen = False
                    gen_params['model'] = self.llm_model.replace(":", "-") if _needs_hyphen else self.llm_model
                else:
                    gen_params.update(region_hybrid_params)

                # Retry with backoff for rate limit errors
                response = None
                max_retries = 3
                for retry_idx in range(max_retries):
                    try:
                        # Reset cloud cooldown state before retry
                        if retry_idx > 0 and hasattr(self.llm_provider, '_cloud_consecutive_fails'):
                            self.llm_provider._cloud_consecutive_fails = 0
                            self.llm_provider._cloud_cooldown_until = 0.0
                        response = self.llm_provider.generate(**gen_params)
                        break  # Success
                    except LLMAPIError as retry_e:
                        if "rate limit" in str(retry_e).lower() or "429" in str(retry_e):
                            wait_time = 30 * (retry_idx + 1)  # 30s, 60s, 90s
                            logger.warning(
                                f"   Region {region_idx+1}: rate limit hit, "
                                f"waiting {wait_time}s before retry {retry_idx+2}/{max_retries}..."
                            )
                            import time
                            time.sleep(wait_time)
                        else:
                            raise  # Non-rate-limit error, propagate

                if not response:
                    logger.error(f"   Region {region_idx+1}: all {max_retries} retries exhausted (rate limit)")
                    continue

                fixed_section = self._extract_code_from_response(response, language)

                if fixed_section:
                    fixed_section = self._clean_llm_artifacts(fixed_section)
                    fixed_section = self._sanitize_dangerous_patterns(fixed_section)

                    # ── Validation Gate 1: Size check ──
                    if len(fixed_section) < len(section_text) * 0.15:
                        logger.warning(
                            f"   Region {region_idx+1}: fix too short "
                            f"({len(fixed_section)} vs {len(section_text)}), skipping"
                        )
                        continue
                    if len(fixed_section) > len(section_text) * 4:
                        logger.warning(
                            f"   Region {region_idx+1}: fix too long "
                            f"({len(fixed_section)} vs {len(section_text)}), skipping"
                        )
                        continue

                    # ── Validation Gate 1b: Max delta check (anti-deletion) ──
                    orig_line_count = reg_end - reg_start + 1
                    fixed_line_count = len(fixed_section.split('\n'))
                    delta_pct = abs(fixed_line_count - orig_line_count) / max(orig_line_count, 1)
                    # Degraded mode uses tighter threshold (15% vs 25%)
                    max_delta = 0.15 if not _AST_AVAILABLE else 0.25
                    if delta_pct > max_delta:
                        logger.warning(
                            f"   Region {region_idx+1}: line count changed too much "
                            f"({orig_line_count} → {fixed_line_count}, {delta_pct:.0%}, "
                            f"max={max_delta:.0%}{'[degraded]' if not _AST_AVAILABLE else ''}), skipping"
                        )
                        continue

                    # ── Validation Gate 2: Brace balance preservation ──
                    fixed_brace_balance = _check_brace_balance(fixed_section)
                    if fixed_brace_balance != orig_brace_balance:
                        logger.warning(
                            f"   Region {region_idx+1}: brace balance changed "
                            f"({orig_brace_balance} → {fixed_brace_balance}), skipping "
                            f"(would break surrounding code)"
                        )
                        continue

                    # ── Validation Gate 3: AST-based semantic validation ──
                    # Uses tree-sitter to compare original vs fixed region structure.
                    sv = get_semantic_validator() if get_semantic_validator else None
                    if sv and sv.available:
                        orig_snap = sv.extract_snapshot(section_text, language)
                        fix_snap = sv.extract_snapshot(fixed_section, language)
                        if orig_snap is not None and fix_snap is not None:
                            sem_diff = sv.diff(orig_snap, fix_snap)
                            if not sem_diff.is_safe:
                                reason = sem_diff.rejection_reason or "unknown semantic violation"
                                logger.warning(
                                    f"   Region {region_idx+1}: AST validation failed — {reason}, skipping"
                                )
                                continue
                    else:
                        # DEGRADED MODE: Regex fallback — stricter checks
                        logger.debug(f"   Region {region_idx+1}: AST unavailable, using degraded validation")

                        # Regex fallback: include preservation (strict: 0 removals)
                        fixed_includes = set(re.findall(
                            r'^\s*#\s*include\s+[<"][^>"]+[>"]', fixed_section, re.MULTILINE
                        ))
                        removed_includes = orig_includes - fixed_includes
                        if removed_includes:
                            logger.warning(
                                f"   Region {region_idx+1}: [degraded] fix removed #include(s): "
                                f"{removed_includes}, skipping"
                            )
                            continue

                        # Regex fallback: ANY missing function rejects (strict)
                        fixed_func_sigs = _extract_function_signatures(fixed_section)
                        missing_funcs = set(orig_func_sigs) - set(fixed_func_sigs)
                        if missing_funcs:
                            logger.warning(
                                f"   Region {region_idx+1}: [degraded] fix removed function(s): "
                                f"{missing_funcs}, skipping"
                            )
                            continue

                    # ── Validation Gate 5: Cross-region symbol preservation ──
                    if cross_region_syms:
                        missing_syms = []
                        for sym in cross_region_syms:
                            if _AST_AVAILABLE and sv is not None:
                                refs = sv.find_symbol_references(fixed_section, sym, language)
                                if not refs:
                                    missing_syms.append(sym)
                            else:
                                if not re.search(r'\b' + re.escape(sym) + r'\b', fixed_section):
                                    missing_syms.append(sym)
                        if missing_syms:
                            logger.warning(
                                f"   Region {region_idx+1}: fix removed cross-region symbol(s): "
                                f"{missing_syms}, skipping (would break other regions)"
                            )
                            continue

                    # ── All validations passed — splice the fixed section back ──
                    fixed_section_lines = fixed_section.split('\n')
                    source_lines[reg_start - 1 : reg_end] = fixed_section_lines

                    # Adjust total_lines and subsequent regions
                    delta = len(fixed_section_lines) - (reg_end - reg_start + 1)
                    total_lines += delta

                    # Shift remaining regions by delta
                    shifted = []
                    for j in range(region_idx + 1, len(regions)):
                        s, e = regions[j]
                        shifted.append((s + delta, e + delta))
                    regions[region_idx + 1 :] = shifted

                    any_fix_applied = True
                    logger.info(
                        f"   ✓ Region {region_idx+1} (lines {reg_start}–{reg_end}): "
                        f"fixed {len(region_errors)} error(s), delta={delta:+d} lines | "
                        f"braces={orig_brace_balance}, funcs={len(orig_func_sigs)}, "
                        f"protected_syms={len(cross_region_syms)}"
                    )
                else:
                    logger.warning(
                        f"   Region {region_idx+1}: no code extracted from LLM response"
                    )

            except LLMAPIError as e:
                logger.error(f"   Region {region_idx+1}: LLM API error: {e}")
            except Exception as e:
                logger.error(f"   Region {region_idx+1}: unexpected error: {e}")

        fixed_code = '\n'.join(source_lines)
        # ── Track surgical result ──
        if _track_key in self.fix_tracking:
            if any_fix_applied:
                self.fix_tracking[_track_key]['successes'] += 1
            # errors_after will be updated after recompilation by caller
        logger.info(f"[TRACK] Surgical fix result: {_track_key} | applied={any_fix_applied}")
        return fixed_code, any_fix_applied, errors  # caller will recompile to get actual remaining errors

    def fix_compilation_errors(
        self,
        source_code: str,
        errors: List[str],
        language: str = "c",
        max_attempts: int = 3,
        use_pattern_fixes: bool = True,
        max_code_length: int = 50000,  # Max characters to send in prompt
        project_context: Optional[str] = None,  # Project-wide context
        file_context: Optional[str] = None,  # File-specific context
        is_header_file: bool = False,  # Enable protected mode for headers
        clang_analysis = None,  # Clang AnalysisResult for per-region AST context
        source_file_path: Optional[str] = None,  # Source file path for Clang context
        previous_fix_errors: Optional[List[str]] = None,  # Errors from a prior failed fix attempt
        compiler_type: Optional[str] = None,  # 'msvc', 'gcc', 'clang', or None (use self.compiler_type)
    ) -> Tuple[str, bool, List[str]]:
        """
        Fix compilation errors using LLM with multi-turn conversation.
        
        Each attempt builds on the previous one — the LLM sees its own prior
        fix and the *new* errors that resulted, so it can iterate instead of
        starting from scratch every time.
        
        Returns:
            Tuple of (fixed_code, success, remaining_errors)
        """
        if not self.llm_provider:
            logger.error("LLM provider not available")
            return source_code, False, errors
        
        if not errors:
            return source_code, True, []
        
        # Apply pattern-based fixes first (for easy cases like non-standard functions)
        if use_pattern_fixes:
            try:
                from .fix_strategies import FixStrategies
                pattern_fixed_code = FixStrategies.apply_pattern_fixes(source_code, errors, language)
                if pattern_fixed_code != source_code:
                    logger.info("Applied pattern-based fixes before LLM")
                    source_code = pattern_fixed_code
            except Exception as e:
                logger.debug(f"Pattern fixes failed: {e}")
        
        # Use safe mode for header files
        if is_header_file:
            return self.safe_header_fix(source_code, errors, language, min(max_attempts, 2))
        
        # Check if source code is too large for LLM — use surgical fix
        if len(source_code) > max_code_length:
            logger.warning(f"Source code too large ({len(source_code)} chars, max {max_code_length})")
            logger.info("Using SURGICAL FIX — fixing error regions only")
            return self.fix_large_file_surgically(
                source_code, errors, language,
                project_context=project_context,
                file_context=file_context,
                clang_analysis=clang_analysis,
                source_file_path=source_file_path,
            )
        
        # ── Track normal (non-surgical) fix path ──
        _normal_provider_tag = self._detect_provider_tag(len(source_code), len(errors))
        _normal_track_key = f'normal_{_normal_provider_tag}'
        if _normal_track_key in self.fix_tracking:
            self.fix_tracking[_normal_track_key]['attempts'] += 1
            self.fix_tracking[_normal_track_key]['errors_before'] += len(errors)
        logger.info(f"[TRACK] Normal fix path: {_normal_track_key} | errors_in={len(errors)} | file_size={len(source_code)}")
        
        # Resolve effective compiler type
        _eff_compiler = compiler_type or self.compiler_type
        if _eff_compiler == 'auto' and detect_compiler_from_errors:
            _eff_compiler = detect_compiler_from_errors(errors)
        _is_msvc = _eff_compiler in (COMPILER_MSVC, COMPILER_AUTO)
        
        error_text = "\n".join([f"  - {error}" for error in errors[:20]])
        if len(errors) > 20:
            error_text += f"\n  ... and {len(errors) - 20} more errors"
        
        # Analyze errors to get better context
        if ErrorAnalyzer:
            try:
                error_infos = ErrorAnalyzer.classify_errors(errors, compiler_type=_eff_compiler)
                strategy = ErrorAnalyzer.get_fix_strategy(error_infos, compiler_type=_eff_compiler)
                system_prompt = self._build_system_prompt(language, strategy)
                error_context = self._build_error_context(error_infos, strategy)
            except Exception as e:
                logger.warning(f"Error analysis failed, using fallback: {e}")
                system_prompt = self._build_fallback_system_prompt(language, compiler_type=_eff_compiler)
                error_context = self._build_fallback_error_context(errors)
        else:
            system_prompt = self._build_fallback_system_prompt(language, compiler_type=_eff_compiler)
            error_context = self._build_fallback_error_context(errors)
        
        # Build context section
        context_section = ""
        if project_context:
            context_section += f"\nPROJECT CONTEXT:\n{project_context}\n"
        if file_context:
            context_section += f"\nFILE CONTEXT:\n{file_context}\n"
        
        # Add Clang AST context for the full file (non-surgical path)
        if clang_analysis and source_file_path:
            try:
                clang_file_ctx = clang_analysis.get_compilation_fix_context(
                    source_file_path, max_length=3000
                )
                if clang_file_ctx:
                    context_section += f"\n{clang_file_ctx}\n"
            except Exception as e:
                logger.debug(f"Clang fix context error: {e}")
        
        # Check for duplicate entry point errors
        entry_point_warning = ""
        if any('multiple definition' in err and 'WinMain' in err for err in errors):
            entry_point_warning = (
                "\n⚠️  WARNING - DUPLICATE ENTRY POINT DETECTED:\n"
                "The project ALREADY HAS a WinMain in another file.\n"
                "DO NOT add another WinMain to this file.\n"
            )

        # Detect VLA pattern: undeclared identifier used as array size
        # MSVC: C2065+C2057+C2466+C2133;  GCC/Clang: 'variable-length array' or similar
        vla_warning = ""
        import re as _re
        vla_ids = []
        if _is_msvc:
            for err in errors:
                m = _re.search(r"C2065.*'([^']+)'.*undeclared", err)
                if m:
                    ident = m.group(1)
                    has_c2057 = any(ident in e and 'C2057' in e for e in errors)
                    if has_c2057 and ident not in vla_ids:
                        vla_ids.append(ident)
            if vla_ids:
                vla_warning = (
                    f"\n🚫 VLA (Variable-Length Array) DETECTED — MSVC does NOT support C99 VLAs:\n"
                    f"   Undeclared array-size identifiers: {', '.join(vla_ids)}\n"
                    f"   These identifiers are used as array sizes but are not defined as constants.\n"
                    f"   FIX: Add these lines near the top of the file (after includes, before code):\n"
                )
                for vid in vla_ids:
                    vla_warning += f"   #ifndef {vid}\n   #define {vid} 256\n   #endif\n"
                vla_warning += (
                    f"   Use #ifndef guard so it doesn't conflict if defined elsewhere.\n"
                    f"   Keep the array declarations as-is: char buf[{vla_ids[0]}]; — just add the #define.\n"
                    f"   NEVER use 'string' as a variable/type name — it conflicts with Windows SDK.\n"
                )
        else:
            # GCC/Clang: VLAs are valid C99 but we still warn if size ident is undeclared
            for err in errors:
                m = _re.search(r"'([^']+)' undeclared", err)
                if m:
                    ident = m.group(1)
                    if any('variable' in e and 'size' in e and ident in e for e in errors):
                        if ident not in vla_ids:
                            vla_ids.append(ident)
            if vla_ids:
                vla_warning = (
                    f"\n⚠️ Undeclared array-size identifiers detected: {', '.join(vla_ids)}\n"
                    f"   These are used as array sizes but not defined. Either:\n"
                    f"   a) Add `#define {vla_ids[0]} 256` (preferred for portability), OR\n"
                    f"   b) Declare them as `const size_t` variables (C99+ VLA).\n"
                )

        # Detect header file being fixed via normal path — warn about include context
        header_file_warning = ""
        if source_file_path and os.path.splitext(source_file_path)[1].lower() in ('.h', '.hh', '.hpp', '.hxx'):
            _hdr_name = os.path.basename(source_file_path)
            header_file_warning = (
                f"\n⚠️  HEADER FILE CONTEXT — THIS FILE IS '{_hdr_name}':\n"
                f"This is a .h header file that is #include'd by a .c/.cpp file.\n"
                f"The .c file ALREADY includes system headers like <windows.h>, <winioctl.h>, <stdio.h>,\n"
                f"<stdlib.h>, <string.h>, etc. BEFORE including this header.\n"
                f"Therefore:\n"
                f"- DO NOT add #include <windows.h> or any system #include at the top of this file\n"
                f"- DO NOT add typedef struct for SDK types (STORAGE_PROPERTY_QUERY, STORAGE_DEVICE_DESCRIPTOR, etc.)\n"
                f"- DO NOT add forward declarations for Win32 API functions (CreateFileA, DeviceIoControl, CloseHandle, etc.)\n"
                f"- DO NOT redefine macros already in system headers (FILE_SHARE_READ, OPEN_EXISTING, etc.)\n"
                f"- DO NOT re-declare CRT functions (strcpy_s, memcpy, sprintf, etc.)\n"
                f"All these symbols are ALREADY available from the system headers included by the parent .c file.\n"
                f"Only fix actual code errors within the existing function bodies.\n"
            )

        # Detect linker errors (MSVC: LNK2019/LNK2001, GCC/Clang: 'undefined reference to')
        lnk_warning = ""
        lnk_symbols = []
        if _is_msvc:
            for err in errors:
                m = _re.search(r'LNK2019.*unresolved external symbol\s+(\S+)', err)
                if not m:
                    m = _re.search(r'LNK2001.*unresolved external symbol\s+(\S+)', err)
                if m and len(lnk_symbols) < 5:
                    lnk_symbols.append(m.group(1))
            if lnk_symbols:
                lnk_warning = (
                    f"\n🔗 LINKER ERRORS DETECTED (LNK2019/LNK2001):\n"
                    f"   Unresolved symbols: {', '.join(lnk_symbols[:5])}\n"
                    f"   Possible causes (check ALL before acting):\n"
                    f"   a) A critical #include was removed (e.g. <windows.h>) → restore the #include.\n"
                    f"   b) A required import library is missing → add #pragma comment(lib, \"name.lib\").\n"
                    f"   c) A function prototype does not match the actual definition (calling convention,\n"
                    f"      name decoration, or parameter mismatch) → fix the declaration to match.\n"
                    f"   Choose the fix that matches the actual root cause. Do NOT blindly assume (a).\n"
                )
        else:
            for err in errors:
                m = _re.search(r'undefined reference to [`\'"]?(\w+)', err)
                if m and len(lnk_symbols) < 5:
                    lnk_symbols.append(m.group(1))
            if lnk_symbols:
                lnk_warning = (
                    f"\n🔗 LINKER ERRORS DETECTED (undefined reference):\n"
                    f"   Unresolved symbols: {', '.join(lnk_symbols[:5])}\n"
                    f"   Possible causes:\n"
                    f"   a) A required #include was removed → restore it.\n"
                    f"   b) A function is declared but not defined in any compiled source file.\n"
                    f"   c) A function is defined as `static` in another file (not visible to linker).\n"
                    f"   d) Missing `-l` library flag → add the function's definition or declaration.\n"
                    f"   Choose the fix that matches the actual root cause.\n"
                )

        # ── Build previous failure feedback section ──
        prev_fail_section = ""
        if previous_fix_errors:
            prev_sample = previous_fix_errors[:5]
            prev_fail_section = (
                "\n⚠️ PREVIOUS FIX ATTEMPT FAILED with these errors:\n"
                + "".join(f"  - {e}\n" for e in prev_sample)
                + "Avoid repeating the same mistakes. Pay special attention to these error patterns.\n"
            )

        # ── RAG: Retrieve similar past fixes as dynamic few-shot ──
        rag_few_shot_section = ""
        if self.fix_history_rag:
            try:
                retrieved = self.fix_history_rag.retrieve_similar_fixes(
                    errors, language=language, top_k=2, min_similarity=0.25
                )
                if retrieved:
                    rag_few_shot_section = self.fix_history_rag.format_as_few_shot(retrieved)
            except Exception as e:
                logger.debug(f"[RAG] Retrieval failed: {e}")

        # ── RAG: Retrieve anti-examples (failed fixes) ──
        rag_anti_section = ""
        if self.fix_history_rag:
            try:
                anti = self.fix_history_rag.retrieve_anti_examples(
                    errors, language=language, top_k=1, min_similarity=0.35
                )
                if anti:
                    rag_anti_section = self.fix_history_rag.format_anti_examples(anti)
            except Exception as e:
                logger.debug(f"[RAG] Anti-example retrieval failed: {e}")

        # ── Build compiler-specific rules and error patterns for user prompt ──
        if _is_msvc:
            _compiler_rules_block = (
                "8. NEVER use VLAs — use #define constants for array sizes\n"
                "9. NEVER define 'string', 'bool', or any Windows reserved type name"
            )
            _compiler_error_patterns = (
                "COMMON MSVC ERROR PATTERNS AND FIXES:\n"
                "- C2039 \"'X' is not a member of 'Y'\": A struct/context is missing a field. ADD the missing field to the struct definition with the correct type inferred from usage.\n"
                "- C2065 \"'X': undeclared identifier\": A variable or type is not declared. For types (DWORD, HANDLE, etc.) — add the correct #include. For variables — add a declaration at the top of the enclosing block.\n"
                "- C2075 \"initialization requires brace-enclosed initializer list\": In C, arrays cannot be copy-initialized from another array. Change `type arr[] = other;` to `const type *arr = other;`\n"
                "- C2082 \"redefinition of formal parameter\": A local variable has the same name as a function parameter. Remove the redundant local declaration.\n"
                "- C2084 \"function already has a body\": A function is defined twice (e.g. in both .h and .c files). In the header, convert the definition to a forward declaration (remove the body, add `;`).\n"
                "- C2143 \"missing ';'\": Add the missing semicolon at the indicated position.\n"
                "- C2365 \"'X': redefinition; previous definition was 'function'\": A variable or struct field was named after a Win32 API function (e.g. `GetUserNameA`, `HeapAlloc`). Rename the variable to a non-conflicting name (e.g. prefix with `_pf` like `_pfGetUserNameA`).\n"
                "- C2371 \"'X': redefinition; different basic types\": A type is defined twice. If it's an SDK type, remove the user-defined duplicate. If two state-machine context structs have the same name (e.g. both named `_Ctx`), rename the second one to `_Ctx2`.\n"
                "- C2373/C2491 \"redefinition; different type modifiers\": A function redeclares a Win32 API. Remove the conflicting redeclaration but NEVER comment out #define macros.\n"
                "- C2561 \"function must return a value\": Add `return 0;` or appropriate return statement.\n"
                "- C2664 \"cannot convert argument\": Usually a wide/narrow string mismatch. Use the correct function variant (e.g. `strcpy` instead of `wcscpy`).\n"
                "- C2733 \"cannot overload extern 'C' linkage\": A function in the source file conflicts with an SDK declaration. Remove the conflicting definition.\n"
                "- C3861 \"'X': identifier not found\": A Win32 API function needs a specific header (#include <wincrypt.h> for Crypt* functions, etc.).\n"
                "- C2059/C2374/C2373 cascading after '}}': The function above likely closed too early. Move the premature '}}' to the correct end of the function."
            )
        else:
            _compiler_rules_block = (
                "8. VLAs are valid in C99+ but prefer fixed-size arrays or dynamic allocation for portability\n"
                "9. Variables can be declared anywhere in a block (C99+), for-loop initializers are OK"
            )
            _gcc_or_clang = 'Clang' if _eff_compiler == COMPILER_CLANG else 'GCC'
            _compiler_error_patterns = (
                f"COMMON {_gcc_or_clang} ERROR PATTERNS AND FIXES:\n"
                "- \"implicit declaration of function 'X'\": Add the correct #include or a forward declaration before the call site.\n"
                "- \"'X' undeclared (first use in this function)\": Declare or #include the missing type/variable. For Win32 types — add #include <windows.h>.\n"
                "- \"incompatible pointer types\": Add an explicit cast to the target type — do NOT change the pointer type or remove the assignment.\n"
                "- \"redefinition of 'X'\": A type/struct/variable is defined twice. Use #ifndef include guards or remove the duplicate.\n"
                "- \"undefined reference to 'X'\": The function is declared but not defined. Ensure it exists in a compiled source file or add `extern` declaration.\n"
                "- \"multiple definition of 'X'\": A function/variable is defined in multiple TUs. Mark it `static` or `static inline` in the header.\n"
                "- \"expected ';' before ...\": Add the missing semicolon or fix the preceding statement.\n"
                "- \"expected declaration or statement at end of input\": Missing closing brace '}}'. Count and balance all braces.\n"
                "- \"'X' has no member named 'Y'\": A struct is missing a field. ADD the missing field to the struct definition.\n"
                "- \"control reaches end of non-void function\": Add `return 0;` or appropriate return statement.\n"
                "- \"conflicting types for 'X'\": A function is declared with different signatures. Fix the declaration to match the definition."
            )

        # ── Build initial user prompt ──
        initial_user_prompt = f"""The following {language} code has compilation errors:

```{language}
{source_code}
```

COMPILATION ERRORS:
{error_text}
{context_section}
{error_context}
{entry_point_warning}
{vla_warning}
{lnk_warning}
{header_file_warning}
{prev_fail_section}
{rag_few_shot_section}
{rag_anti_section}
YOUR TASK:
1. Fix ALL compilation errors while PRESERVING the original runtime behavior.
2. For missing declarations: add forward declarations with correct types (infer from usage).
3. For missing headers: keep the #include line, add forward declarations for the needed types/functions
   above it so the code compiles even if the header is absent. NEVER comment out or delete #include lines.
4. For syntax errors: fix them completely.
5. SEMANTIC PRESERVATION IS PARAMOUNT — every API call, control flow branch, and data structure
   in the original code must remain intact and reachable in the fixed code.
6. DO NOT redefine functions that are defined in other files
7. NEVER add WinMain/main if the project already has one
{_compiler_rules_block}
10. NEVER remove ANY #include directive
11. NEVER comment out or remove #define macros or typedef lines from the original source code

{_compiler_error_patterns}

CRITICAL OUTPUT FORMAT:
- Return ONLY the complete, compilable source code
- DO NOT add instructions, explanations, or text outside code
- Wrap code in markdown: ```{language}\\n<code>\\n```
"""

        # ── Multi-turn conversation state ──
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": initial_user_prompt},
        ]
        
        fixed_code = source_code
        remaining_errors = errors.copy()
        has_chat = hasattr(self.llm_provider, 'generate_chat')
        
        # Hybrid-specific routing parameters
        hybrid_params = {}
        if self.use_hybrid and hasattr(self.llm_provider, 'choose_provider'):
            hybrid_params = {
                'file_size': len(source_code),
                'error_count': len(errors),
                'is_header': is_header_file,
            }
        
        for attempt in range(max_attempts):
            try:
                logger.info(f"Attempting to fix errors (attempt {attempt + 1}/{max_attempts}, turn {len(messages)//2})...")
                
                # ── Call LLM ──
                if has_chat and attempt > 0:
                    # Multi-turn: send full conversation history
                    response = self.llm_provider.generate_chat(
                        messages=messages,
                        **hybrid_params,
                    )
                else:
                    # First turn or no chat support: use generate()
                    gen_params = {
                        'system_prompt': system_prompt,
                        'user_prompt': messages[-1]["content"],  # latest user message
                    }
                    if not self.use_hybrid or not hasattr(self.llm_provider, 'choose_provider'):
                        try:
                            from llm_api import MistralAPIProvider, DeepSeekProvider as _DeepSeekProvider
                            _needs_hyphen = isinstance(self.llm_provider, (MistralAPIProvider, _DeepSeekProvider))
                        except Exception:
                            _needs_hyphen = False
                        gen_params['model'] = self.llm_model.replace(":", "-") if _needs_hyphen else self.llm_model
                    else:
                        gen_params.update(hybrid_params)
                    response = self.llm_provider.generate(**gen_params)
                
                # Extract code from response
                extracted_code = self._extract_code_from_response(response, language)
                
                if extracted_code:
                    cleaned_code = self._clean_llm_artifacts(extracted_code)
                    
                    # Remove dangerous #define / typedef that break Windows SDK
                    cleaned_code = self._sanitize_dangerous_patterns(cleaned_code)
                    
                    # CRITICAL: Restore any project includes that were removed
                    cleaned_code = self._restore_removed_includes(source_code, cleaned_code)
                    
                    # Validate the generated fix
                    is_valid, validation_error = self.validate_fixed_code(source_code, cleaned_code, language)
                    
                    if not is_valid:
                        logger.warning(f"⚠️  Fix validation failed: {validation_error}")
                        # ── RAG: Store failed fix as anti-example ──
                        if self.fix_history_rag:
                            try:
                                self.fix_history_rag.store_negative_fix(
                                    errors=errors,
                                    original_code=source_code,
                                    failed_code=cleaned_code,
                                    language=language,
                                    failure_reason=validation_error or "validation rejected",
                                )
                            except Exception as e:
                                logger.debug(f"[RAG] Negative store failed: {e}")
                        # Add the failed response + feedback to conversation
                        messages.append({"role": "assistant", "content": response})
                        messages.append({"role": "user", "content": 
                            f"Your fix was rejected: {validation_error}\n"
                            f"Please try again. Return the COMPLETE fixed source code.\n"
                            f"Do NOT truncate or shorten the code. Keep ALL functions.\n"
                            f"Wrap code in: ```{language}\\n<code>\\n```"
                        })
                        logger.info("Feeding validation error back to LLM for next turn...")
                        continue
                    
                    fixed_code = cleaned_code
                    logger.info(f"✓ Generated and validated fix (attempt {attempt + 1})")
                    
                    # ── Track success ──
                    if _normal_track_key in self.fix_tracking:
                        self.fix_tracking[_normal_track_key]['successes'] += 1
                    logger.info(f"[TRACK] Normal fix SUCCESS: {_normal_track_key}")
                    
                    # ── Append assistant response to conversation history ──
                    messages.append({"role": "assistant", "content": response})
                    
                    # ── RAG: Store successful fix for future retrieval ──
                    if self.fix_history_rag:
                        try:
                            self.fix_history_rag.store_fix(
                                errors=errors,
                                original_code=source_code,
                                fixed_code=fixed_code,
                                language=language,
                                metadata={'track_key': _normal_track_key},
                            )
                        except Exception as e:
                            logger.debug(f"[RAG] Failed to store fix: {e}")
                    
                    # Success! Return the fix.
                    return fixed_code, True, []
                else:
                    logger.warning(f"No code extracted from response (attempt {attempt + 1})")
                    # Feed back to LLM
                    messages.append({"role": "assistant", "content": response})
                    messages.append({"role": "user", "content":
                        f"I could not extract code from your response. "
                        f"Please return the COMPLETE fixed {language} source code "
                        f"wrapped in markdown code blocks: ```{language}\\n<code>\\n```"
                    })
                    continue
            
            except LLMAPIError as e:
                logger.error(f"LLM API error: {e}")
                break
            
            except Exception as e:
                logger.error(f"Unexpected error during auto-fix: {e}")
                break
        
        logger.warning("Failed to fix errors after all attempts")
        logger.info(f"[TRACK] Normal fix FAILED: {_normal_track_key}")
        
        # FALLBACK: If normal fix failed and file is large (>30k), try surgical fix
        # The 7B model cannot handle large files in normal mode (outputs stubs),
        # but surgical mode only sends small error regions — 7B can handle those.
        if len(source_code) > 30000:
            logger.info(f"Normal fix failed for large file ({len(source_code)} chars). "
                       f"Falling back to SURGICAL FIX...")
            try:
                surgical_result = self.fix_large_file_surgically(
                    source_code, errors, language,
                    project_context=project_context,
                    file_context=file_context,
                    clang_analysis=clang_analysis,
                    source_file_path=source_file_path,
                )
                if surgical_result[1]:  # fix applied
                    logger.info("[TRACK] Surgical fallback SUCCESS")
                    return surgical_result
                else:
                    logger.warning("Surgical fallback also failed")
            except Exception as e:
                logger.error(f"Surgical fallback error: {e}")
        
        if fixed_code and isinstance(fixed_code, str):
            return fixed_code, False, remaining_errors
        return source_code, False, remaining_errors
    
    def fix_code_issues(
        self,
        source_code: str,
        issues: List[str],
        language: str = "c",
    ) -> Tuple[str, bool]:
        """
        Fix code quality issues (warnings, style, etc.).
        
        Args:
            source_code: Original source code
            issues: List of code issues
            language: Programming language
        
        Returns:
            Tuple of (fixed_code, success)
        """
        if not self.llm_provider:
            return source_code, False
        
        if not issues:
            return source_code, True
        
        issues_text = "\n".join([f"  - {issue}" for issue in issues])
        
        system_prompt = (
            f"You are an expert {language} programmer. "
            "Fix code quality issues while maintaining functionality."
        )
        
        user_prompt = f"""
The following {language} code has quality issues:

```{language}
{source_code}
```

Issues:
{issues_text}

Please fix these issues. Return only the fixed code within code blocks.
"""
        
        try:
            # Prepare params
            gen_params = {
                'system_prompt': system_prompt,
                'user_prompt': user_prompt,
            }
            
            # Only pass model for non-hybrid mode
            if not self.use_hybrid or not hasattr(self.llm_provider, 'choose_provider'):
                try:
                    from llm_api import MistralAPIProvider, DeepSeekProvider as _DeepSeekProvider
                    _needs_hyphen = isinstance(self.llm_provider, (MistralAPIProvider, _DeepSeekProvider))
                except Exception:
                    _needs_hyphen = False
                gen_params['model'] = self.llm_model.replace(":", "-") if _needs_hyphen else self.llm_model
            
            response = self.llm_provider.generate(**gen_params)
            
            fixed_code = self._extract_code_from_response(response, language)
            
            if fixed_code:
                return fixed_code, True
            
            return source_code, False
        
        except Exception as e:
            logger.error(f"Error fixing code issues: {e}")
            return source_code, False
    
    @staticmethod
    def _strip_prose_lines(code: str) -> str:
        """Remove English prose lines interleaved within C/C++ code."""
        _PROSE_LINE = re.compile(
            r"^\s*(However|But\s|Note\s|Let's|Let us|Now,?\s|Since\s|Wait|Remember|"
            r"The\s|This\s|Here\s|We\s|We'll|We've|I\s|So\s|Also|Therefore|"
            r"First|Second|Third|Finally|Actually|Basically|"
            r"How\s|Alternatively|Original\w*|In\s+(state|this|the)\s|Then\s|"
            r"State\s+\d+:|Step\s+\d+:|"
            r"\d+\.\s+[A-Z]|"
            r"-\s+[a-z]+\s+(is|are|was|were|has|have|can|should|would|will)\s)",
            re.IGNORECASE)
        lines = code.split('\n')
        cleaned = []
        for line in lines:
            ls = line.strip()
            if ls and _PROSE_LINE.match(ls) and '{' not in ls and '}' not in ls and ';' not in ls:
                continue
            cleaned.append(line)
        return '\n'.join(cleaned)

    def _extract_code_from_response(self, response: str, language: str) -> Optional[str]:
        """
        Extract code from LLM response.
        
        Args:
            response: LLM response text
            language: Programming language
        
        Returns:
            Extracted code or None
        """
        # Strip reasoning model <think>...</think> blocks
        response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
        if '<think>' in response:
            response = re.sub(r'<think>.*', '', response, flags=re.DOTALL).strip()
        # Try to find code blocks
        patterns = [
            rf'```{language}\s*\n(.*?)```',
            rf'```\s*\n(.*?)```',
            rf'```{language}(.*?)```',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            if matches:
                code = matches[0].strip()
                if code:
                    # For C/C++, strip any prose lines that leaked inside code fences
                    if language not in ('python', 'javascript') and '{' in code and '}' in code:
                        code = self._strip_prose_lines(code)
                    return code
        
        # If no code blocks, try to extract code by stripping prose
        stripped = response.strip()
        if language in ('python', 'javascript'):
            lines = stripped.split('\n')
            if len(lines) > 5:
                code_indicators = ['def ', 'class ', 'import ', 'from '] if language == 'python' else ['function ', '=>', '{', 'const ', 'let ', 'var ']
                if any(indicator in stripped for indicator in code_indicators):
                    return stripped
        else:
            # C/C++: strip leading/trailing prose, keep only code
            if '{' in stripped and '}' in stripped:
                lines = stripped.split('\n')
                _CODE_START = re.compile(
                    r'^\s*('
                    r'(static\s+|const\s+|unsigned\s+|signed\s+|extern\s+|inline\s+|volatile\s+)*'
                    r'(void|int|char|short|long|float|double|BOOL|DWORD|HANDLE|HMODULE|'
                    r'ULONG_PTR|ULONG|LONG|LPSTR|LPCSTR|LPVOID|PVOID|SIZE_T|HRESULT|'
                    r'BYTE|WORD|UINT|LPCTSTR|LPTSTR|TCHAR|WCHAR|SOCKET|HINTERNET|'
                    r'FARPROC|HKEY|LPBYTE|LPDWORD|NTSTATUS|LPWSTR|LPCWSTR|PCHAR|'
                    r'struct\s+\w+|enum\s+\w+|typedef\s+|#define\s+|#include\s+|#if|#pragma)'
                    r')', re.IGNORECASE)
                _PROSE_LINE = re.compile(
                    r'^\s*(However|But\s|Note\s|Let\'s|Since\s|Wait|Remember|'
                    r'The\s|This\s|Here\s|We\s|I\s|So\s|Also|Therefore|'
                    r'First|Second|Third|Finally|Actually|Basically|'
                    r'How\s|Alternatively|Original\w*\s|In\s+(state|this|the)\s|Then\s|'
                    r'Now,?\s|Let us|We\'ll|We\'ve|'
                    r'State\s+\d+:|Step\s+\d+:|'
                    r'\d+\.\s+[A-Z])', re.IGNORECASE)
                # Find code start
                start_idx = None
                for i, line in enumerate(lines):
                    ls = line.strip()
                    if not ls:
                        continue
                    if _CODE_START.match(ls) or ls.startswith('{') or (ls.startswith('//') and i > 0):
                        start_idx = i
                        break
                if start_idx is None:
                    return None
                # Smarter end detection: stop at first run of 3+ consecutive
                # non-code lines instead of scanning to last '}'.
                def _is_code_ish(ln):
                    s = ln.strip()
                    if not s:
                        return False
                    if any(c in s for c in (';', '{', '}')):
                        return True
                    if s.startswith('#') or s.startswith('//') or s.startswith('/*') or s.startswith('*'):
                        return True
                    if _CODE_START.match(s):
                        return True
                    return False
                last_code_idx = start_idx
                noncode_streak = 0
                for i in range(start_idx, len(lines)):
                    if _is_code_ish(lines[i]):
                        last_code_idx = i
                        noncode_streak = 0
                    else:
                        noncode_streak += 1
                    if noncode_streak >= 3:
                        break
                end_idx = last_code_idx
                # Filter prose lines within code
                code_lines = []
                for line in lines[start_idx:end_idx + 1]:
                    ls = line.strip()
                    if ls and _PROSE_LINE.match(ls) and '{' not in ls and '}' not in ls and ';' not in ls:
                        continue
                    code_lines.append(line)
                result = '\n'.join(code_lines).strip()
                if '{' in result and '}' in result:
                    return result
        
        return None
    
    # ── Micro few-shot examples for common compiler error patterns ──
    FEW_SHOT_FIX_EXAMPLES = (
        "\n\nFEW-SHOT EXAMPLES (common fix patterns):\n"
        "─────────────────────────────────────────\n"
        "Example 1 — Unbalanced braces (C2143/C1075):\n"
        "  WRONG: Deleting lines to fix, causing brace mismatch.\n"
        "  RIGHT: Keep all lines, add missing } at the correct scope level.\n"
        "  Before:  void foo() { if(x) { bar();  /* missing } */\n"
        "  After:   void foo() { if(x) { bar(); } }\n\n"
        "Example 2 — Undeclared identifier / missing type (C2065/C2061):\n"
        "  WRONG: Removing the line that uses the identifier.\n"
        "  RIGHT: Add a forward declaration or typedef before usage.\n"
        "  Before:  MY_STRUCT* ptr;  // error: 'MY_STRUCT' undeclared\n"
        "  After:   typedef struct MY_STRUCT MY_STRUCT;  // << added\n"
        "           MY_STRUCT* ptr;  // now compiles\n\n"
        "Example 3 — Removed #include causing cascade (LNK2019/C2065):\n"
        "  WRONG: Removing more code to suppress the cascade errors.\n"
        "  RIGHT: Restore the removed #include <windows.h> at the top.\n\n"
        "Example 4 — Array copy-initialization (C2075: initialization requires brace-enclosed list):\n"
        "  WRONG: const unsigned char arr[] = other_arr;  // C arrays cannot be copy-initialized\n"
        "  RIGHT: const unsigned char *arr = other_arr;   // Use pointer instead\n"
        "  Or if inside a macro that tries `type _e[] = enc;`, change to `const type *_e = enc;`\n\n"
        "Example 5 — Redefinition of formal parameter (C2082):\n"
        "  WRONG: void f(int x) { int x; ... }  // redeclares parameter x\n"
        "  RIGHT: void f(int x) { ... }          // remove the redundant declaration\n\n"
        "Example 6 — Early function close causing file-scope code (cascading C2059/C2143/C2374):\n"
        "  WRONG: void func() { /* code */ }  /* stray } closed function too early */\n"
        "         int a = 1; if(x) { }  // these are now at file scope → many errors\n"
        "  RIGHT: Move the stray } to the correct end of function.\n"
        "  HINT: If you see many C2059/C2374 'redefinition' errors from lines after a },\n"
        "        the function above closed too early. Remove the premature } and close at the end.\n\n"
        "Example 7 — Static local with non-constant initializer (C2099):\n"
        "  WRONG: static FnType pFn = (FnType)GetProcAddress(LoadLibraryA(\"x\"), \"y\");  // C2099: must be constant\n"
        "  RIGHT: FnType pFn = (FnType)GetProcAddress(LoadLibraryA(\"x\"), \"y\");         // remove 'static'\n\n"
        "Example 8 — Local variable shadows Win32 API name (C2063/C2059):\n"
        "  WRONG: char *SHGetFolderPathW = (char*)GetProcAddress(...);  // shadows the real API\n"
        "         SHGetFolderPathW(0, CSIDL, ...);  // C2063: not a function (it's a char* now!)\n"
        "  RIGHT: HRESULT(WINAPI*_pfnSHGet)(HWND,int,HANDLE,DWORD,LPWSTR) = ...; _pfnSHGet(0, CSIDL, ...);\n\n"
        "Example 9 — C++ syntax in .c file (C2065 'static_cast' undeclared / C2059 syntax error '>'):\n"
        "  WRONG: static_cast<MyCtx*>(ctx)->field = 1;  // .c file compiled as C, not C++\n"
        "  RIGHT: ((MyCtx*)ctx)->field = 1;              // use C-style cast\n"
        "  ALSO: Replace nullptr→NULL, bool→BOOL, true→TRUE, false→FALSE, new→malloc, delete→free.\n"
        "─────────────────────────────────────────\n"
    )

    def _build_fallback_system_prompt(self, language: str, compiler_type: str = COMPILER_MSVC) -> str:
        """Fallback system prompt when error analyzer is not available"""
        _is_msvc = compiler_type in (COMPILER_MSVC, COMPILER_AUTO)
        return (
            f"You are an expert {language} programmer. Fix compilation errors while PRESERVING "
            "the original runtime behavior — every API call, branch, and data structure must survive.\n\n"
            "CRITICAL INSTRUCTIONS:\n"
            "1. For missing SYSTEM header files: keep the #include line, add forward declarations\n"
            "   for the types/functions actually used so code compiles without the header.\n"
            "   NEVER comment out or delete ANY #include line.\n"
            "2. NEVER comment out or remove project-specific includes (quoted paths like \"path/header.h\")\n"
            "   - Keep project includes like #include \"chacha20/...\" or #include \"../common.h\" UNCHANGED\n"
            "3. For undefined symbols: Add forward declarations with correct types (infer from usage).\n"
            "   NEVER replace typed pointers with void* or add stub functions that return 0.\n"
            "4. For syntax errors: Fix all syntax issues completely\n"
            "5. For non-standard functions: Replace with standard equivalents\n"
            "   - _halloc() → malloc(), _hfree() → free()\n"
            "   - _strdup() → strdup(), _stricmp() → strcasecmp()\n"
            "6. IMPORTANT: The code MUST compile AND preserve all original behavior.\n\n"
            + self.FEW_SHOT_FIX_EXAMPLES
            + (self._get_msvc_strict_rules() if _is_msvc else self._get_gcc_clang_rules(compiler_type))
            +
            "OUTPUT FORMAT:\n"
            "- Return ONLY complete, compilable source code\n"
            "- NEVER include instructions like 'Add #include' or 'Remove line X'\n"
            "- NEVER add explanations or comments about your fixes\n"
            "- Output raw code ready to compile directly\n"
            "- Wrap in markdown code blocks: ```" + language + "\n<code>\n```"
        )
    
    def _build_fallback_error_context(self, errors: List[str]) -> str:
        """Fallback error context when error analyzer is not available"""
        missing_headers = [e for e in errors if 'no such file' in e.lower() or 'fatal error' in e.lower()]
        syntax_errors = [e for e in errors if 'error:' in e.lower() and 'no such file' not in e.lower()]
        
        context = ""
        if missing_headers:
            context += "\n⚠️ MISSING HEADERS DETECTED:\n"
            for err in missing_headers[:5]:
                context += f"    - {err}\n"
            context += "\n  ACTION: Keep #include lines, add forward declarations for types/functions used so code compiles without the header.\n"
            context += "  CRITICAL: NEVER remove or comment out ANY #include line.\n\n"
        
        if syntax_errors:
            context += "\n⚠️ SYNTAX ERRORS DETECTED:\n"
            for err in syntax_errors[:5]:
                context += f"    - {err}\n"
            context += "\n  ACTION: Fix all syntax issues completely.\n\n"
        
        return context
    
    def _build_system_prompt(self, language: str, strategy: dict) -> str:
        """Build system prompt based on error analysis strategy"""
        prompt = (
            f"You are an expert {language} programmer. Fix compilation errors while "
            "PRESERVING the original runtime behavior — every API call, branch, and "
            "data structure must survive in the fixed code.\n\n"
            "CRITICAL INSTRUCTIONS:\n"
        )
        
        if strategy.get('has_missing_headers'):
            prompt += (
                "1. For missing SYSTEM header files (e.g., 'No such file or directory', 'fatal error'):\n"
                "   - KEEP the #include line (do NOT comment it out or remove it).\n"
                "   - Add forward declarations for types and functions actually used from that header.\n"
                "   - This lets the code compile without the header while preserving intent.\n"
                "   - Example: If 'dokani.h' is missing and code uses DokanInit():\n"
                "     typedef void* DOKAN_HANDLE; // forward-declare types from dokani.h\n"
                "     int DokanInit(void);        // forward-declare used functions\n\n"
                "   CRITICAL: NEVER comment out or remove ANY #include directive.\n\n"
            )
        
        if strategy.get('has_undefined_symbols'):
            prompt += (
                "2. For undefined symbols (functions, variables, types):\n"
                "   - Add forward declarations at the top of the file\n"
                "   - For functions: Add a forward declaration with the correct signature\n"
                "     (infer params from call sites). Do NOT add stub bodies that return 0 — just declare.\n"
                "   - For types: Add 'typedef struct NAME NAME;' or a minimal struct definition\n"
                "     with the fields actually used in the code. NEVER replace a typed pointer with void*.\n"
                "   - For variables: Add 'extern TYPE NAME;' declarations — NEVER delete usage code.\n\n"
            )
        
        if strategy.get('has_syntax_errors'):
            prompt += (
                "3. For syntax errors:\n"
                "   - Fix all syntax issues completely (missing semicolons, brackets, etc.)\n"
                "   - Ensure all brackets, parentheses, and semicolons are correct\n"
                "   - Check for typos in keywords and identifiers\n\n"
            )
        
        if strategy.get('has_type_mismatches'):
            prompt += (
                "4. For type mismatches:\n"
                "   - Add explicit type casts where needed\n"
                "   - Fix function signatures to match declarations\n"
                "   - Ensure return types match function definitions\n\n"
            )

        if strategy.get('has_linking_errors'):
            linker_syms = strategy.get('linker_symbols', [])
            prompt += (
                "5. For LINKER errors (LNK2019/LNK2001 unresolved externals):\n"
                "   - ROOT CAUSE: a critical #include was removed, OR a #pragma comment(lib,...) is missing.\n"
                "   - Restore the missing #include at the top (e.g. <windows.h>, <winsock2.h>).\n"
                "   - NEVER remove #include <windows.h> — it provides hundreds of Win32 API declarations.\n"
            )
            if linker_syms:
                prompt += f"   Unresolved symbols: {', '.join(linker_syms[:10])}\n"
            prompt += "\n"

        if strategy.get('has_redefinitions'):
            prompt += (
                "6. For redefinition errors (C2011/C2086/C2370/C2371):\n"
                "   - Do NOT add a second definition of the same struct/type/variable.\n"
                "   - Use #ifndef include guards or check if the type already exists.\n"
                "   - If the redefinition is in YOUR code, remove the duplicate — keep the first.\n\n"
            )

        if strategy.get('has_environment_issues'):
            prompt += (
                "⚠️ ENVIRONMENT ISSUE DETECTED: Some SDK headers (windows.h, etc.) are reported missing.\n"
                "   This is an SDK/toolchain setup problem, NOT a code bug.\n"
                "   Do NOT remove or comment out these #includes — they are correct.\n"
                "   Focus only on fixing actual CODE errors.\n\n"
            )
        
        prompt += (
            "5. IMPORTANT: The code MUST compile AND preserve the original runtime behavior.\n"
            "   - NEVER comment out, delete, or stub-out code that performs real work (API calls,\n"
            "     network I/O, file I/O, process manipulation, registry access, crypto ops).\n"
            "   - ONLY add declarations, typedefs, casts, or missing headers to resolve errors.\n"
            "   - If a symbol is undeclared, add its declaration — do NOT remove the code that uses it.\n"
            "   - If a type is unknown, add a typedef or forward-declare the struct — do NOT replace with void*.\n"
            "   - Return ONLY the complete fixed code, nothing else.\n"
        )

        prompt += self.FEW_SHOT_FIX_EXAMPLES

        # Compiler-specific forbidden patterns
        _strategy_compiler = strategy.get('compiler_type', self.compiler_type)
        _is_msvc = _strategy_compiler in (COMPILER_MSVC, COMPILER_AUTO)
        if language.lower() in ('c', 'cpp', 'c++'):
            if _is_msvc:
                prompt += self._get_msvc_strict_rules()
            else:
                prompt += self._get_gcc_clang_rules(_strategy_compiler)

        return prompt

    # ── Compiler-specific rule blocks for system prompts ──

    @staticmethod
    def _get_msvc_strict_rules() -> str:
        """Return MSVC/Windows-specific forbidden patterns for fix prompts."""
        return (
            "\n🚫 MSVC/WINDOWS STRICT RULES (violation causes 100+ cascade errors in Windows SDK headers):\n"
            "- NEVER use Variable-Length Arrays (VLAs): char buf[n] where n is a runtime variable.\n"
            "  MSVC C does NOT support C99 VLAs. To fix: add '#define IDENTIFIER 256' at top of file\n"
            "  and use the constant: char buf[IDENTIFIER]; — use #ifndef guard to avoid redef.\n"
            "- NEVER define, typedef, or #define an identifier named 'string'.\n"
            "  'string' is used as a SAL annotation keyword in Windows SDK winnt.h — redefining it\n"
            "  causes 100+ errors like \"missing ':' before 'string'\" across ALL Windows headers.\n"
            "  Use 'char*', 'LPSTR', or 'LPCSTR' instead.\n"
            "- NEVER #define or typedef: bool (use BOOL/int), byte, CHAR, DWORD, HANDLE, UINT,\n"
            "  LONG, LPSTR, LPCSTR, LPVOID, WORD, TRUE, FALSE — already defined in windows.h.\n"
            "- NEVER add C++ headers in .c files: <string>, <vector>, <iostream>, <map>, etc.\n"
            "- NEVER use 'using namespace std;' in C code.\n"
            "- Declare ALL variables at the TOP of a block before any statements (MSVC C89 compat).\n"
            "- For 'C2065: undeclared identifier' used as array size (C2057/C2466/C2133):\n"
            "  Add at the TOP of the file: #ifndef IDENTIFIER\n  #define IDENTIFIER 256\n  #endif\n"
            "  Then keep: char buf[IDENTIFIER]; — do NOT change to dynamic allocation.\n"
        )

    @staticmethod
    def _get_gcc_clang_rules(compiler_type: str = COMPILER_GCC) -> str:
        """Return GCC/Clang-specific rules for fix prompts."""
        compiler_name = 'Clang' if compiler_type == COMPILER_CLANG else 'GCC'
        return (
            f"\n🔧 {compiler_name} COMPILER RULES:\n"
            "- Variable-Length Arrays (VLAs) ARE supported in C99/C11 mode but should be avoided\n"
            "  for portability. Prefer fixed-size arrays or dynamic allocation.\n"
            "- Variables CAN be declared anywhere in a block (C99+), not just at the top.\n"
            "- For-loop initializers like `for(int i=0; ...)` are valid in C99+ mode.\n"
            "- 'implicit declaration of function' warnings: add the correct #include or a\n"
            "  forward declaration before the call site — do NOT remove the call.\n"
            "- 'incompatible pointer types' warnings: add an explicit cast — do NOT change\n"
            "  the pointer type or remove the assignment.\n"
            "- 'undefined reference to' linker errors: ensure the function is defined in EXACTLY\n"
            "  one translation unit and the source file is compiled, OR add `extern` declarations.\n"
            "- 'multiple definition of' errors: if a function/variable is defined in a header,\n"
            "  mark it `static` or `static inline` to avoid duplicate symbols across TUs.\n"
            "- 'redefinition of struct/type' errors: use `#ifndef` include guards or `#pragma once`.\n"
            "- NEVER add C++ headers (<string>, <vector>, <iostream>) in .c files.\n"
            "- Use C-style casts, NULL (not nullptr), and standard C types in .c files.\n"
        )

    def _build_error_context(self, error_infos: List, strategy: dict) -> str:
        """Build detailed error context for LLM"""
        context = ""

        if strategy.get('has_environment_issues'):
            context += (
                "\n🔧 ENVIRONMENT ISSUE — the following are SDK/toolchain problems, NOT code bugs:\n"
                "  Do NOT modify code to work around these. They will resolve when the SDK is configured.\n\n"
            )
        
        if strategy.get('has_missing_headers'):
            context += "\n⚠️ MISSING HEADERS DETECTED:\n"
            missing_headers = strategy.get('missing_headers', [])
            if missing_headers:
                context += "  Headers to fix:\n"
                for header in missing_headers[:10]:  # Limit to first 10
                    context += f"    - {header}\n"
            else:
                # Fallback to showing error messages
                header_errors = [e.error_text for e in error_infos if e.error_type == ErrorType.MISSING_HEADER]
                for err in header_errors[:5]:
                    context += f"    - {err}\n"
            context += "\n  ACTION: Keep #include lines, add forward declarations for types/functions used so code compiles without the header.\n"
            context += "  CRITICAL: NEVER remove or comment out ANY #include line.\n\n"
        
        if strategy.get('has_undefined_symbols'):
            context += "\n⚠️ UNDEFINED SYMBOLS DETECTED:\n"
            undefined_symbols = strategy.get('undefined_symbols', [])
            if undefined_symbols:
                context += "  Symbols to fix:\n"
                for symbol in undefined_symbols[:10]:  # Limit to first 10
                    context += f"    - {symbol}\n"
            else:
                symbol_errors = [e.error_text for e in error_infos if e.error_type == ErrorType.UNDEFINED_SYMBOL]
                for err in symbol_errors[:5]:
                    context += f"    - {err}\n"
            context += "\n  ACTION: Add forward declarations or stub implementations.\n\n"
        
        if strategy.get('has_syntax_errors'):
            context += "\n⚠️ SYNTAX ERRORS DETECTED:\n"
            syntax_errors = [e.error_text for e in error_infos if e.error_type == ErrorType.SYNTAX_ERROR]
            for err in syntax_errors[:5]:
                context += f"    - {err}\n"
            context += "\n  ACTION: Fix all syntax issues completely.\n\n"
        
        # Show error type summary
        if strategy.get('error_types'):
            context += "\n📊 ERROR SUMMARY:\n"
            for error_type, count in strategy['error_types'].items():
                context += f"  - {error_type}: {count} error(s)\n"
            context += "\n"
        
        return context


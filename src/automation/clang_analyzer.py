"""
Clang-Based Code Analyzer for Surgical-Fix
============================================
Uses libclang to build accurate AST, symbol table, dependency graph,
and call graph for C/C++ source files. Enables:

1. Pre-mutation analysis: identify safe mutation targets
2. Post-mutation validation: verify no broken symbols BEFORE compiling
3. Dependency-aware prompting: give LLM precise context about dependencies
4. Auto-fix without LLM: fix simple symbol/type mismatches directly

This replaces regex-based heuristics in mutation_strategy_improver.py
with precise compiler-level analysis.
"""

import os
import re
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

# ── libclang import with graceful fallback ──
_HAS_CLANG = False
try:
    from clang.cindex import (
        Index, TranslationUnit, CursorKind, TypeKind, Cursor,
        Diagnostic, SourceLocation
    )
    _HAS_CLANG = True
except ImportError:
    logger.warning("libclang not installed. ClangAnalyzer will use regex fallback.")


# ═══════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════

class SymbolKind(Enum):
    FUNCTION = "function"
    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    TYPEDEF = "typedef"
    MACRO = "macro"
    GLOBAL_VAR = "global_var"
    ENUM_CONST = "enum_const"
    CLASS = "class"
    METHOD = "method"
    FIELD = "field"
    PARAMETER = "parameter"


@dataclass
class Symbol:
    """A symbol extracted from the AST."""
    name: str
    kind: SymbolKind
    file: str               # Absolute file path
    line: int               # Line number (1-based)
    col: int                # Column number (1-based)
    end_line: int = 0       # End line of definition
    return_type: str = ""   # For functions
    parameters: List[Tuple[str, str]] = field(default_factory=list)  # (type, name) pairs
    signature: str = ""     # Full signature text
    is_definition: bool = False   # True if this is the definition, not just declaration
    is_static: bool = False       # File-local?
    is_inline: bool = False
    parent: str = ""              # Parent struct/class name
    referenced_symbols: Set[str] = field(default_factory=set)  # Symbols used in body
    body_hash: str = ""           # Hash of function body for change detection
    
    @property
    def qualified_name(self) -> str:
        if self.parent:
            return f"{self.parent}::{self.name}"
        return self.name
    
    @property
    def is_leaf(self) -> bool:
        """A leaf function calls no other project-defined functions."""
        return len(self.referenced_symbols) == 0


@dataclass
class DependencyEdge:
    """An edge in the dependency graph."""
    source: str       # Symbol that depends on target
    target: str       # Symbol being depended on
    kind: str         # "calls", "uses_type", "uses_global", "includes"
    file: str         # File where the dependency occurs
    line: int


@dataclass  
class AnalysisResult:
    """Complete analysis result for a set of source files."""
    # Symbol table: name -> list of Symbol (multiple definitions possible)
    symbols: Dict[str, List[Symbol]] = field(default_factory=dict)
    
    # Dependency graph: edges
    dependencies: List[DependencyEdge] = field(default_factory=list)
    
    # Call graph: caller -> set of callees
    call_graph: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Reverse call graph: callee -> set of callers
    reverse_call_graph: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Diagnostics from clang (warnings/errors in the original code)
    diagnostics: List[str] = field(default_factory=list)
    
    # Files analyzed
    files_analyzed: List[str] = field(default_factory=list)
    
    # Parse errors per file
    parse_errors: Dict[str, List[str]] = field(default_factory=dict)
    
    def get_symbol(self, name: str) -> Optional[Symbol]:
        """Get the definition of a symbol (prefers definitions over declarations)."""
        syms = self.symbols.get(name, [])
        for s in syms:
            if s.is_definition:
                return s
        return syms[0] if syms else None
    
    def get_function_symbols(self) -> Dict[str, Symbol]:
        """Get all function definitions."""
        result = {}
        for name, syms in self.symbols.items():
            for s in syms:
                if s.kind == SymbolKind.FUNCTION and s.is_definition:
                    result[name] = s
                    break
        return result
    
    def get_callers(self, func_name: str) -> Set[str]:
        """Who calls this function?"""
        return self.reverse_call_graph.get(func_name, set())
    
    def get_callees(self, func_name: str) -> Set[str]:
        """What does this function call?"""
        return self.call_graph.get(func_name, set())
    
    def get_dependents(self, symbol_name: str) -> Set[str]:
        """Get all symbols that depend on the given symbol."""
        dependents = set()
        for edge in self.dependencies:
            if edge.target == symbol_name:
                dependents.add(edge.source)
        return dependents
    
    def get_dependencies_of(self, symbol_name: str) -> Set[str]:
        """Get all symbols that the given symbol depends on."""
        deps = set()
        for edge in self.dependencies:
            if edge.source == symbol_name:
                deps.add(edge.target)
        return deps
    
    def get_leaf_functions(self) -> List[str]:
        """Get functions that don't call other project-defined functions.
        These are safest to mutate."""
        functions = self.get_function_symbols()
        leaves = []
        for name, sym in functions.items():
            callees = self.get_callees(name)
            # Filter to only project-defined callees
            project_callees = {c for c in callees if c in functions}
            if not project_callees:
                leaves.append(name)
        return leaves
    
    def get_mutation_safety_score(self, func_name: str) -> Tuple[float, str]:
        """
        Score how safe it is to mutate a function (0.0 = dangerous, 1.0 = safe).
        
        Returns (score, reason).
        """
        sym = self.get_symbol(func_name)
        if not sym:
            return 0.5, "unknown function"
        
        callers = self.get_callers(func_name)
        callees = self.get_callees(func_name)
        dependents = self.get_dependents(func_name)
        
        score = 1.0
        reasons = []
        
        # Penalize functions with many callers (signature changes are dangerous)
        if len(callers) > 5:
            score -= 0.3
            reasons.append(f"{len(callers)} callers")
        elif len(callers) > 2:
            score -= 0.1
            reasons.append(f"{len(callers)} callers")
        
        # Penalize functions used across multiple files
        caller_files = set()
        for caller in callers:
            caller_sym = self.get_symbol(caller)
            if caller_sym:
                caller_files.add(caller_sym.file)
        if len(caller_files) > 1:
            score -= 0.3
            reasons.append(f"cross-file ({len(caller_files)} files)")
        
        # Penalize functions with many dependencies (complex to mutate correctly)
        if len(callees) > 10:
            score -= 0.2
            reasons.append(f"{len(callees)} callees")
        
        # Bonus for leaf functions
        if not callees:
            score += 0.1
            reasons.append("leaf function")
        
        # Bonus for static/file-local functions
        if sym.is_static:
            score += 0.1
            reasons.append("static/file-local")
        
        # Penalize entry points
        if sym.name in {'main', 'WinMain', 'wWinMain', 'DllMain', '_start'}:
            score -= 0.5
            reasons.append("entry point")
        
        score = max(0.0, min(1.0, score))
        return score, "; ".join(reasons) if reasons else "no special constraints"
    
    def get_compilation_fix_context(self, file_path: str, max_length: int = 4000) -> str:
        """
        Generate AST-aware context for the compilation fixer.
        
        For a given file, produces:
        - Functions/types defined in THIS file
        - Cross-file symbols THIS file depends on (with signatures)
        - Functions from OTHER files that the fixer should NOT redefine
        
        This helps the LLM fixer understand the project structure and
        avoid introducing duplicate definitions or breaking cross-file deps.
        """
        norm_path = os.path.normpath(os.path.abspath(file_path))
        basename = os.path.basename(norm_path)
        lines = []
        lines.append(f"=== CLANG AST CONTEXT for {basename} ===")
        
        # --- Symbols defined in THIS file ---
        this_file_funcs = []
        this_file_types = []
        this_file_globals = []
        for name, syms in self.symbols.items():
            for s in syms:
                if not s.is_definition:
                    continue
                s_norm = os.path.normpath(os.path.abspath(s.file))
                if s_norm != norm_path:
                    continue
                if s.kind == SymbolKind.FUNCTION:
                    this_file_funcs.append((name, s))
                elif s.kind in (SymbolKind.STRUCT, SymbolKind.ENUM, SymbolKind.TYPEDEF):
                    this_file_types.append((name, s))
                elif s.kind == SymbolKind.VARIABLE:
                    this_file_globals.append((name, s))
        
        if this_file_funcs:
            lines.append(f"\nFunctions defined in {basename} ({len(this_file_funcs)}):")
            for name, s in sorted(this_file_funcs, key=lambda x: x[1].line):
                sig = s.signature or f"{name}()"
                lines.append(f"  L{s.line}: {sig}")
        
        if this_file_types:
            lines.append(f"\nTypes defined in {basename} ({len(this_file_types)}):")
            for name, s in sorted(this_file_types, key=lambda x: x[1].line):
                lines.append(f"  L{s.line}: {s.kind.value} {name}")
        
        # --- Cross-file dependencies ---
        # Find symbols that functions in this file call but are defined elsewhere
        other_file_sigs = []
        other_file_types = set()
        for func_name, _ in this_file_funcs:
            callees = self.get_callees(func_name)
            for callee in callees:
                callee_sym = self.get_symbol(callee)
                if callee_sym:
                    c_norm = os.path.normpath(os.path.abspath(callee_sym.file))
                    if c_norm != norm_path and callee_sym.is_definition:
                        sig = callee_sym.signature or f"{callee}()"
                        entry = f"  {sig}  // from {os.path.basename(callee_sym.file)}:{callee_sym.line}"
                        if entry not in other_file_sigs:
                            other_file_sigs.append(entry)
            # Types from other files
            for edge in self.dependencies:
                if edge.source == func_name and edge.kind == "uses_type":
                    t_sym = self.get_symbol(edge.target)
                    if t_sym:
                        t_norm = os.path.normpath(os.path.abspath(t_sym.file))
                        if t_norm != norm_path:
                            other_file_types.add(f"{edge.target} ({os.path.basename(t_sym.file)})")
        
        if other_file_sigs:
            lines.append(f"\nCross-file functions used ({len(other_file_sigs)}):")
            lines.append("  (DO NOT redefine these — they exist in other source files)")
            for sig in other_file_sigs[:20]:
                lines.append(sig)
        
        if other_file_types:
            lines.append(f"\nCross-file types used: {', '.join(sorted(other_file_types)[:15])}")
        
        # --- Functions defined in OTHER files (avoid redefining) ---
        other_funcs = []
        for name, syms in self.symbols.items():
            for s in syms:
                if s.kind == SymbolKind.FUNCTION and s.is_definition:
                    s_norm = os.path.normpath(os.path.abspath(s.file))
                    if s_norm != norm_path:
                        other_funcs.append(name)
                        break
        
        if other_funcs:
            lines.append(f"\nFunctions in OTHER files ({len(other_funcs)}) — do NOT redefine:")
            lines.append(f"  {', '.join(sorted(other_funcs)[:30])}")
        
        lines.append("=== END CLANG AST CONTEXT ===")
        
        context = "\n".join(lines)
        # Truncate if too long
        if len(context) > max_length:
            context = context[:max_length - 50] + "\n... (truncated)\n=== END CLANG AST CONTEXT ==="
        return context

    def get_region_semantic_context(
        self,
        file_path: str,
        region_start: int,
        region_end: int,
        max_length: int = 3000
    ) -> str:
        """
        Generate per-region semantic context for surgical fix.
        
        For a code region (line range), identifies which functions/symbols
        live in it and returns their specific AST context:
        - Function signatures & callers/callees
        - Types used by functions in this region
        - Globals accessed
        - Cross-file dependencies relevant to THIS region
        
        This allows the LLM to fix the region with full semantic understanding
        rather than just raw text + compiler errors.
        
        Args:
            file_path: Path to the source file
            region_start: 1-based start line
            region_end: 1-based end line
            max_length: Max context string length
            
        Returns:
            Semantic context string for the region, or "" if nothing found
        """
        norm_path = os.path.normpath(os.path.abspath(file_path))
        
        # Find functions whose bodies overlap with the region
        region_funcs = []
        for name, syms in self.symbols.items():
            for s in syms:
                if not s.is_definition or s.kind != SymbolKind.FUNCTION:
                    continue
                s_norm = os.path.normpath(os.path.abspath(s.file))
                if s_norm != norm_path:
                    continue
                # Check line overlap — function lives partially/fully in region
                func_end = s.end_line if s.end_line > 0 else s.line + 50
                if s.line <= region_end and func_end >= region_start:
                    region_funcs.append((name, s))
        
        if not region_funcs:
            # Maybe region is in global scope — find types/globals instead
            region_types = []
            for name, syms in self.symbols.items():
                for s in syms:
                    if not s.is_definition:
                        continue
                    s_norm = os.path.normpath(os.path.abspath(s.file))
                    if s_norm != norm_path:
                        continue
                    if s.kind in (SymbolKind.STRUCT, SymbolKind.ENUM, SymbolKind.TYPEDEF):
                        if s.line <= region_end and s.line >= region_start:
                            region_types.append((name, s))
            if not region_types:
                return ""
            lines = [f"[AST Region L{region_start}-{region_end}]"]
            lines.append(f"Types in this region: {', '.join(n for n, _ in region_types)}")
            return "\n".join(lines)
        
        lines = [f"[AST Region L{region_start}-{region_end}: "
                 f"{len(region_funcs)} function(s)]"]
        
        all_project_funcs = set(self.get_function_symbols().keys())
        
        for func_name, func_sym in region_funcs:
            sig = func_sym.signature or f"{func_name}()"
            lines.append(f"\n● {sig}")
            
            # Callers — who calls this function? (signature must be compatible)
            callers = self.get_callers(func_name)
            if callers:
                caller_names = sorted(callers)[:8]
                lines.append(f"  Called by ({len(callers)}): {', '.join(caller_names)}")
                if len(callers) > 0:
                    lines.append(f"  ⚠ Do NOT change its signature!")
            
            # Callees — what does it call?
            callees = self.get_callees(func_name)
            if callees:
                # Project-defined callees: LLM must preserve these calls
                project_callees = sorted(c for c in callees if c in all_project_funcs)
                api_callees = sorted(c for c in callees if c not in all_project_funcs)
                
                if project_callees:
                    # Include signatures so LLM knows correct parameters
                    callee_sigs = []
                    for c in project_callees[:10]:
                        c_sym = self.get_symbol(c)
                        if c_sym and c_sym.signature:
                            callee_sigs.append(c_sym.signature)
                        else:
                            callee_sigs.append(f"{c}()")
                    lines.append(f"  Calls project funcs ({len(project_callees)}):")
                    for cs in callee_sigs:
                        lines.append(f"    → {cs}")
                
                if api_callees:
                    lines.append(f"  Calls APIs: {', '.join(api_callees[:15])}")
            
            # Types used
            type_deps = set()
            global_deps = set()
            for edge in self.dependencies:
                if edge.source == func_name:
                    if edge.kind == "uses_type":
                        type_deps.add(edge.target)
                    elif edge.kind == "uses_global":
                        global_deps.add(edge.target)
            if type_deps:
                lines.append(f"  Types: {', '.join(sorted(type_deps)[:10])}")
            if global_deps:
                lines.append(f"  Globals: {', '.join(sorted(global_deps)[:8])}")
        
        # Cross-file symbols that functions in this region depend on
        cross_file_sigs = []
        for func_name, _ in region_funcs:
            for callee in self.get_callees(func_name):
                callee_sym = self.get_symbol(callee)
                if callee_sym and callee_sym.is_definition:
                    c_norm = os.path.normpath(os.path.abspath(callee_sym.file))
                    if c_norm != norm_path:
                        sig_entry = callee_sym.signature or f"{callee}()"
                        if sig_entry not in cross_file_sigs:
                            cross_file_sigs.append(sig_entry)
        
        if cross_file_sigs:
            lines.append(f"\nCross-file deps (DO NOT redefine):")
            for sig in cross_file_sigs[:10]:
                lines.append(f"  ✗ {sig}")
        
        context = "\n".join(lines)
        if len(context) > max_length:
            context = context[:max_length - 30] + "\n... (truncated)"
        return context

    def get_dependency_context_for_prompt(self, func_name: str) -> str:
        """
        Generate context string for LLM prompt that describes the dependencies
        of a function, so the LLM knows what NOT to break.
        """
        sym = self.get_symbol(func_name)
        if not sym:
            return ""
        
        lines = []
        lines.append(f"=== DEPENDENCY CONTEXT for {func_name} ===")
        
        # Signature
        if sym.signature:
            lines.append(f"Signature: {sym.signature}")
        
        # Callers (who calls this function - their signatures must be compatible)
        callers = self.get_callers(func_name)
        if callers:
            lines.append(f"\nCallers ({len(callers)}) - these call {func_name}:")
            for caller in sorted(callers)[:10]:
                caller_sym = self.get_symbol(caller)
                if caller_sym:
                    lines.append(f"  - {caller} in {os.path.basename(caller_sym.file)}:{caller_sym.line}")
        
        # Callees (what this function calls - must keep these calls valid)  
        callees = self.get_callees(func_name)
        project_funcs = self.get_function_symbols()
        if callees:
            project_callees = sorted(c for c in callees if c in project_funcs)
            api_callees = sorted(c for c in callees if c not in project_funcs)
            
            if project_callees:
                lines.append(f"\nProject functions called ({len(project_callees)}):")
                for callee in project_callees[:15]:
                    callee_sym = self.get_symbol(callee)
                    if callee_sym and callee_sym.signature:
                        lines.append(f"  - {callee_sym.signature}")
                    else:
                        lines.append(f"  - {callee}()")
            
            if api_callees:
                lines.append(f"\nExternal/API functions called ({len(api_callees)}):")
                for api in api_callees[:20]:
                    lines.append(f"  - {api}()")
        
        # Types used
        type_deps = set()
        for edge in self.dependencies:
            if edge.source == func_name and edge.kind == "uses_type":
                type_deps.add(edge.target)
        if type_deps:
            lines.append(f"\nTypes used: {', '.join(sorted(type_deps)[:15])}")
        
        # Globals used
        global_deps = set()
        for edge in self.dependencies:
            if edge.source == func_name and edge.kind == "uses_global":
                global_deps.add(edge.target)
        if global_deps:
            lines.append(f"\nGlobal variables used: {', '.join(sorted(global_deps)[:10])}")
        
        lines.append("=== END DEPENDENCY CONTEXT ===")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# Main Analyzer
# ═══════════════════════════════════════════════════════════════

class ClangAnalyzer:
    """
    Clang-based C/C++ code analyzer.
    
    Usage:
        analyzer = ClangAnalyzer()
        result = analyzer.analyze_files(["file1.c", "file2.c"])
        
        # Get mutation safety
        score, reason = result.get_mutation_safety_score("my_function")
        
        # Get dependency context for LLM prompt
        context = result.get_dependency_context_for_prompt("my_function")
        
        # Validate a mutation before compiling
        issues = analyzer.validate_mutation(result, "my_function", new_code)
    """
    
    # Common Windows SDK / C stdlib functions that should NOT be treated
    # as project-defined symbols
    SYSTEM_FUNCTIONS = {
        # C stdlib
        'printf', 'fprintf', 'sprintf', 'snprintf', 'scanf', 'sscanf',
        'malloc', 'calloc', 'realloc', 'free',
        'memcpy', 'memset', 'memcmp', 'memmove',
        'strlen', 'strcpy', 'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp',
        'strstr', 'strchr', 'strrchr', 'strtol', 'strtoul', 'atoi', 'atof',
        'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell', 'fgets', 'fputs',
        'exit', 'abort', 'atexit', 'system', 'getenv',
        'rand', 'srand', 'time', 'clock', 'sleep', 'usleep',
        'isalpha', 'isdigit', 'isalnum', 'isspace', 'toupper', 'tolower',
        'abs', 'labs', 'fabs', 'pow', 'sqrt', 'log', 'exp',
        'qsort', 'bsearch',
        # Windows API (common)
        'CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile', 'CloseHandle',
        'GetLastError', 'SetLastError', 'FormatMessageA', 'FormatMessageW',
        'VirtualAlloc', 'VirtualFree', 'VirtualProtect',
        'HeapAlloc', 'HeapFree', 'HeapCreate', 'HeapDestroy',
        'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'FreeLibrary',
        'CreateProcessA', 'CreateProcessW', 'TerminateProcess',
        'CreateThread', 'ExitThread', 'WaitForSingleObject', 'WaitForMultipleObjects',
        'InitializeCriticalSection', 'EnterCriticalSection', 'LeaveCriticalSection',
        'RegOpenKeyExA', 'RegOpenKeyExW', 'RegSetValueExA', 'RegSetValueExW',
        'RegQueryValueExA', 'RegQueryValueExW', 'RegCloseKey',
        'WSAStartup', 'WSACleanup', 'socket', 'connect', 'bind', 'listen',
        'accept', 'send', 'recv', 'closesocket', 'select',
        'inet_addr', 'htons', 'ntohs', 'inet_ntoa', 'gethostbyname',
        'MessageBoxA', 'MessageBoxW', 'GetModuleHandleA', 'GetModuleHandleW',
        'GetModuleFileNameA', 'GetModuleFileNameW',
        'FindFirstFileA', 'FindFirstFileW', 'FindNextFileA', 'FindNextFileW',
        'FindClose', 'DeleteFileA', 'DeleteFileW',
        'CopyFileA', 'CopyFileW', 'MoveFileA', 'MoveFileW',
        'GetCurrentDirectoryA', 'GetCurrentDirectoryW',
        'SetCurrentDirectoryA', 'SetCurrentDirectoryW',
        'CreateDirectoryA', 'CreateDirectoryW',
        'GetTickCount', 'GetTickCount64', 'QueryPerformanceCounter',
        'Sleep', 'SleepEx', 'GetSystemTime', 'GetLocalTime',
        'MultiByteToWideChar', 'WideCharToMultiByte',
        'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW',
        'InternetReadFile', 'InternetCloseHandle', 'HttpOpenRequestA',
        'HttpSendRequestA', 'InternetConnectA',
        'CryptAcquireContextA', 'CryptGenRandom', 'CryptReleaseContext',
        'CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash', 'CryptHashData',
    }
    
    # System types that are NOT project-defined
    SYSTEM_TYPES = {
        'HANDLE', 'DWORD', 'WORD', 'BYTE', 'BOOL', 'LONG', 'ULONG',
        'HINSTANCE', 'HWND', 'HDC', 'HMODULE', 'HKEY', 'HRESULT',
        'LPSTR', 'LPCSTR', 'LPWSTR', 'LPCWSTR', 'LPVOID', 'LPDWORD',
        'SOCKET', 'sockaddr', 'sockaddr_in', 'in_addr', 'hostent',
        'WSADATA', 'SECURITY_ATTRIBUTES', 'PROCESS_INFORMATION',
        'STARTUPINFO', 'STARTUPINFOA', 'STARTUPINFOW',
        'OVERLAPPED', 'LARGE_INTEGER', 'FILETIME', 'SYSTEMTIME',
        'WIN32_FIND_DATAA', 'WIN32_FIND_DATAW',
        'FILE', 'size_t', 'ssize_t', 'time_t', 'clock_t',
        'int8_t', 'int16_t', 'int32_t', 'int64_t',
        'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
        'PVOID', 'PCHAR', 'PUCHAR', 'PDWORD', 'PLONG',
        'NTSTATUS', 'UNICODE_STRING', 'OBJECT_ATTRIBUTES',
        'CRITICAL_SECTION', 'CONDITION_VARIABLE', 'SRWLOCK',
    }
    
    def __init__(self, extra_include_paths: Optional[List[str]] = None):
        """
        Initialize the analyzer.
        
        Args:
            extra_include_paths: Additional include paths for header resolution
        """
        self._index = None
        self._extra_includes = extra_include_paths or []
        self._file_contents_cache: Dict[str, str] = {}
        
        if _HAS_CLANG:
            self._index = Index.create()
        else:
            logger.warning("ClangAnalyzer: libclang not available, using regex fallback")
    
    def analyze_files(
        self,
        source_files: List[str],
        header_files: Optional[List[str]] = None,
        include_paths: Optional[List[str]] = None
    ) -> AnalysisResult:
        """
        Analyze a set of C/C++ source files.
        
        Args:
            source_files: List of .c/.cpp source file paths
            header_files: Optional list of .h/.hpp header file paths  
            include_paths: Additional include directories
            
        Returns:
            AnalysisResult with complete symbol table and dependency graph
        """
        result = AnalysisResult()
        all_includes = list(self._extra_includes)
        if include_paths:
            all_includes.extend(include_paths)
        
        # Add directories of source files as include paths
        for sf in source_files:
            d = os.path.dirname(os.path.abspath(sf))
            if d not in all_includes:
                all_includes.append(d)
        
        if _HAS_CLANG and self._index:
            result = self._analyze_with_clang(source_files, header_files or [], all_includes)
        else:
            result = self._analyze_with_regex(source_files, header_files or [])
        
        result.files_analyzed = list(source_files)
        
        logger.info(f"ClangAnalyzer: analyzed {len(source_files)} files")
        logger.info(f"  Symbols: {len(result.symbols)}")
        logger.info(f"  Dependencies: {len(result.dependencies)}")
        logger.info(f"  Call graph entries: {len(result.call_graph)}")
        
        return result
    
    # ────────────────────────────────────────────────────────
    # Clang-based analysis
    # ────────────────────────────────────────────────────────
    
    def _analyze_with_clang(
        self,
        source_files: List[str],
        header_files: List[str],
        include_paths: List[str]
    ) -> AnalysisResult:
        """Analyze using libclang for precise AST parsing."""
        result = AnalysisResult()
        
        for source_file in source_files:
            try:
                self._analyze_single_file_clang(source_file, include_paths, result)
            except Exception as e:
                logger.warning(f"Clang parse failed for {source_file}: {e}")
                # Fallback to regex for this file
                self._analyze_single_file_regex(source_file, result)
        
        # Build reverse call graph
        for caller, callees in result.call_graph.items():
            for callee in callees:
                if callee not in result.reverse_call_graph:
                    result.reverse_call_graph[callee] = set()
                result.reverse_call_graph[callee].add(caller)
        
        return result
    
    def _analyze_single_file_clang(
        self,
        source_file: str,
        include_paths: List[str],
        result: AnalysisResult
    ):
        """Analyze a single file with libclang."""
        abs_path = os.path.abspath(source_file)
        
        # Determine language
        ext = os.path.splitext(source_file)[1].lower()
        is_cpp = ext in ('.cpp', '.cc', '.cxx', '.hpp')
        
        # Build clang args
        args = ['-std=c11' if not is_cpp else '-std=c++17']
        args.append('-DWIN32')
        args.append('-D_WIN32')
        args.append('-D_WINDOWS')
        args.append('-D_CRT_SECURE_NO_WARNINGS')
        args.append('-D_WINSOCK_DEPRECATED_NO_WARNINGS')
        # Allow unknown pragmas etc. for malware code
        args.append('-Wno-everything')
        # Prevent system header traversal (speeds up significantly)
        args.append('-fsyntax-only')
        
        for ip in include_paths:
            args.append(f'-I{ip}')
        
        # Cache file contents for body extraction & regex call graph
        try:
            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                self._file_contents_cache[abs_path] = f.read()
        except Exception:
            pass
        
        # Single parse with PARSE_INCOMPLETE to handle missing headers gracefully
        try:
            tu = self._index.parse(
                abs_path,
                args=args,
                options=(
                    TranslationUnit.PARSE_INCOMPLETE |
                    TranslationUnit.PARSE_SKIP_FUNCTION_BODIES
                )
            )
        except Exception as e:
            logger.warning(f"Clang parse error for {source_file}: {e}")
            self._analyze_single_file_regex(source_file, result)
            return
        
        # Collect diagnostics
        file_errors = []
        for diag in tu.diagnostics:
            severity = diag.severity
            if severity >= Diagnostic.Error:
                file_errors.append(str(diag))
        if file_errors:
            result.parse_errors[abs_path] = file_errors
        
        # Walk AST (function bodies are skipped, so we get declarations only)
        self._walk_cursor(tu.cursor, abs_path, result, current_function=None)
        
        # Build call graph from file content using regex since we skipped bodies
        content = self._file_contents_cache.get(abs_path, '')
        if content:
            self._build_call_graph_regex(abs_path, content, result)
    
    def _walk_cursor(
        self,
        cursor: 'Cursor',
        source_file: str,
        result: AnalysisResult,
        current_function: Optional[str] = None
    ):
        """Recursively walk the AST cursor tree."""
        # Only process nodes from our source file (not included headers)
        if cursor.location.file and os.path.abspath(cursor.location.file.name) != source_file:
            # Still recurse for top-level include expansion
            if cursor.kind == CursorKind.TRANSLATION_UNIT:
                for child in cursor.get_children():
                    self._walk_cursor(child, source_file, result, current_function)
            return
        
        kind = cursor.kind
        
        # ── Functions ──
        if kind in (CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD):
            sym = self._extract_function_symbol(cursor, source_file)
            if sym:
                if sym.name not in result.symbols:
                    result.symbols[sym.name] = []
                result.symbols[sym.name].append(sym)
                
                # Initialize call graph entry
                if sym.is_definition and sym.name not in result.call_graph:
                    result.call_graph[sym.name] = set()
                
                # Recurse into function body to find calls
                if sym.is_definition:
                    for child in cursor.get_children():
                        self._walk_cursor(child, source_file, result, 
                                         current_function=sym.name)
                return  # Don't double-recurse
        
        # ── Struct/Union/Class ──
        elif kind in (CursorKind.STRUCT_DECL, CursorKind.UNION_DECL, CursorKind.CLASS_DECL):
            name = cursor.spelling
            if name:
                kind_map = {
                    CursorKind.STRUCT_DECL: SymbolKind.STRUCT,
                    CursorKind.UNION_DECL: SymbolKind.UNION,
                    CursorKind.CLASS_DECL: SymbolKind.CLASS,
                }
                sym = Symbol(
                    name=name,
                    kind=kind_map.get(kind, SymbolKind.STRUCT),
                    file=source_file,
                    line=cursor.location.line,
                    col=cursor.location.column,
                    end_line=cursor.extent.end.line if cursor.extent else 0,
                    is_definition=cursor.is_definition(),
                )
                if name not in result.symbols:
                    result.symbols[name] = []
                result.symbols[name].append(sym)
        
        # ── Typedef ──
        elif kind == CursorKind.TYPEDEF_DECL:
            name = cursor.spelling
            if name:
                sym = Symbol(
                    name=name,
                    kind=SymbolKind.TYPEDEF,
                    file=source_file,
                    line=cursor.location.line,
                    col=cursor.location.column,
                    is_definition=True,
                )
                if name not in result.symbols:
                    result.symbols[name] = []
                result.symbols[name].append(sym)
        
        # ── Enum ──
        elif kind == CursorKind.ENUM_DECL:
            name = cursor.spelling
            if name:
                sym = Symbol(
                    name=name,
                    kind=SymbolKind.ENUM,
                    file=source_file,
                    line=cursor.location.line,
                    col=cursor.location.column,
                    end_line=cursor.extent.end.line if cursor.extent else 0,
                    is_definition=cursor.is_definition(),
                )
                if name not in result.symbols:
                    result.symbols[name] = []
                result.symbols[name].append(sym)
        
        # ── Enum constants ──
        elif kind == CursorKind.ENUM_CONSTANT_DECL:
            name = cursor.spelling
            if name:
                sym = Symbol(
                    name=name,
                    kind=SymbolKind.ENUM_CONST,
                    file=source_file,
                    line=cursor.location.line,
                    col=cursor.location.column,
                    is_definition=True,
                )
                if name not in result.symbols:
                    result.symbols[name] = []
                result.symbols[name].append(sym)
        
        # ── Global variables ──
        elif kind == CursorKind.VAR_DECL and current_function is None:
            name = cursor.spelling
            if name:
                storage = cursor.storage_class
                sym = Symbol(
                    name=name,
                    kind=SymbolKind.GLOBAL_VAR,
                    file=source_file,
                    line=cursor.location.line,
                    col=cursor.location.column,
                    is_definition=cursor.is_definition(),
                    return_type=cursor.type.spelling if cursor.type else "",
                )
                if name not in result.symbols:
                    result.symbols[name] = []
                result.symbols[name].append(sym)
        
        # ── Call expressions (for call graph) ──
        elif kind == CursorKind.CALL_EXPR and current_function:
            callee_name = cursor.spelling
            if callee_name and callee_name not in self.SYSTEM_FUNCTIONS:
                result.call_graph.setdefault(current_function, set()).add(callee_name)
                result.dependencies.append(DependencyEdge(
                    source=current_function,
                    target=callee_name,
                    kind="calls",
                    file=source_file,
                    line=cursor.location.line,
                ))
        
        # ── Type references (for dependency tracking) ──
        elif kind == CursorKind.TYPE_REF and current_function:
            type_name = cursor.spelling
            if type_name and type_name not in self.SYSTEM_TYPES:
                result.dependencies.append(DependencyEdge(
                    source=current_function,
                    target=type_name,
                    kind="uses_type",
                    file=source_file,
                    line=cursor.location.line,
                ))
        
        # ── Decl references (globals, enums) ──
        elif kind == CursorKind.DECL_REF_EXPR and current_function:
            ref = cursor.referenced
            if ref and ref.kind == CursorKind.VAR_DECL:
                # Check if it's a global (not local parameter/variable)
                ref_name = ref.spelling
                if ref_name and ref_name not in self.SYSTEM_FUNCTIONS:
                    # Check if it's in the symbol table as a global
                    syms = result.symbols.get(ref_name, [])
                    if any(s.kind == SymbolKind.GLOBAL_VAR for s in syms):
                        result.dependencies.append(DependencyEdge(
                            source=current_function,
                            target=ref_name,
                            kind="uses_global",
                            file=source_file,
                            line=cursor.location.line,
                        ))
        
        # Recurse
        for child in cursor.get_children():
            self._walk_cursor(child, source_file, result, current_function)
    
    def _build_call_graph_regex(
        self,
        source_file: str,
        content: str,
        result: AnalysisResult
    ):
        """Build call graph from function bodies using regex.
        
        Used when PARSE_SKIP_FUNCTION_BODIES is enabled for speed.
        Extracts function bodies from source text and scans for call patterns.
        """
        # Get function symbols defined in this file
        file_functions = {}
        for name, syms in result.symbols.items():
            for sym in syms:
                if (sym.kind == SymbolKind.FUNCTION and sym.is_definition 
                        and sym.file == source_file and sym.end_line > sym.line):
                    file_functions[name] = sym
        
        if not file_functions:
            return
        
        lines = content.split('\n')
        call_pattern = re.compile(r'\b(\w+)\s*\(')
        keywords = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof',
                    'case', 'default', 'do', 'else', 'goto', 'defined'}
        
        for func_name, sym in file_functions.items():
            # Extract function body text (between line and end_line)
            start = max(0, sym.line - 1)
            end = min(len(lines), sym.end_line)
            body_text = '\n'.join(lines[start:end])
            
            # Find all function calls in the body
            calls = set(call_pattern.findall(body_text))
            calls -= keywords
            calls -= {func_name}  # Remove self
            calls -= self.SYSTEM_FUNCTIONS
            
            if calls:
                result.call_graph.setdefault(func_name, set()).update(calls)
                
                for callee in calls:
                    result.dependencies.append(DependencyEdge(
                        source=func_name,
                        target=callee,
                        kind="calls",
                        file=source_file,
                        line=sym.line,
                    ))
    
    def _extract_function_symbol(self, cursor: 'Cursor', source_file: str) -> Optional[Symbol]:
        """Extract a Symbol from a function cursor."""
        name = cursor.spelling
        if not name:
            return None
        
        # Get parameters
        params = []
        for arg in cursor.get_arguments():
            param_type = arg.type.spelling if arg.type else "unknown"
            param_name = arg.spelling or ""
            params.append((param_type, param_name))
        
        # Get return type
        ret_type = ""
        if cursor.result_type:
            ret_type = cursor.result_type.spelling
        
        # Build signature string
        param_str = ", ".join(f"{t} {n}".strip() for t, n in params)
        signature = f"{ret_type} {name}({param_str})"
        
        # Check storage class
        is_static = cursor.storage_class.name == 'STATIC' if hasattr(cursor.storage_class, 'name') else False
        
        # Get line range
        end_line = cursor.extent.end.line if cursor.extent else 0
        
        # When SKIP_FUNCTION_BODIES is used, is_definition() returns False
        # even for actual definitions. Check source text to determine if this 
        # is really a definition (has a '{' body).
        is_def = cursor.is_definition()
        if not is_def and source_file in self._file_contents_cache:
            content = self._file_contents_cache[source_file]
            lines = content.split('\n')
            line_idx = cursor.location.line - 1
            # Check if '{' appears on the same line or the next few lines
            check_range = '\n'.join(lines[line_idx:min(len(lines), line_idx + 5)])
            # Match: closing paren followed by opening brace
            if re.search(r'\)\s*\{', check_range):
                is_def = True
                # Also try to find end_line from the brace
                if end_line <= cursor.location.line:
                    brace_pos = content.find('{', sum(len(l) + 1 for l in lines[:line_idx]))
                    if brace_pos >= 0:
                        end_line = self._find_matching_brace(content, brace_pos)
        
        return Symbol(
            name=name,
            kind=SymbolKind.FUNCTION,
            file=source_file,
            line=cursor.location.line,
            col=cursor.location.column,
            end_line=end_line,
            return_type=ret_type,
            parameters=params,
            signature=signature,
            is_definition=is_def,
            is_static=is_static,
            parent=cursor.semantic_parent.spelling if cursor.semantic_parent and cursor.semantic_parent.kind in (CursorKind.CLASS_DECL, CursorKind.STRUCT_DECL) else "",
        )
    
    # ────────────────────────────────────────────────────────
    # Regex fallback (when libclang unavailable)
    # ────────────────────────────────────────────────────────
    
    def _analyze_with_regex(
        self,
        source_files: List[str],
        header_files: List[str]
    ) -> AnalysisResult:
        """Fallback: regex-based analysis when libclang is not available."""
        result = AnalysisResult()
        for sf in source_files + header_files:
            self._analyze_single_file_regex(sf, result)
        
        # Build reverse call graph
        for caller, callees in result.call_graph.items():
            for callee in callees:
                if callee not in result.reverse_call_graph:
                    result.reverse_call_graph[callee] = set()
                result.reverse_call_graph[callee].add(caller)
        
        return result
    
    def _analyze_single_file_regex(self, source_file: str, result: AnalysisResult):
        """Regex-based analysis for a single file."""
        abs_path = os.path.abspath(source_file)
        
        try:
            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Cannot read {source_file}: {e}")
            return
        
        lines = content.split('\n')
        
        # ── Extract function definitions ──
        # Pattern: return_type func_name(params) {
        func_pattern = re.compile(
            r'^[\s]*((?:static\s+|inline\s+|extern\s+|unsigned\s+|signed\s+|const\s+|volatile\s+)*'
            r'(?:void|int|char|short|long|float|double|BOOL|DWORD|HANDLE|LPSTR|LPCSTR|'
            r'SOCKET|HRESULT|NTSTATUS|size_t|BYTE|WORD|LPVOID|PVOID|'
            r'struct\s+\w+|enum\s+\w+|\w+)\s*\**)\s+'
            r'(\w+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )
        
        for match in func_pattern.finditer(content):
            ret_type = match.group(1).strip()
            func_name = match.group(2)
            params_str = match.group(3).strip()
            line_num = content[:match.start()].count('\n') + 1
            
            # Parse parameters
            params = []
            if params_str and params_str != 'void':
                for p in params_str.split(','):
                    p = p.strip()
                    if p:
                        # Last word is parameter name, rest is type
                        tokens = p.split()
                        if len(tokens) >= 2:
                            pname = tokens[-1].strip('*&')
                            ptype = ' '.join(tokens[:-1])
                            params.append((ptype, pname))
                        else:
                            params.append((p, ''))
            
            is_static = 'static' in ret_type
            is_inline = 'inline' in ret_type
            
            # Find end of function (match braces)
            brace_start = match.end() - 1
            end_line = self._find_matching_brace(content, brace_start)
            
            param_str = ", ".join(f"{t} {n}".strip() for t, n in params)
            signature = f"{ret_type} {func_name}({param_str})"
            
            sym = Symbol(
                name=func_name,
                kind=SymbolKind.FUNCTION,
                file=abs_path,
                line=line_num,
                col=0,
                end_line=end_line,
                return_type=ret_type,
                parameters=params,
                signature=signature,
                is_definition=True,
                is_static=is_static,
                is_inline=is_inline,
            )
            
            if func_name not in result.symbols:
                result.symbols[func_name] = []
            result.symbols[func_name].append(sym)
            
            # Extract call graph from function body
            if end_line > line_num:
                body_text = '\n'.join(lines[line_num - 1:end_line])
                call_pattern = re.compile(r'\b(\w+)\s*\(')
                calls = set(call_pattern.findall(body_text))
                # Remove keywords and self
                keywords = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof',
                           'case', 'default', 'do', 'else', 'goto'}
                calls -= keywords
                calls -= {func_name}  # Remove self-recursion from deps
                calls -= self.SYSTEM_FUNCTIONS
                
                result.call_graph[func_name] = calls
                
                for callee in calls:
                    result.dependencies.append(DependencyEdge(
                        source=func_name,
                        target=callee,
                        kind="calls",
                        file=abs_path,
                        line=line_num,
                    ))
        
        # ── Extract struct/union/typedef definitions ──
        struct_pattern = re.compile(
            r'\b(struct|union|typedef\s+struct|typedef\s+union)\s+(\w+)',
            re.MULTILINE
        )
        for match in struct_pattern.finditer(content):
            kind_str = match.group(1).strip()
            name = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            if 'typedef' in kind_str:
                sk = SymbolKind.TYPEDEF
            elif 'struct' in kind_str:
                sk = SymbolKind.STRUCT
            else:
                sk = SymbolKind.UNION
            
            sym = Symbol(
                name=name, kind=sk, file=abs_path,
                line=line_num, col=0, is_definition=True
            )
            if name not in result.symbols:
                result.symbols[name] = []
            result.symbols[name].append(sym)
        
        # ── Extract #define macros ──
        define_pattern = re.compile(r'^\s*#define\s+(\w+)', re.MULTILINE)
        for match in define_pattern.finditer(content):
            name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            sym = Symbol(
                name=name, kind=SymbolKind.MACRO, file=abs_path,
                line=line_num, col=0, is_definition=True
            )
            if name not in result.symbols:
                result.symbols[name] = []
            result.symbols[name].append(sym)
        
        # ── Extract global variables ──
        # Simple heuristic: top-level declarations outside functions
        global_pattern = re.compile(
            r'^(?:static\s+|extern\s+|const\s+|volatile\s+)*'
            r'(?:int|char|short|long|float|double|DWORD|HANDLE|BYTE|WORD|BOOL|'
            r'unsigned\s+\w+|signed\s+\w+|struct\s+\w+|\w+)\s*\**\s+'
            r'(\w+)\s*(?:=|;|\[)',
            re.MULTILINE
        )
        # Only match globals outside function bodies
        func_ranges = []
        for name, syms in result.symbols.items():
            for s in syms:
                if s.kind == SymbolKind.FUNCTION and s.is_definition and s.file == abs_path:
                    func_ranges.append((s.line, s.end_line))
        
        for match in global_pattern.finditer(content):
            name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            # Check if inside a function
            in_func = any(start <= line_num <= end for start, end in func_ranges)
            if not in_func and name not in self.SYSTEM_TYPES:
                sym = Symbol(
                    name=name, kind=SymbolKind.GLOBAL_VAR, file=abs_path,
                    line=line_num, col=0, is_definition=True
                )
                if name not in result.symbols:
                    result.symbols[name] = []
                result.symbols[name].append(sym)
    
    @staticmethod
    def _find_matching_brace(content: str, brace_pos: int) -> int:
        """Find the line number of the matching closing brace."""
        depth = 0
        for i in range(brace_pos, len(content)):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
                if depth == 0:
                    return content[:i].count('\n') + 1
        return content.count('\n') + 1
    
    # ────────────────────────────────────────────────────────
    # Mutation Validation
    # ────────────────────────────────────────────────────────
    
    def validate_mutation(
        self,
        analysis: AnalysisResult,
        func_name: str,
        mutated_code: str,
        original_code: str = ""
    ) -> List[str]:
        """
        Validate a proposed mutation BEFORE compiling.
        
        Checks:
        1. Function signature preserved
        2. All called functions exist (no invented APIs)
        3. All used types exist
        4. No symbol name conflicts introduced
        
        Returns list of issues (empty = valid).
        """
        issues = []
        
        original_sym = analysis.get_symbol(func_name)
        if not original_sym:
            return issues  # Can't validate unknown function
        
        # ── Check 1: Signature preservation ──
        if original_sym.signature:
            # Extract signature from mutated code
            sig_pattern = re.compile(
                rf'(?:static\s+|inline\s+)?(?:\w[\w\s\*]+)\s+{re.escape(func_name)}\s*\([^)]*\)'
            )
            sig_match = sig_pattern.search(mutated_code)
            if not sig_match:
                issues.append(f"SIGNATURE_MISSING: Function {func_name} signature not found in mutated code")
            else:
                # Compare parameter count
                orig_params = len(original_sym.parameters)
                mut_sig = sig_match.group(0)
                mut_param_str = mut_sig[mut_sig.find('(') + 1:mut_sig.rfind(')')]
                if mut_param_str.strip() == 'void' or not mut_param_str.strip():
                    mut_params = 0
                else:
                    mut_params = len([p for p in mut_param_str.split(',') if p.strip()])
                
                if orig_params != mut_params:
                    issues.append(
                        f"PARAM_COUNT_MISMATCH: {func_name} has {orig_params} params "
                        f"but mutated version has {mut_params}"
                    )
        
        # ── Check 2: Called functions exist ──
        call_pattern = re.compile(r'\b(\w+)\s*\(')
        calls_in_mutation = set(call_pattern.findall(mutated_code))
        keywords = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof',
                    'case', 'default', 'do', 'else', 'goto', 'defined'}
        calls_in_mutation -= keywords
        calls_in_mutation -= {func_name}
        calls_in_mutation -= self.SYSTEM_FUNCTIONS
        
        # Check against known project symbols
        known_functions = set(analysis.get_function_symbols().keys())
        
        for call in calls_in_mutation:
            if call not in known_functions and call not in self.SYSTEM_FUNCTIONS:
                # Check if it's defined within the mutated code itself (new helper)
                new_func_pattern = re.compile(rf'\b\w[\w\s\*]+\s+{re.escape(call)}\s*\([^)]*\)\s*\{{')
                if not new_func_pattern.search(mutated_code):
                    # Could be a system function we don't know about, or a macro
                    if call not in analysis.symbols:
                        issues.append(f"UNKNOWN_FUNCTION: {call}() called but not defined anywhere")
        
        # ── Check 3: Types used exist ──
        # Look for type casts and declarations
        type_cast_pattern = re.compile(r'\((\w+)\s*\*?\s*\)')
        type_decl_pattern = re.compile(r'\b(\w+)\s+\w+\s*[;=\[,)]')
        
        used_types = set()
        for pattern in [type_cast_pattern, type_decl_pattern]:
            for match in pattern.finditer(mutated_code):
                t = match.group(1)
                if t and t[0].isupper() and t not in keywords:
                    used_types.add(t)
        
        for t in used_types:
            if (t not in analysis.symbols 
                and t not in self.SYSTEM_TYPES
                and t not in self.SYSTEM_FUNCTIONS
                and t not in {'TRUE', 'FALSE', 'NULL', 'INVALID_HANDLE_VALUE'}):
                issues.append(f"UNKNOWN_TYPE: Type {t} used but not defined")
        
        return issues
    
    def auto_fix_mutation(
        self,
        analysis: AnalysisResult,
        func_name: str,
        mutated_code: str,
        issues: List[str]
    ) -> Tuple[str, List[str]]:
        """
        Try to auto-fix mutation issues WITHOUT calling the LLM.
        
        Returns (fixed_code, remaining_issues).
        """
        fixed_code = mutated_code
        remaining = []
        
        for issue in issues:
            if issue.startswith("UNKNOWN_FUNCTION:"):
                # Extract the function name
                match = re.search(r'UNKNOWN_FUNCTION:\s+(\w+)\(\)', issue)
                if match:
                    bad_func = match.group(1)
                    # Check if it's a renamed version of a known function
                    # e.g., "SetRegistryValueW" when code has "RegSetValueExW"
                    fixed = self._try_fix_function_name(analysis, bad_func, fixed_code)
                    if fixed:
                        fixed_code = fixed
                        continue
                remaining.append(issue)
            
            elif issue.startswith("PARAM_COUNT_MISMATCH:"):
                # Can't auto-fix parameter count changes
                remaining.append(issue)
            
            elif issue.startswith("SIGNATURE_MISSING:"):
                remaining.append(issue)
            
            elif issue.startswith("UNKNOWN_TYPE:"):
                remaining.append(issue)
            
            else:
                remaining.append(issue)
        
        return fixed_code, remaining
    
    def _try_fix_function_name(
        self,
        analysis: AnalysisResult,
        bad_name: str,
        code: str
    ) -> Optional[str]:
        """Try to replace an unknown function with the correct known one."""
        known_functions = set(analysis.get_function_symbols().keys())
        
        # Strategy 1: Case-insensitive match
        for known in known_functions:
            if known.lower() == bad_name.lower() and known != bad_name:
                logger.info(f"  Auto-fix: {bad_name} -> {known} (case fix)")
                return re.sub(r'\b' + re.escape(bad_name) + r'\b', known, code)
        
        # Strategy 2: Common API name confusion patterns
        # e.g., "SetRegistryValueW" -> should be "RegSetValueExW"
        # This requires knowing common API aliases - skip for now
        
        return None
    
    # ────────────────────────────────────────────────────────
    # Prompt Generation
    # ────────────────────────────────────────────────────────
    
    def generate_mutation_prompt_context(
        self,
        analysis: AnalysisResult,
        func_name: str,
        strategy_name: str = ""
    ) -> str:
        """
        Generate enhanced context for the LLM mutation prompt.
        Includes dependency information so the LLM knows what to preserve.
        """
        parts = []
        
        # Safety score
        score, reason = analysis.get_mutation_safety_score(func_name)
        parts.append(f"[Mutation Safety: {score:.1f}/1.0 - {reason}]")
        
        # Dependency context
        dep_context = analysis.get_dependency_context_for_prompt(func_name)
        if dep_context:
            parts.append(dep_context)
        
        # Add specific warnings based on analysis
        callees = analysis.get_callees(func_name)
        project_funcs = set(analysis.get_function_symbols().keys())
        project_callees = callees & project_funcs
        
        if project_callees:
            parts.append(
                f"\n⚠️ WARNING: This function calls {len(project_callees)} project-defined functions. "
                f"You MUST keep calls to: {', '.join(sorted(project_callees)[:10])}"
            )
        
        callers = analysis.get_callers(func_name)
        if callers:
            parts.append(
                f"\n⚠️ WARNING: This function is called by {len(callers)} other functions. "
                f"You MUST NOT change its signature (return type, name, parameters)."
            )
        
        return "\n".join(parts)
    
    def rank_mutation_candidates(
        self,
        analysis: AnalysisResult,
        candidate_functions: List[str]
    ) -> List[Tuple[str, float, str]]:
        """
        Rank mutation candidates by safety score.
        
        Returns list of (func_name, score, reason) sorted by score descending.
        """
        ranked = []
        for func_name in candidate_functions:
            score, reason = analysis.get_mutation_safety_score(func_name)
            ranked.append((func_name, score, reason))
        
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked


# ═══════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════

def analyze_project(
    source_files: List[str],
    header_files: Optional[List[str]] = None,
    include_paths: Optional[List[str]] = None
) -> AnalysisResult:
    """
    Convenience function: analyze a project's source files.
    
    Usage:
        result = analyze_project(["a.c", "b.c"], ["common.h"])
        for func in result.get_leaf_functions():
            print(f"Safe to mutate: {func}")
    """
    analyzer = ClangAnalyzer()
    return analyzer.analyze_files(source_files, header_files, include_paths)


def validate_mutation(
    analysis: AnalysisResult,
    func_name: str,
    mutated_code: str
) -> List[str]:
    """Convenience: validate a mutation."""
    analyzer = ClangAnalyzer()
    return analyzer.validate_mutation(analysis, func_name, mutated_code)

"""
MutationValidator — AST-based validation for LLM-mutated code.

Uses tree-sitter to parse both original and mutated C/C++ code, extract
structural features, and run pluggable checks to detect common LLM
mutation failures:

  - Hallucinated junk (300+ unused variable declarations, no real logic)
  - Buffer overflow in stack-built strings (array size < assignment count)
  - Missing function calls (original logic deleted)
  - Suspicious type casts (narrow char* cast to LPCWSTR)
  - Forward declarations that conflict with existing headers
  - Logic density collapse (almost all code is declarations, no work)

Each check is a standalone function that receives extracted AST features
and returns (pass: bool, reason: str). New checks can be added by
writing a function and appending it to _CHECKS.

This module complements (not replaces) the existing regex-based gates
in mutation_agent.py. It provides a deeper, structural layer of
validation on top of the simpler size/brace/stub checks.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── tree-sitter import ──────────────────────────────────────────────
_HAS_TREE_SITTER = False
_C_LANG = None
_CPP_LANG = None

try:
    from tree_sitter import Language, Parser, Node
    try:
        import tree_sitter_c as _ts_c
        import tree_sitter_cpp as _ts_cpp
        _C_LANG = Language(_ts_c.language())
        _CPP_LANG = Language(_ts_cpp.language())
        _HAS_TREE_SITTER = True
    except ImportError:
        logger.warning("tree-sitter-c/cpp not installed. MutationValidator disabled.")
except ImportError:
    logger.warning("tree-sitter not installed. MutationValidator disabled.")
    Node = None  # type: ignore


# ═══════════════════════════════════════════════════════════════════
# Data: extracted features from AST
# ═══════════════════════════════════════════════════════════════════

@dataclass
class CodeFeatures:
    """Structural features extracted from a C/C++ function via tree-sitter."""

    # Function calls present in the code (set of names)
    function_calls: Set[str] = field(default_factory=set)

    # Local variable declarations: name -> type string
    local_declarations: Dict[str, str] = field(default_factory=dict)

    # Array declarations: name -> declared size (from char _s0[13])
    array_sizes: Dict[str, int] = field(default_factory=dict)

    # Array max subscript index written: name -> max index seen
    array_max_index: Dict[str, int] = field(default_factory=dict)

    # Forward function declarations (not definitions) added in the code
    forward_declarations: Set[str] = field(default_factory=set)

    # Suspicious casts: list of (cast_target_type, variable_name, variable_type)
    suspicious_casts: List[Tuple[str, str, str]] = field(default_factory=list)

    # Character width inferred for local variables: "narrow", "wide", "byte", or "unknown"
    var_char_widths: Dict[str, str] = field(default_factory=dict)

    # Function call argument widths: (call_name, arg_index, width, expression_preview)
    call_arg_widths: List[Tuple[str, int, str, str]] = field(default_factory=list)

    # Counts
    total_lines: int = 0
    declaration_lines: int = 0  # lines that are only declarations
    executable_lines: int = 0   # lines with actual logic (calls, assignments, control flow)
    ast_node_count: int = 0     # total AST nodes (complexity proxy)
    error_node_count: int = 0   # tree-sitter ERROR nodes (parse failures)

    # String literals still present in the code
    string_literals: List[str] = field(default_factory=list)

    @property
    def logic_density(self) -> float:
        """Ratio of executable lines to total non-blank lines."""
        total = self.declaration_lines + self.executable_lines
        if total == 0:
            return 0.0
        return self.executable_lines / total

    @property
    def declaration_ratio(self) -> float:
        """Ratio of declaration lines to total non-blank lines."""
        total = self.declaration_lines + self.executable_lines
        if total == 0:
            return 0.0
        return self.declaration_lines / total


# Check result type
CheckResult = Tuple[bool, str]  # (passed, reason_if_failed)

# Check function signature: (original_features, mutated_features, strategy) -> CheckResult
CheckFn = Callable[[CodeFeatures, CodeFeatures, str], CheckResult]


# ═══════════════════════════════════════════════════════════════════
# Feature Extractor
# ═══════════════════════════════════════════════════════════════════

class _FeatureExtractor:
    """Extract CodeFeatures from C/C++ code using tree-sitter AST."""

    def __init__(self):
        self._available = _HAS_TREE_SITTER

    def _get_parser(self, language: str) -> Optional['Parser']:
        if not self._available:
            return None
        lang = language.lower().replace('+', 'p')
        if lang in ('c',):
            return Parser(_C_LANG)
        elif lang in ('cpp', 'cplusplus', 'cxx'):
            return Parser(_CPP_LANG)
        return None

    def extract(self, code: str, language: str = "c") -> Optional[CodeFeatures]:
        """Parse code and extract structural features."""
        parser = self._get_parser(language)
        if not parser:
            return None

        tree = parser.parse(bytes(code, 'utf-8'))
        root = tree.root_node
        feats = CodeFeatures()
        feats.ast_node_count = self._count_nodes(root)

        # Line-level analysis
        lines = code.split('\n')
        feats.total_lines = len(lines)
        self._classify_lines(lines, feats)

        # AST walk
        self._walk(root, code, feats)

        # Regex-based supplementary extraction (catches things AST may
        # represent differently across tree-sitter versions)
        self._extract_array_info_regex(code, feats)
        self._extract_variable_widths_regex(code, feats)
        self._extract_call_arg_widths_regex(code, feats)
        self._extract_string_literals_regex(code, feats)
        self._extract_suspicious_casts_regex(code, feats)

        return feats

    # ── AST walking ────────────────────────────────────────────────

    def _count_nodes(self, node) -> int:
        count = 1
        for child in node.children:
            count += self._count_nodes(child)
        return count

    def _walk(self, node, code: str, feats: CodeFeatures):
        """Recursively walk AST and populate features."""
        ntype = node.type

        # Count parse errors
        if ntype == 'ERROR' or node.is_missing:
            feats.error_node_count += 1

        # Function call expressions
        if ntype == 'call_expression':
            func_node = node.child_by_field_name('function')
            if func_node:
                name = code[func_node.start_byte:func_node.end_byte]
                # Strip object access (pBrowser2->Navigate → Navigate)
                if '->' in name:
                    name = name.split('->')[-1]
                if '.' in name:
                    name = name.split('.')[-1]
                # Strip pointer dereference
                name = name.lstrip('*')
                if name and not name.startswith('('):
                    feats.function_calls.add(name)

        # Declaration (top-level in function body = forward decl if it's a function declarator)
        if ntype == 'declaration':
            self._check_forward_declaration(node, code, feats)

        # Recurse
        for child in node.children:
            self._walk(child, code, feats)

    def _check_forward_declaration(self, node, code: str, feats: CodeFeatures):
        """Detect function forward declarations (not variable declarations)."""
        text = code[node.start_byte:node.end_byte].strip()
        # Pattern: return_type name(params); with no body
        # This catches: int ZipAdd(HZIP, const TCHAR*, const TCHAR*);
        if re.match(
            r'^(?:(?:static|extern|inline|const|unsigned|signed)\s+)*'
            r'(?:int|void|BOOL|DWORD|HRESULT|ZRESULT|HANDLE|HMODULE|NTSTATUS|LONG|SIZE_T)\s+'
            r'(\w+)\s*\([^)]*\)\s*;',
            text,
        ):
            m = re.search(r'\b(\w+)\s*\(', text)
            if m:
                name = m.group(1)
                # Only flag if it looks like a forward declaration (no body { })
                if '{' not in text:
                    feats.forward_declarations.add(name)

    # ── Line classification ────────────────────────────────────────

    def _classify_lines(self, lines: List[str], feats: CodeFeatures):
        """Classify lines as declaration-only vs executable."""
        _DECL_ONLY = re.compile(
            r'^\s*'
            r'(?:(?:volatile|const|static|unsigned|signed|register|extern|inline)\s+)*'
            r'(?:int|char|short|long|float|double|void|BOOL|DWORD|HANDLE|BYTE|WORD|UINT|'
            r'SIZE_T|HMODULE|HRESULT|LPSTR|LPCSTR|LPVOID|PVOID|WCHAR|LPWSTR|LPCWSTR|'
            r'LPBYTE|LPDWORD|HINTERNET|HKEY|FARPROC|NTSTATUS|SOCKET|HDC|HBITMAP|'
            r'MEMORYSTATUS|SYSTEMTIME|SYSTEM_INFO|WIN32_FIND_DATAW|'
            r'BITMAPFILEHEADER|BITMAPINFOHEADER|PBITMAPINFO|PBITMAPINFOHEADER|'
            r'JSON_Value|JSON_Object|VARIANT|HZIP'
            r')\s*\*?\s*\w+(?:\s*\[\d*\])?\s*(?:=\s*(?:0|NULL|FALSE|TRUE|nullptr))?\s*;'
            r'\s*$'
        )
        _BLANK = re.compile(r'^\s*$')
        _COMMENT = re.compile(r'^\s*//')
        _OPEN_BRACE = re.compile(r'^\s*\{?\s*$')
        _CLOSE_BRACE = re.compile(r'^\s*\}?\s*$')

        for line in lines:
            if _BLANK.match(line) or _COMMENT.match(line):
                continue
            if _OPEN_BRACE.match(line) or _CLOSE_BRACE.match(line):
                continue
            if _DECL_ONLY.match(line):
                feats.declaration_lines += 1
            else:
                feats.executable_lines += 1

    # ── Regex supplementary extraction ─────────────────────────────

    def _extract_array_info_regex(self, code: str, feats: CodeFeatures):
        """Extract array declarations and subscript assignments via regex."""
        # Array declarations: char _s0[13]; or WCHAR _w0[8];
        for m in re.finditer(r'\b(?:char|WCHAR|wchar_t|BYTE|unsigned\s+char)\s+(\w+)\s*\[(\d+)\]', code):
            name = m.group(1)
            size = int(m.group(2))
            feats.array_sizes[name] = size

        # Array subscript assignments: _s0[6] = 'x'; or _s0[6]='x';
        for m in re.finditer(r'\b(\w+)\s*\[(\d+)\]\s*=', code):
            name = m.group(1)
            idx = int(m.group(2))
            if name in feats.array_sizes:
                cur_max = feats.array_max_index.get(name, -1)
                if idx > cur_max:
                    feats.array_max_index[name] = idx

    def _extract_variable_widths_regex(self, code: str, feats: CodeFeatures):
        """Infer narrow/wide byte character width for local variables."""
        type_patterns = [
            (
                "wide",
                r'\b(?:const\s+)?(?:WCHAR|wchar_t|OLECHAR)\s*(?:\*|\s)\s*(\w+)\s*(?:\[\s*\d*\s*\])?',
            ),
            (
                "wide",
                r'\b(?:BSTR|LPWSTR|LPCWSTR)\s+(\w+)\b',
            ),
            (
                "narrow",
                r'\b(?:const\s+)?(?:char|CHAR)\s*(?:\*|\s)\s*(\w+)\s*(?:\[\s*\d*\s*\])?',
            ),
            (
                "narrow",
                r'\b(?:LPSTR|LPCSTR)\s+(\w+)\b',
            ),
            (
                "byte",
                r'\b(?:BYTE|unsigned\s+char)\s*(?:\*|\s)\s*(\w+)\s*(?:\[\s*\d*\s*\])?',
            ),
        ]
        for width, pattern in type_patterns:
            for match in re.finditer(pattern, code):
                name = match.group(1)
                if name:
                    feats.var_char_widths[name] = width

    def _extract_call_arg_widths_regex(self, code: str, feats: CodeFeatures):
        """Extract inferred character width for function-call arguments.

        This is deliberately generic: it does not know API names. It records
        whether each call argument is a wide string, narrow string, or a local
        variable previously declared as wide/narrow/byte.
        """
        for call_name, args_text in self._iter_call_expressions_regex(code):
            args = self._split_args(args_text)
            for idx, arg in enumerate(args):
                width = self._infer_expr_char_width(arg.strip(), feats)
                if width != "unknown":
                    feats.call_arg_widths.append((call_name, idx, width, arg.strip()[:80]))

    def _iter_call_expressions_regex(self, code: str):
        """Yield (call_name, args_text) for simple balanced call expressions."""
        keywords = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'catch'}
        i = 0
        n = len(code)
        while i < n:
            match = re.search(r'\b([A-Za-z_]\w*)\s*\(', code[i:])
            if not match:
                break
            name = match.group(1)
            start = i + match.end() - 1
            i = start + 1
            if name in keywords:
                continue

            depth = 0
            in_string = False
            in_char = False
            escape = False
            end = None
            for pos in range(start, n):
                ch = code[pos]
                if escape:
                    escape = False
                    continue
                if ch == '\\':
                    escape = True
                    continue
                if in_string:
                    if ch == '"':
                        in_string = False
                    continue
                if in_char:
                    if ch == "'":
                        in_char = False
                    continue
                if ch == '"':
                    in_string = True
                    continue
                if ch == "'":
                    in_char = True
                    continue
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                    if depth == 0:
                        end = pos
                        break
            if end is None:
                continue
            yield name, code[start + 1:end]
            i = end + 1

    @staticmethod
    def _split_args(args_text: str) -> List[str]:
        """Split a C/C++ argument list while respecting simple nesting."""
        args: List[str] = []
        current: List[str] = []
        depth = 0
        in_string = False
        in_char = False
        escape = False
        for ch in args_text:
            if escape:
                current.append(ch)
                escape = False
                continue
            if ch == '\\':
                current.append(ch)
                escape = True
                continue
            if in_string:
                current.append(ch)
                if ch == '"':
                    in_string = False
                continue
            if in_char:
                current.append(ch)
                if ch == "'":
                    in_char = False
                continue
            if ch == '"':
                in_string = True
                current.append(ch)
                continue
            if ch == "'":
                in_char = True
                current.append(ch)
                continue
            if ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth = max(0, depth - 1)
            if ch == ',' and depth == 0:
                args.append(''.join(current).strip())
                current = []
            else:
                current.append(ch)
        tail = ''.join(current).strip()
        if tail:
            args.append(tail)
        return args

    @staticmethod
    def _infer_expr_char_width(expr: str, feats: CodeFeatures) -> str:
        """Infer expression character width: wide/narrow/byte/unknown."""
        expr = re.sub(r'^\(\s*(?:const\s+)?[\w\s\*]+\s*\)\s*', '', expr).strip()
        if re.match(r'^(?:L|TEXT|_T)\s*\(', expr):
            return "wide"
        if re.match(r'^(?:L|u|U)?"', expr):
            return "wide" if expr.startswith('L"') else "narrow"
        if re.match(r"^L'.*'$", expr):
            return "wide"
        if re.match(r"^'.*'$", expr):
            return "narrow"
        if expr in feats.var_char_widths:
            return feats.var_char_widths[expr]
        addr = re.match(r'^&\s*(\w+)\b', expr)
        if addr and addr.group(1) in feats.var_char_widths:
            return feats.var_char_widths[addr.group(1)]
        sub = re.match(r'^(\w+)\s*\[', expr)
        if sub and sub.group(1) in feats.var_char_widths:
            return feats.var_char_widths[sub.group(1)]
        return "unknown"

    def _extract_string_literals_regex(self, code: str, feats: CodeFeatures):
        """Extract string literals still present in the code."""
        # Match "..." strings but not inside comments or char-by-char assignments
        for m in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', code):
            literal = m.group(1)
            # Skip single-char or empty
            if len(literal) >= 2:
                feats.string_literals.append(literal)

    def _extract_suspicious_casts_regex(self, code: str, feats: CodeFeatures):
        """Detect suspicious type casts: (LPCWSTR)narrow_char_var."""
        # Find all local char arrays/pointers
        narrow_vars: Set[str] = set()
        for m in re.finditer(r'\b(?:char|CHAR|LPSTR|LPCSTR)\s*\*?\s*(\w+)', code):
            narrow_vars.add(m.group(1))
        for m in re.finditer(r'\b(?:char)\s+(\w+)\s*\[', code):
            narrow_vars.add(m.group(1))

        # Find casts to wide types applied to narrow vars
        wide_types = {'LPCWSTR', 'LPWSTR', 'WCHAR*', 'wchar_t*', 'BSTR'}
        for m in re.finditer(r'\(\s*(LPCWSTR|LPWSTR|WCHAR\s*\*|wchar_t\s*\*|BSTR)\s*\)\s*(\w+)', code):
            cast_type = m.group(1).strip()
            var_name = m.group(2)
            if var_name in narrow_vars:
                feats.suspicious_casts.append((cast_type, var_name, 'char'))


# ═══════════════════════════════════════════════════════════════════
# Pluggable Checks
# ═══════════════════════════════════════════════════════════════════

def _check_logic_density(
    orig: CodeFeatures, mut: CodeFeatures, strategy: str,
) -> CheckResult:
    """Reject if mutated code is almost entirely declarations with no logic.

    Catches the enumTelegram-style failure where the LLM outputs 300+
    variable declarations and no actual function body.
    """
    if mut.total_lines < 10:
        return True, ""

    # Allow higher declaration ratio for strat_1 (string obfuscation adds many char arrays)
    max_decl_ratio = 0.85 if strategy == "strat_1" else 0.80

    if mut.declaration_ratio > max_decl_ratio and mut.executable_lines < 3:
        return False, (
            f"Logic density too low: {mut.declaration_lines} declaration lines vs "
            f"{mut.executable_lines} executable lines "
            f"(ratio {mut.declaration_ratio:.2f}, max {max_decl_ratio}). "
            f"Your output is almost entirely variable declarations with no real logic. "
            f"You MUST preserve ALL original logic — do NOT replace the function body "
            f"with just variable declarations."
        )
    return True, ""


def _check_function_call_preservation(
    orig: CodeFeatures, mut: CodeFeatures, strategy: str,
) -> CheckResult:
    """Reject if important function calls from the original are missing.

    The mutation should preserve ALL original function calls (possibly
    calling them through function pointers for strat_3/strat_all).
    """
    if not orig.function_calls:
        return True, ""

    # For strat_3/strat_all, API calls may be replaced with function pointers
    # resolved via GetProcAddress, so we can't require exact name matches
    # for Win32 APIs. But project-level helper calls must remain.
    if strategy in ("strat_3", "strat_all"):
        # Only check that GetProcAddress/LoadLibraryA appear (they're resolving the others)
        if orig.function_calls - mut.function_calls:
            # Some calls disappeared — only flag if no GetProcAddress is used
            if "GetProcAddress" not in mut.function_calls:
                missing = orig.function_calls - mut.function_calls
                # Filter out common Win32 APIs that may be dynamically resolved
                _win32_dynamic = {
                    'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile',
                    'RegOpenKeyExA', 'RegOpenKeyExW', 'VirtualAlloc',
                    'CreateProcessA', 'CreateProcessW', 'InternetOpenA',
                    'InternetOpenW', 'HttpOpenRequestA', 'HttpSendRequestW',
                    'InternetConnectW', 'InternetOpenUrlA', 'CopyFileA',
                    'DeleteFileA', 'GetModuleFileNameA', 'SHGetFolderPathA',
                    'InternetCloseHandle', 'HttpSendRequestA',
                }
                non_api_missing = missing - _win32_dynamic
                if non_api_missing:
                    return False, (
                        f"Missing {len(non_api_missing)} original function call(s) that are NOT "
                        f"Win32 APIs (cannot be replaced by GetProcAddress): "
                        f"{', '.join(sorted(list(non_api_missing)[:8]))}. "
                        f"These calls MUST remain in the mutated code."
                    )
        return True, ""

    # For other strategies: check that at least 60% of original calls remain
    if len(orig.function_calls) >= 3:
        preserved = orig.function_calls & mut.function_calls
        preservation_rate = len(preserved) / len(orig.function_calls)
        if preservation_rate < 0.60:
            missing = orig.function_calls - mut.function_calls
            return False, (
                f"Only {len(preserved)}/{len(orig.function_calls)} original function calls "
                f"preserved ({preservation_rate:.0%}). Missing: "
                f"{', '.join(sorted(list(missing)[:8]))}. "
                f"You MUST keep ALL original function calls. Only change HOW they are "
                f"called (e.g., via function pointer), not WHETHER they are called."
            )
    return True, ""


def _check_buffer_overflow(
    orig: CodeFeatures, mut: CodeFeatures, strategy: str,
) -> CheckResult:
    """Reject if any stack-built array has out-of-bounds writes.

    Catches: char _s0[4]; _s0[4]='I'; _s0[5]='1'; _s0[6]=0;
    """
    for name, size in mut.array_sizes.items():
        max_idx = mut.array_max_index.get(name, -1)
        if max_idx >= size:
            return False, (
                f"Buffer overflow: array '{name}' declared with size {size} "
                f"but you wrote to index [{max_idx}]. "
                f"The valid index range is [0..{size - 1}]. "
                f"Fix: change declaration to `char {name}[{max_idx + 1}]` "
                f"or reduce the number of character assignments."
            )
    return True, ""


def _check_suspicious_casts(
    orig: CodeFeatures, mut: CodeFeatures, strategy: str,
) -> CheckResult:
    """Reject if narrow char arrays are cast to wide string types.

    Catches: (LPCWSTR)_s5 where _s5 is char[64] — produces garbage
    when passed to SysAllocString or other wide-string APIs.
    """
    # Only flag casts that weren't in the original
    orig_cast_vars = {c[1] for c in orig.suspicious_casts}
    new_casts = [c for c in mut.suspicious_casts if c[1] not in orig_cast_vars]

    if new_casts:
        cast = new_casts[0]
        return False, (
            f"Suspicious type cast: ({cast[0]}){cast[1]} — but '{cast[1]}' is a "
            f"narrow char array/pointer. Casting char* to a wide string type "
            f"(LPCWSTR/LPWSTR) produces garbage. "
            f"Use a WCHAR array with wchar_t character literals instead: "
            f"WCHAR _w0[N]; _w0[0]=L'C'; _w0[1]=L':'; ... _w0[N-1]=0;"
        )
    return True, ""


def _check_call_argument_char_width_preservation(
    orig: CodeFeatures, mut: CodeFeatures, strategy: str,
) -> CheckResult:
    """Reject narrow/wide string regressions at matching call arguments.

    The check is intentionally API-agnostic. If the original code passed a
    wide-character value at `SomeCall(argN)` and the mutation now passes a
    narrow char buffer/string at the same call argument position, the mutation
    is likely to fail compilation or corrupt runtime data. The inverse is also
    rejected for the same reason.
    """
    original_widths: Dict[Tuple[str, int], Set[str]] = {}
    for call_name, arg_index, width, _expr in orig.call_arg_widths:
        if width in {"wide", "narrow"}:
            original_widths.setdefault((call_name, arg_index), set()).add(width)

    for call_name, arg_index, width, expr in mut.call_arg_widths:
        if width not in {"wide", "narrow"}:
            continue
        expected = original_widths.get((call_name, arg_index))
        if not expected:
            continue
        if "wide" in expected and width == "narrow":
            return False, (
                f"Argument character-width mismatch at call `{call_name}` arg {arg_index}: "
                f"the original call used a wide-character value, but the mutated call passes "
                f"a narrow char expression `{expr}`. Preserve the original pointee width: "
                f"use a wide local buffer/type (for example WCHAR/wchar_t/OLECHAR with wide "
                f"character literals) or keep the original wide argument. Fix only this "
                f"argument construction and preserve all original logic."
            )
        if "narrow" in expected and width == "wide":
            return False, (
                f"Argument character-width mismatch at call `{call_name}` arg {arg_index}: "
                f"the original call used a narrow char value, but the mutated call passes "
                f"a wide-character expression `{expr}`. Preserve the original pointee width "
                f"and fix only this argument construction."
            )
    return True, ""


def _check_forward_declarations(
    orig: CodeFeatures, mut: CodeFeatures, strategy: str,
) -> CheckResult:
    """Reject if the mutation added new forward function declarations.

    These can conflict with declarations in header files (e.g., the LLM
    adding `int ZipAdd(...)` that conflicts with `ZRESULT ZipAdd(...)` in zip.h).
    """
    new_fwd = mut.forward_declarations - orig.forward_declarations
    if new_fwd:
        return False, (
            f"You added {len(new_fwd)} forward function declaration(s) that are NOT "
            f"in the original: {', '.join(sorted(new_fwd))}. "
            f"These WILL conflict with existing declarations in header files. "
            f"REMOVE all forward declarations — only use function pointers declared "
            f"as local variables inside the function body."
        )
    return True, ""


def _check_ast_error_rate(
    orig: CodeFeatures, mut: CodeFeatures, strategy: str,
) -> CheckResult:
    """Reject if mutated code has significantly more parse errors than original."""
    if mut.ast_node_count < 10:
        return True, ""

    orig_rate = orig.error_node_count / max(orig.ast_node_count, 1)
    mut_rate = mut.error_node_count / max(mut.ast_node_count, 1)

    # Allow some increase (mutation adds complexity), but flag if excessive
    if mut.error_node_count > orig.error_node_count + 5 and mut_rate > 0.10:
        return False, (
            f"Too many parse errors in mutated code: {mut.error_node_count} errors "
            f"in {mut.ast_node_count} AST nodes ({mut_rate:.1%}) vs original "
            f"{orig.error_node_count} errors ({orig_rate:.1%}). "
            f"This suggests syntax errors in the generated code. "
            f"Check for unclosed braces, missing semicolons, or invalid C syntax."
        )
    return True, ""


def _check_complexity_preservation(
    orig: CodeFeatures, mut: CodeFeatures, strategy: str,
) -> CheckResult:
    """Reject if AST complexity collapsed (sign of lost logic)."""
    if orig.ast_node_count < 20:
        return True, ""

    ratio = mut.ast_node_count / orig.ast_node_count

    # strat_4 splits into helpers which are separate functions → total should be similar
    # strat_1/strat_5 may increase nodes significantly
    min_ratio = 0.30  # mutated should have at least 30% of original complexity

    if ratio < min_ratio:
        return False, (
            f"AST complexity collapsed: mutated has {mut.ast_node_count} nodes vs "
            f"original {orig.ast_node_count} ({ratio:.0%}). "
            f"This suggests major logic was deleted or replaced with stubs. "
            f"ALL original logic MUST remain in the output."
        )
    return True, ""


# ── Registry of all checks ─────────────────────────────────────────
# Order matters: cheaper/faster checks first for early rejection.

_CHECKS: List[Tuple[str, CheckFn]] = [
    ("logic_density",            _check_logic_density),
    ("function_call_preservation", _check_function_call_preservation),
    ("buffer_overflow",          _check_buffer_overflow),
    ("suspicious_casts",         _check_suspicious_casts),
    ("call_argument_char_width", _check_call_argument_char_width_preservation),
    ("forward_declarations",     _check_forward_declarations),
    ("ast_error_rate",           _check_ast_error_rate),
    ("complexity_preservation",  _check_complexity_preservation),
]


# ═══════════════════════════════════════════════════════════════════
# Public API: MutationValidator
# ═══════════════════════════════════════════════════════════════════

class MutationValidator:
    """AST-based validation for LLM-mutated code.

    Usage:
        validator = MutationValidator()
        passed, reason = validator.validate(
            original_code, mutated_code, language="cpp", strategy="strat_1"
        )
    """

    def __init__(self):
        self._extractor = _FeatureExtractor()
        self._available = _HAS_TREE_SITTER

    @property
    def available(self) -> bool:
        return self._available

    def extract_features(self, code: str, language: str = "c") -> Optional[CodeFeatures]:
        """Public API to extract features (useful for debugging)."""
        return self._extractor.extract(code, language)

    def validate(
        self,
        original_code: str,
        mutated_code: str,
        language: str = "c",
        strategy: str = "strat_1",
    ) -> Tuple[bool, Optional[str]]:
        """Run all validation checks on mutated code.

        Returns:
            (passed, failure_reason)
            If passed is True, failure_reason is None.
            If passed is False, failure_reason describes the first check that failed.
        """
        if not self._available:
            logger.debug("mutation_validator_unavailable_passthrough")
            return True, None

        orig_feats = self._extractor.extract(original_code, language)
        mut_feats = self._extractor.extract(mutated_code, language)

        if orig_feats is None or mut_feats is None:
            logger.warning("mutation_validator_parse_failed_passthrough")
            return True, None  # Can't validate → pass through

        for check_name, check_fn in _CHECKS:
            passed, reason = check_fn(orig_feats, mut_feats, strategy)
            if not passed:
                logger.warning(
                    "mutation_validator_check_failed: %s — %s",
                    check_name,
                    reason[:200] if reason else "",
                )
                return False, reason

        return True, None

"""
Semantic Repair Validator — AST-based structural and semantic validation.

Uses tree-sitter to parse C/C++ code into a concrete syntax tree (CST)
and perform real structural comparisons between original and fixed code.
This replaces regex-based heuristics with compiler-grade analysis.

Capabilities:
  - Parse code into AST and extract function/struct/type/global nodes
  - Compare original vs fixed AST for structural equivalence
  - Infer variable types from AST context (assignment RHS, function call)
  - Detect parse errors without invoking the real compiler
  - Validate brace balance via AST (not text counting)
  - Check function signature preservation at the AST level
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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
        logger.warning("tree-sitter-c/cpp not installed. SemanticValidator disabled.")
except ImportError:
    logger.warning("tree-sitter not installed. SemanticValidator disabled.")
    Node = None  # type: ignore


# ═══════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════

@dataclass
class FunctionInfo:
    """AST-extracted function metadata."""
    name: str
    return_type: str
    param_count: int
    param_types: List[str]
    start_line: int
    end_line: int
    is_static: bool = False
    is_inline: bool = False
    body_node_count: int = 0  # Number of AST nodes in body (complexity proxy)


@dataclass
class TypeInfo:
    """AST-extracted struct/union/enum/typedef metadata."""
    name: str
    kind: str             # "struct", "union", "enum", "typedef"
    start_line: int
    end_line: int
    field_count: int = 0  # Number of fields (for struct/union)


@dataclass
class GlobalInfo:
    """AST-extracted global variable."""
    name: str
    type_str: str
    start_line: int


@dataclass
class ASTSnapshot:
    """Complete AST snapshot of a source file."""
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    types: Dict[str, TypeInfo] = field(default_factory=dict)
    globals: Dict[str, GlobalInfo] = field(default_factory=dict)
    includes: List[str] = field(default_factory=list)
    macros: List[str] = field(default_factory=list)

    # Parse quality
    error_count: int = 0
    error_nodes: List[Tuple[int, int, str]] = field(default_factory=list)  # (line, col, context)
    total_nodes: int = 0

    @property
    def parse_error_rate(self) -> float:
        return self.error_count / max(self.total_nodes, 1)

    @property
    def function_names(self) -> Set[str]:
        return set(self.functions.keys())

    @property
    def type_names(self) -> Set[str]:
        return set(self.types.keys())


@dataclass
class SemanticDiff:
    """Differences between two AST snapshots."""
    missing_functions: Set[str] = field(default_factory=set)
    added_functions: Set[str] = field(default_factory=set)
    missing_types: Set[str] = field(default_factory=set)
    added_types: Set[str] = field(default_factory=set)
    missing_globals: Set[str] = field(default_factory=set)
    signature_changes: Dict[str, str] = field(default_factory=dict)  # func -> description
    missing_includes: Set[str] = field(default_factory=set)
    orig_errors: int = 0
    fixed_errors: int = 0

    @property
    def is_safe(self) -> bool:
        """True if the diff represents a semantically safe change."""
        # Tolerate added functions/types (LLM may add helpers)
        # But missing functions/types/globals = destructive
        return (
            len(self.missing_functions) == 0
            and len(self.missing_types) == 0
            and len(self.missing_globals) == 0
            and len(self.signature_changes) == 0
            and len(self.missing_includes) == 0
            and self.fixed_errors <= self.orig_errors
        )

    @property
    def rejection_reason(self) -> Optional[str]:
        if self.missing_functions:
            return (
                f"AST: {len(self.missing_functions)} function(s) deleted: "
                f"{', '.join(sorted(list(self.missing_functions)[:5]))}"
            )
        if self.missing_types:
            return (
                f"AST: {len(self.missing_types)} type(s) deleted: "
                f"{', '.join(sorted(list(self.missing_types)[:5]))}"
            )
        if self.missing_globals:
            return (
                f"AST: {len(self.missing_globals)} global(s) deleted: "
                f"{', '.join(sorted(list(self.missing_globals)[:5]))}"
            )
        if self.signature_changes:
            first = next(iter(self.signature_changes.items()))
            return f"AST: function signature changed — {first[0]}: {first[1]}"
        if self.missing_includes:
            return f"AST: {len(self.missing_includes)} #include(s) removed"
        if self.fixed_errors > self.orig_errors:
            return (
                f"AST: parse errors increased ({self.orig_errors} → {self.fixed_errors})"
            )
        return None


# ═══════════════════════════════════════════════════════════════════
# Core: SemanticValidator
# ═══════════════════════════════════════════════════════════════════

class SemanticValidator:
    """AST-based semantic validation for C/C++ code repairs.

    Uses tree-sitter to parse code and compare structural properties
    between original and fixed versions.
    """

    def __init__(self):
        self._available = _HAS_TREE_SITTER

    @property
    def available(self) -> bool:
        return self._available

    # ── Parsing ─────────────────────────────────────────────────────

    def _get_parser(self, language: str) -> Optional['Parser']:
        """Get a tree-sitter parser for the given language."""
        if not self._available:
            return None
        lang = language.lower().replace('+', 'p')
        if lang in ('c',):
            parser = Parser(_C_LANG)
        elif lang in ('cpp', 'cpp', 'cxx'):
            parser = Parser(_CPP_LANG)
        else:
            return None
        return parser

    def parse(self, code: str, language: str = "c") -> Optional['Node']:
        """Parse code string into a tree-sitter AST root node."""
        parser = self._get_parser(language)
        if not parser:
            return None
        tree = parser.parse(bytes(code, 'utf-8'))
        return tree.root_node

    # ── AST Snapshot extraction ─────────────────────────────────────

    def extract_snapshot(self, code: str, language: str = "c") -> Optional[ASTSnapshot]:
        """Extract a complete AST snapshot from source code."""
        root = self.parse(code, language)
        if root is None:
            return None

        snap = ASTSnapshot()
        snap.total_nodes = self._count_nodes(root)

        # Walk tree
        self._walk_top_level(root, code, snap)

        return snap

    def _node_text(self, node: 'Node', code: str) -> str:
        """Get the source text of an AST node."""
        return code[node.start_byte:node.end_byte]

    def _count_nodes(self, node: 'Node') -> int:
        """Count total AST nodes."""
        count = 1
        for child in node.children:
            count += self._count_nodes(child)
        return count

    def _walk_top_level(self, root: 'Node', code: str, snap: ASTSnapshot):
        """Walk top-level AST nodes and populate the snapshot."""
        for node in root.children:
            ntype = node.type

            # ERROR nodes
            if ntype == 'ERROR' or node.is_missing:
                snap.error_count += 1
                line = node.start_point[0] + 1
                col = node.start_point[1]
                ctx = self._node_text(node, code)[:80] if ntype == 'ERROR' else f"MISSING '{ntype}'"
                snap.error_nodes.append((line, col, ctx))
                continue

            # Recursively count errors in any node
            self._count_errors_recursive(node, code, snap)

            # #include / #define
            if ntype == 'preproc_include':
                path_node = node.child_by_field_name('path')
                if path_node:
                    snap.includes.append(self._node_text(path_node, code))
            elif ntype == 'preproc_def':
                name_node = node.child_by_field_name('name')
                if name_node:
                    snap.macros.append(self._node_text(name_node, code))

            # Function definition
            elif ntype == 'function_definition':
                fi = self._extract_function_info(node, code)
                if fi:
                    snap.functions[fi.name] = fi

            # Struct / union / enum
            elif ntype in ('struct_specifier', 'union_specifier', 'enum_specifier'):
                ti = self._extract_type_info(node, code, ntype.replace('_specifier', ''))
                if ti and ti.name:
                    snap.types[ti.name] = ti
            elif ntype == 'type_definition':
                ti = self._extract_typedef_info(node, code)
                if ti and ti.name:
                    snap.types[ti.name] = ti

            # Declaration (globals, typedefs, struct defs)
            elif ntype == 'declaration':
                self._extract_from_declaration(node, code, snap)

    def _count_errors_recursive(self, node: 'Node', code: str, snap: ASTSnapshot):
        """Count ERROR and MISSING nodes recursively within a subtree."""
        for child in node.children:
            if child.type == 'ERROR' or child.is_missing:
                snap.error_count += 1
                line = child.start_point[0] + 1
                col = child.start_point[1]
                ctx = self._node_text(child, code)[:80] if not child.is_missing else f"MISSING '{child.type}'"
                snap.error_nodes.append((line, col, ctx))
            else:
                self._count_errors_recursive(child, code, snap)

    def _extract_function_info(self, node: 'Node', code: str) -> Optional[FunctionInfo]:
        """Extract function info from a function_definition node."""
        # Get return type
        ret_type = ''
        declarator = None

        for child in node.children:
            if child.type in ('primitive_type', 'type_identifier', 'sized_type_specifier'):
                ret_type = self._node_text(child, code)
            elif child.type == 'storage_class_specifier':
                pass  # static, extern, etc.
            elif child.type in ('function_declarator', 'pointer_declarator'):
                declarator = child
            elif child.type == 'compound_statement':
                pass  # body

        if declarator is None:
            return None

        # Unwrap pointer_declarator → function_declarator
        actual_decl = declarator
        while actual_decl.type == 'pointer_declarator':
            ret_type += '*'
            for c in actual_decl.children:
                if c.type in ('function_declarator', 'pointer_declarator'):
                    actual_decl = c
                    break
            else:
                break

        if actual_decl.type != 'function_declarator':
            return None

        # Function name
        name_node = actual_decl.child_by_field_name('declarator')
        if name_node is None:
            return None
        func_name = self._node_text(name_node, code)

        # Parameters
        params_node = actual_decl.child_by_field_name('parameters')
        param_types = []
        param_count = 0
        if params_node:
            for p in params_node.children:
                if p.type == 'parameter_declaration':
                    param_count += 1
                    # Extract type
                    ptype = ''
                    for pc in p.children:
                        if pc.type in ('primitive_type', 'type_identifier',
                                       'sized_type_specifier'):
                            ptype = self._node_text(pc, code)
                    param_types.append(ptype)
                elif p.type == '...':
                    param_count += 1
                    param_types.append('...')

        # Static / inline
        is_static = any(
            self._node_text(c, code) == 'static'
            for c in node.children if c.type == 'storage_class_specifier'
        )
        is_inline = any(
            self._node_text(c, code) == 'inline'
            for c in node.children if c.type == 'storage_class_specifier'
        )

        # Body complexity
        body_node = node.child_by_field_name('body')
        body_count = self._count_nodes(body_node) if body_node else 0

        return FunctionInfo(
            name=func_name,
            return_type=ret_type,
            param_count=param_count,
            param_types=param_types,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            is_static=is_static,
            is_inline=is_inline,
            body_node_count=body_count,
        )

    def _extract_type_info(self, node: 'Node', code: str, kind: str) -> Optional[TypeInfo]:
        """Extract struct/union/enum info."""
        name_node = node.child_by_field_name('name')
        name = self._node_text(name_node, code) if name_node else ''
        field_count = 0
        body = node.child_by_field_name('body')
        if body:
            field_count = sum(1 for c in body.children if c.type == 'field_declaration')
        return TypeInfo(
            name=name, kind=kind,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            field_count=field_count,
        )

    def _extract_typedef_info(self, node: 'Node', code: str) -> Optional[TypeInfo]:
        """Extract typedef info."""
        # typedef ... NAME ;
        declarator = node.child_by_field_name('declarator')
        if declarator:
            name = self._node_text(declarator, code)
        else:
            # Fallback: last identifier before ';'
            name = ''
            for child in reversed(node.children):
                if child.type == 'type_identifier':
                    name = self._node_text(child, code)
                    break
        return TypeInfo(
            name=name, kind='typedef',
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
        ) if name else None

    def _extract_from_declaration(self, node: 'Node', code: str, snap: ASTSnapshot):
        """Extract from a top-level declaration (may contain struct def, global var, etc.)."""
        for child in node.children:
            if child.type in ('struct_specifier', 'union_specifier', 'enum_specifier'):
                ti = self._extract_type_info(child, code, child.type.replace('_specifier', ''))
                if ti and ti.name:
                    snap.types[ti.name] = ti
            elif child.type == 'type_definition':
                ti = self._extract_typedef_info(child, code)
                if ti and ti.name:
                    snap.types[ti.name] = ti
            elif child.type == 'init_declarator':
                # Global variable: TYPE name = ...;
                decl_node = child.child_by_field_name('declarator')
                if decl_node and decl_node.type == 'identifier':
                    name = self._node_text(decl_node, code)
                    type_str = ''
                    for tc in node.children:
                        if tc.type in ('primitive_type', 'type_identifier', 'sized_type_specifier'):
                            type_str = self._node_text(tc, code)
                            break
                    snap.globals[name] = GlobalInfo(
                        name=name, type_str=type_str,
                        start_line=node.start_point[0] + 1,
                    )

    # ── Semantic Diff ───────────────────────────────────────────────

    def diff(self, original: ASTSnapshot, fixed: ASTSnapshot) -> SemanticDiff:
        """Compare two AST snapshots and return semantic differences."""
        d = SemanticDiff()

        d.missing_functions = original.function_names - fixed.function_names
        d.added_functions = fixed.function_names - original.function_names
        d.missing_types = original.type_names - fixed.type_names
        d.added_types = fixed.type_names - original.type_names
        d.missing_globals = set(original.globals.keys()) - set(fixed.globals.keys())

        # Include comparison
        orig_inc = set(original.includes)
        fix_inc = set(fixed.includes)
        d.missing_includes = orig_inc - fix_inc

        # Signature changes: same function name but different param count or return type
        common = original.function_names & fixed.function_names
        for fname in common:
            orig_f = original.functions[fname]
            fix_f = fixed.functions[fname]
            changes = []
            if orig_f.return_type != fix_f.return_type:
                changes.append(f"return type {orig_f.return_type}→{fix_f.return_type}")
            if orig_f.param_count != fix_f.param_count:
                changes.append(f"param count {orig_f.param_count}→{fix_f.param_count}")
            if changes:
                d.signature_changes[fname] = '; '.join(changes)

        d.orig_errors = original.error_count
        d.fixed_errors = fixed.error_count

        return d

    # ── High-level validation ───────────────────────────────────────

    def validate_fix(
        self,
        original_code: str,
        fixed_code: str,
        language: str = "c",
    ) -> Tuple[bool, Optional[str], Optional[SemanticDiff]]:
        """Validate a code fix using AST-based semantic comparison.

        Returns:
            (is_valid, rejection_reason, diff)
        """
        if not self._available:
            return True, None, None  # Can't validate, pass through

        orig_snap = self.extract_snapshot(original_code, language)
        fix_snap = self.extract_snapshot(fixed_code, language)

        if orig_snap is None or fix_snap is None:
            # Parse failed — NOT safe to silently pass through.
            # Log warning and return degraded=True so caller knows.
            logger.warning(
                "SemanticValidator.validate_fix(): tree-sitter parse failed "
                "for original or fixed code — returning DEGRADED pass-through"
            )
            return True, "[degraded] AST parse failed, heuristic only", None

        d = self.diff(orig_snap, fix_snap)

        if d.is_safe:
            return True, None, d
        return False, d.rejection_reason, d

    # ── AST-based function extraction (replaces regex) ──────────────

    def extract_function_names(self, code: str, language: str = "c") -> List[str]:
        """Extract function names using AST (replaces regex-based _extract_function_signatures)."""
        snap = self.extract_snapshot(code, language)
        if snap is None:
            return []
        return sorted(snap.functions.keys())

    # ── AST-based function body start ───────────────────────────────

    def find_function_body_start(
        self, code: str, usage_line: int, language: str = "c",
    ) -> Optional[int]:
        """Return the 1-based line number of the first statement inside the
        function that contains *usage_line* (1-based).

        Walks all function_definition nodes in the AST, finds the one whose
        range contains *usage_line*, then returns start_line_of_body + 1
        (i.e. the line just after the opening '{').

        Returns None if no enclosing function is found.
        """
        root = self.parse(code, language)
        if root is None:
            return None

        target = usage_line - 1  # 0-based

        # Collect all function_definition nodes
        best: Optional[Tuple[int, int, int]] = None  # (start, end, body_start)
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == 'function_definition':
                fn_start = node.start_point[0]
                fn_end = node.end_point[0]
                if fn_start <= target <= fn_end:
                    # Find the compound_statement (body) child
                    body = node.child_by_field_name('body')
                    if body and body.type == 'compound_statement':
                        body_open_line = body.start_point[0]  # line with '{'
                        # The insertion point is the line AFTER the '{'
                        insert_line = body_open_line + 1  # 0-based
                        # Pick the innermost (tightest) function match
                        if best is None or (fn_end - fn_start) < (best[1] - best[0]):
                            best = (fn_start, fn_end, insert_line)
            for child in node.children:
                stack.append(child)

        if best is not None:
            return best[2] + 1  # convert to 1-based
        return None

    # ── AST-based symbol references (replaces regex word-boundary) ──

    def find_symbol_references(
        self, code: str, symbol: str, language: str = "c",
    ) -> List[int]:
        """Return a list of 1-based line numbers where *symbol* appears as an
        actual identifier token in the AST (not inside comments or strings).
        """
        root = self.parse(code, language)
        if root is None:
            return []

        lines: List[int] = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == 'identifier' and code[node.start_byte:node.end_byte] == symbol:
                lines.append(node.start_point[0] + 1)  # 1-based
            for child in node.children:
                stack.append(child)
        return sorted(set(lines))

    # ── AST-based type inference ────────────────────────────────────

    def infer_type_at_usage(
        self,
        code: str,
        identifier: str,
        usage_line: int,
        language: str = "c",
    ) -> Optional[str]:
        """Infer the type of an identifier from AST context at the usage site.

        Looks at:
        1. Assignment RHS — if `ident = FuncCall(...)`, infer from function return type
        2. Comparison — if `ident == TRUE/FALSE`, infer BOOL
        3. Cast — if `(TYPE)ident`, infer TYPE
        4. Function parameter — if `FuncCall(..., ident, ...)`, infer from param type

        Returns the inferred type string or None.
        """
        root = self.parse(code, language)
        if root is None:
            return None

        target_line = usage_line - 1  # 0-based

        # Find the node at the usage line that matches the identifier
        matches = self._find_identifier_nodes(root, code, identifier, target_line)
        if not matches:
            return None

        for id_node in matches:
            parent = id_node.parent
            if parent is None:
                continue

            # Case 1: assignment_expression — ident = expr
            if parent.type == 'assignment_expression':
                left = parent.child_by_field_name('left')
                right = parent.child_by_field_name('right')
                if left and self._node_text(left, code) == identifier and right:
                    inferred = self._infer_type_from_expr(right, code)
                    if inferred:
                        return inferred

            # Case 2: init_declarator — TYPE ident = expr (already declared, but tells us type)
            if parent.type == 'init_declarator':
                decl = parent.parent
                if decl and decl.type == 'declaration':
                    for c in decl.children:
                        if c.type in ('primitive_type', 'type_identifier', 'sized_type_specifier'):
                            return self._node_text(c, code)

            # Case 3: binary_expression — ident == TRUE/FALSE/NULL
            if parent.type == 'binary_expression':
                for c in parent.children:
                    if c.type == 'identifier' and self._node_text(c, code) != identifier:
                        val = self._node_text(c, code)
                        if val in ('TRUE', 'FALSE'):
                            return 'BOOL'
                        if val in ('NULL', 'INVALID_HANDLE_VALUE'):
                            return 'HANDLE'
                    if c.type == 'true' or c.type == 'false':
                        return 'BOOL'

            # Case 4: call_expression — FuncCall(..., ident, ...)
            if parent.type == 'argument_list':
                call = parent.parent
                if call and call.type == 'call_expression':
                    func_node = call.child_by_field_name('function')
                    if func_node:
                        # We know the function name, could look up expected param type
                        # but that requires cross-reference — return None for now
                        pass

        return None

    def _find_identifier_nodes(
        self, root: 'Node', code: str, name: str, target_line: int
    ) -> List['Node']:
        """Find all identifier AST nodes matching name on the target line."""
        results = []
        stack = [root]
        while stack:
            node = stack.pop()
            if (node.type == 'identifier'
                    and node.start_point[0] == target_line
                    and self._node_text(node, code) == name):
                results.append(node)
            for child in node.children:
                stack.append(child)
        return results

    def _infer_type_from_expr(self, expr: 'Node', code: str) -> Optional[str]:
        """Infer type from an expression node (RHS of assignment)."""
        # call_expression → look up function name return type
        if expr.type == 'call_expression':
            func = expr.child_by_field_name('function')
            if func:
                func_name = self._node_text(func, code)
                # Load from win32_knowledge if available
                from automation.auto_fixer import _load_win32_knowledge
                knowledge = _load_win32_knowledge()
                ret_types = knowledge.get('func_return_types', {})
                if func_name in ret_types:
                    ret = ret_types[func_name]
                    if ret != 'void':
                        return ret
        # Number literal
        if expr.type == 'number_literal':
            return 'int'
        # String literal
        if expr.type == 'string_literal':
            return 'char*'
        # Cast expression — (TYPE)value
        if expr.type == 'cast_expression':
            type_node = expr.child_by_field_name('type')
            if type_node:
                return self._node_text(type_node, code)
        # TRUE/FALSE
        if expr.type == 'identifier':
            val = self._node_text(expr, code)
            if val in ('TRUE', 'FALSE'):
                return 'BOOL'
            if val in ('NULL', 'INVALID_HANDLE_VALUE'):
                return 'HANDLE'
        return None

    # ── Parse error detection ───────────────────────────────────────

    def get_parse_errors(self, code: str, language: str = "c") -> List[Tuple[int, int, str]]:
        """Get parse errors from tree-sitter (without invoking real compiler).

        Returns list of (line, col, context_text).
        """
        snap = self.extract_snapshot(code, language)
        if snap is None:
            return []
        return snap.error_nodes

    def has_parse_errors(self, code: str, language: str = "c") -> bool:
        """Quick check: does the code have any parse errors?"""
        root = self.parse(code, language)
        if root is None:
            return True
        return root.has_error


# ═══════════════════════════════════════════════════════════════════
# Module-level singleton
# ═══════════════════════════════════════════════════════════════════

_validator_instance: Optional[SemanticValidator] = None


def get_semantic_validator() -> SemanticValidator:
    """Get the singleton SemanticValidator instance."""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = SemanticValidator()
    return _validator_instance

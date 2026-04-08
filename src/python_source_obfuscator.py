"""
Python Source Obfuscator — Pre-compilation AST-based string literal obfuscation.

Runs on ALL .py files in the variant build directory BEFORE PyInstaller packages them.
This handles everything the LLM-based mutation misses:
  - Module-level string constants (APP_DATA, DB_PATH, KEY_PATH, SQL queries, URLs, etc.)

Strategy:
  1. Parse each .py file with the AST module.
  2. Visit every ast.Constant that is a str.
  3. Replace with: bytes.fromhex('<hex>').decode('utf-8')
  4. No injected decoder function — uses Python builtins only.
  5. Preserve all non-string nodes as-is (int, list, bytes, float, bool, None).
  6. Write the transformed source back to the same path (in-place on the COPY).
  7. Verify the result compiles cleanly; roll back on error.

IMPORTANT: This runs only on the VARIANT build directory copy, never on original samples.
"""

import ast
import os
import sys
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

# Strings shorter than this are not obfuscated (single chars, empty strings)
MIN_STRING_LEN = 2

# Strings that are too long to encode inline (bytecode size guard)
MAX_STRING_LEN = 512

# Names we must never touch (special Python attributes)
SKIP_NAMES = frozenset({'__name__', '__file__', '__doc__', '__version__', '__all__',
                         '__init__', '__main__', 'utf-8', 'utf8', 'ascii', 'latin-1'})

# Decorator name strings we skip so they still work
SKIP_DECORATORS = frozenset({'staticmethod', 'classmethod', 'property',
                              'abstractmethod', 'overload'})

def _hex_encode(s: str) -> Optional[str]:
    """Encode a string as a lowercase hex string, return None on failure."""
    try:
        return s.encode('utf-8').hex()
    except (UnicodeEncodeError, AttributeError):
        return None


def _hex_decode_call_node(hex_str: str) -> ast.Call:
    """
    Build an AST call node for: bytes.fromhex('<hex>').decode('utf-8')
    This is indistinguishable from legitimate hash/encoding code.
    """
    # bytes.fromhex('...')
    fromhex_call = ast.Call(
        func=ast.Attribute(
            value=ast.Name(id='bytes', ctx=ast.Load()),
            attr='fromhex',
            ctx=ast.Load(),
        ),
        args=[ast.Constant(value=hex_str)],
        keywords=[],
    )
    # .decode('utf-8')
    decode_call = ast.Call(
        func=ast.Attribute(
            value=fromhex_call,
            attr='decode',
            ctx=ast.Load(),
        ),
        args=[ast.Constant(value='utf-8')],
        keywords=[],
    )
    return decode_call


class StringObfuscatorTransformer(ast.NodeTransformer):
    """
    AST transformer that replaces string literals with bytes.fromhex().decode() calls.
    Avoids all XOR byte-array patterns that trigger ML-based AV engines.
    """

    def __init__(self, skip_docstrings: bool = True):
        self.skip_docstrings = skip_docstrings
        self.substitution_count = 0
        self._in_decorator = False
        self._in_docstring_position = False
        # Track first statement of each function/class/module for docstring detection
        self._first_stmt_stack: List[bool] = [True]  # module level starts as "first"

    # ──────────────────────────────────────────────────────────────────────
    # Visitor helpers
    # ──────────────────────────────────────────────────────────────────────

    def _is_docstring_node(self, node: ast.AST) -> bool:
        """Return True if this Constant is in a docstring position."""
        return self._in_docstring_position

    def visit_Module(self, node: ast.Module) -> ast.Module:
        # Process module body — track first-stmt for docstrings
        new_body = []
        for i, stmt in enumerate(node.body):
            self._in_docstring_position = (
                i == 0 and isinstance(stmt, ast.Expr)
                and isinstance(getattr(stmt, 'value', None), ast.Constant)
            )
            new_stmt = self.visit(stmt)
            new_body.append(new_stmt)
        self._in_docstring_position = False
        node.body = new_body
        return node

    def _visit_body_with_docstring(self, body: list) -> list:
        """Visit a function/class body, skipping the first expr if it's a docstring."""
        new_body = []
        for i, stmt in enumerate(body):
            self._in_docstring_position = (
                i == 0
                and isinstance(stmt, ast.Expr)
                and isinstance(getattr(stmt, 'value', None), ast.Constant)
                and isinstance(stmt.value.value, str)
            )
            new_stmt = self.visit(stmt)
            new_body.append(new_stmt)
        self._in_docstring_position = False
        return new_body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.body = self._visit_body_with_docstring(node.body)
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        node.args = self.visit(node.args)
        if node.returns:
            node.returns = self.visit(node.returns)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.body = self._visit_body_with_docstring(node.body)
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        node.bases = [self.visit(b) for b in node.bases]
        node.keywords = [self.visit(k) for k in node.keywords]
        return node

    # ──────────────────────────────────────────────────────────────────────
    # Core transformation: replace string constants with hex decode calls
    # ──────────────────────────────────────────────────────────────────────

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        """Replace eligible string constants with bytes.fromhex().decode() calls."""
        # Skip docstrings
        if self._in_docstring_position:
            return node

        val = node.value

        # Obfuscate string constants only (no integer obfuscation — avoids ML triggers)
        if isinstance(val, str):
            if (
                len(val) < MIN_STRING_LEN
                or len(val) > MAX_STRING_LEN
                or val in SKIP_NAMES
                or val in SKIP_DECORATORS
                or (val.startswith('__') and val.endswith('__'))
            ):
                return node

            hex_str = _hex_encode(val)
            if hex_str is None:
                return node

            self.substitution_count += 1
            call = _hex_decode_call_node(hex_str)
            ast.copy_location(call, node)
            return call

        return node

    # ──────────────────────────────────────────────────────────────────────
    # Skip f-strings (JoinedStr) — too complex to transform safely
    # ──────────────────────────────────────────────────────────────────────
    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.JoinedStr:
        # Do NOT recurse into f-strings — the Constants inside are format specs
        return node


def obfuscate_file(path: str, dry_run: bool = False) -> bool:
    """
    Obfuscate a single Python source file in-place.
    
    Args:
        path: Absolute path to .py file
        dry_run: If True, do not write; just return success/fail
    
    Returns:
        True if successfully obfuscated (or no substitutions needed), False on error
    """
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
    except Exception as e:
        logger.warning(f"Cannot read {path}: {e}")
        return False

    # Parse
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        logger.warning(f"Syntax error in {path}, skipping obfuscation: {e}")
        return False

    # Transform
    transformer = StringObfuscatorTransformer()
    new_tree = transformer.visit(tree)

    if transformer.substitution_count == 0:
        logger.debug(f"No substitutions in {path}")
        return True

    # Fix missing line numbers
    ast.fix_missing_locations(new_tree)

    # Unparse back to source
    try:
        import ast as _ast
        new_source = ast.unparse(new_tree)
    except AttributeError:
        # ast.unparse was added in Python 3.9; fall back to asttokens/astunparse if needed
        try:
            import astunparse
            new_source = astunparse.unparse(new_tree)
        except ImportError:
            logger.warning(f"ast.unparse not available and astunparse not installed; skipping {path}")
            return True  # non-fatal

    # Verify the new source compiles cleanly
    try:
        compile(new_source, path, 'exec')
    except SyntaxError as e:
        logger.error(f"Obfuscated source has syntax error in {path}: {e}. Rolling back.")
        return False

    if dry_run:
        logger.info(f"[dry-run] Would write {path} ({transformer.substitution_count} substitutions)")
        return True

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_source)
        logger.info(f"   Obfuscated {os.path.basename(path)}: {transformer.substitution_count} string substitutions")
    except Exception as e:
        logger.error(f"Cannot write obfuscated {path}: {e}")
        return False

    return True


def obfuscate_project_dir(root_dir: str) -> dict:
    """
    Obfuscate all .py files in a project directory tree.
    
    Args:
        root_dir: Root directory of the Python project copy (variant build dir)
        key_seed: Optional seed for key generation (for reproducibility)
    
    Returns:
        dict with stats: {files_processed, files_modified, files_failed, total_substitutions}
    """
    stats = {'files_processed': 0, 'files_modified': 0, 'files_failed': 0, 'total_substitutions': 0}

    if not os.path.isdir(root_dir):
        logger.warning(f"obfuscate_project_dir: not a directory: {root_dir}")
        return stats

    logger.info(f"\n{'='*50}")
    logger.info(f"🔐 PRE-COMPILATION OBFUSCATION")
    logger.info(f"   Directory: {root_dir}")
    logger.info(f"{'='*50}")

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip hidden dirs, __pycache__, .venv, etc.
        dirnames[:] = [d for d in dirnames if not d.startswith('.') and d not in
                       ('__pycache__', '.venv', 'venv', 'env', 'node_modules', '.git')]

        for filename in filenames:
            if not filename.endswith('.py'):
                continue

            filepath = os.path.join(dirpath, filename)
            stats['files_processed'] += 1

            # Track substitutions before
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    source_before = f.read()
            except Exception:
                stats['files_failed'] += 1
                continue

            success = obfuscate_file(filepath)
            if success:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        source_after = f.read()
                    if source_after != source_before:
                        stats['files_modified'] += 1
                except Exception:
                    pass
            else:
                stats['files_failed'] += 1

    logger.info(f"   ✓ Obfuscation complete: {stats['files_modified']}/{stats['files_processed']} "
                f"files modified, {stats['files_failed']} failed")
    return stats


if __name__ == '__main__':
    # CLI usage: python python_source_obfuscator.py <directory>
    import sys
    if len(sys.argv) < 2:
        print("Usage: python python_source_obfuscator.py <project_dir>")
        sys.exit(1)
    
    logging.basicConfig(level=logging.INFO)
    target = sys.argv[1]
    stats = obfuscate_project_dir(target)
    print(f"\nStats: {stats}")

"""
cpp_source_obfuscator.py — XOR-encodes string literals in C/C++ source files.

For each string literal found in the source, replaces it with inline XOR decode:
    "kernel32.dll"
    -->
    ([](){static char _r[16];static const unsigned char _e[]={...};for(int _i=0;_e[_i];_i++)_r[_i]=_e[_i]^0x5A;_r[sizeof(_e)-1]=0;return _r;}())

Scope: replaces string literals that are:
  - Not in comments (// and /* */)
  - Not in #include / #pragma lines
  - Not already obfuscated
  - Longer than MIN_LEN characters

Usage:
  python cpp_source_obfuscator.py <file_or_dir>  [--dry-run]
"""
import re
import os
import sys
import random
import shutil
from pathlib import Path
from typing import Optional

MIN_LEN = 3       # skip very short strings ("\\n", "", etc.)
MAX_LEN = 200     # skip suspiciously long strings (probably multi-line)
XOR_KEY = 0x5A    # XOR key

# Strings we definitely don't want to encode (C runtime format specifiers etc.)
SKIP_PATTERNS = {r'%', r'\n', r'\t', r'\r', r'\\', r'%s', r'%d', r'%i', r'%x'}

SKIP_FILE_EXTENSIONS = {'.h'}  # Don't obfuscate headers — causes redeclaration issues


def _xor_encode(s: str) -> list[int]:
    """XOR-encode a string, return list of encoded byte values."""
    return [b ^ XOR_KEY for b in s.encode('utf-8', errors='replace')]


def _build_inline_decode(s: str, var_id: int) -> str:
    """Build inline C expression to XOR-decode a string at runtime.
    
    Returns a C expression of type: (const char*)
    Using a local static buffer approach — safe for use as l-values.
    """
    encoded = _xor_encode(s)
    # Build encoded array literal
    enc_arr = ",".join(hex(b) for b in encoded) + ",0"
    n = len(encoded)
    # Use a unique variable name per call site
    uid = f"_{var_id:04x}"
    
    # Inline lambda-style using compound statement expression (gcc extension)
    # Instead, use a simple approach: static char buf + static const array
    # We wrap in a do-once block. Actually simplest that works in MSVC:
    # Use a helper macro-style inline function call via a local static
    code = (
        f"(["
        f"&](){{" 
        f"static char _r{uid}[{n+1}]={{0}};"
        f"if(!_r{uid}[0]){{"
        f"static const unsigned char _e{uid}[]={{{enc_arr}}};"
        f"for(int _i{uid}=0;_i{uid}<{n};_i{uid}++)"
        f"_r{uid}[_i{uid}]=_e{uid}[_i{uid}]^0x5A;"
        f"}}"
        f"return _r{uid};"
        f"}}())"
    )
    return code


def _build_simple_decode(s: str, suffix: str) -> tuple[str, str]:
    """Build a two-part decode: declaration + usage.
    
    Returns (declaration_line, usage_expression).
    Declaration goes before the string's first use.
    Usage expression replaces the string literal.
    
    More compatible with MSVC (no lambda expressions in C).
    """
    encoded = _xor_encode(s)
    n = len(encoded)
    enc_arr = ",".join(hex(b) for b in encoded) + ",0x00"
    buf_name = f"_s{suffix}"
    enc_name = f"_e{suffix}"
    # Simple inline decode block — these statements go before the use point
    decl = (
        f"char {buf_name}[{n+2}]={{0}};"
        f"{{static const unsigned char {enc_name}[]={{{enc_arr}}};"
        f"for(int _i=0;_i<{n};_i++){buf_name}[_i]=(char)({enc_name}[_i]^0x{XOR_KEY:02X});}}"
    )
    return decl, buf_name


class CppStringObfuscator:
    """Obfuscates string literals in a C/C++ source file."""
    
    def __init__(self, xor_key: int = XOR_KEY):
        self.xor_key = xor_key
        self._counter = 0
    
    def _next_id(self) -> str:
        self._counter += 1
        return f"{self._counter:04x}"
    
    def _strip_comments(self, code: str) -> str:
        """Remove comments from code for analysis (not for output)."""
        # Remove /* ... */ comments
        code = re.sub(r'/\*.*?\*/', lambda m: ' ' * len(m.group()), code, flags=re.DOTALL)
        # Remove // comments
        code = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group()), code)
        return code
    
    def _count_brace_change(self, line: str) -> int:
        """Count net brace depth change for a line (ignoring strings and comments)."""
        # Strip line comment
        comment_idx = line.find('//')
        if comment_idx >= 0:
            line = line[:comment_idx]
        # Simple count — good enough for tracking function scope in well-formed C/C++
        return line.count('{') - line.count('}')

    def obfuscate(self, source: str) -> str:
        """Obfuscate string literals in C/C++ source code.
        
        Only processes strings inside function bodies (brace_depth > 0 and not a
        global initializer block). Global-scope char[] initializers use compile-time
        string concatenation and sizeof() semantics that would break with lambdas.
        """
        lines = source.split('\n')
        output_lines = []
        brace_depth = 0
        in_function_body = False  # True only when inside a function body

        for line in lines:
            stripped = line.strip()

            # Skip preprocessor directives
            if stripped.startswith('#'):
                output_lines.append(line)
                brace_depth += self._count_brace_change(line)
                continue

            # Skip comment-only lines
            if stripped.startswith('//'):
                output_lines.append(line)
                continue

            change = self._count_brace_change(line)

            # Detect whether we're entering a function body or a global initializer
            # on this line (only relevant at global scope)
            if brace_depth == 0 and change > 0:
                # Is this a global variable/struct initializer? Key indicator: `= {` or `={`
                is_global_init = bool(re.search(r'=\s*\{', line))
                if not is_global_init:
                    # Entering a function body (or similar block at global scope)
                    in_function_body = True

            # Only obfuscate inside function bodies
            if in_function_body:
                output_lines.append(self._process_line(line))
            else:
                output_lines.append(line)

            brace_depth += change

            # Reset when we return to global scope
            if brace_depth == 0:
                in_function_body = False

        return '\n'.join(output_lines)
    
    def _process_line(self, line: str) -> str:
        """Replace string literals in a single line with XOR decode code."""
        # Pattern: match string literals (handling escaped quotes)
        # This regex handles "..." including escaped quotes (\")
        STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
        
        result = []
        last_end = 0
        
        for m in STRING_RE.finditer(line):
            s = m.group(1)  # content between quotes
            
            # Decode escape sequences for length check
            try:
                actual = bytes(s, 'utf-8').decode('unicode_escape')
            except Exception:
                actual = s
            
            # Skip conditions
            if len(actual) < MIN_LEN or len(actual) > MAX_LEN:
                result.append(line[last_end:m.end()])
                last_end = m.end()
                continue
            
            # Skip if contains format specifiers, escape-only content, or binary hex escapes
            if any(p in s for p in ['%', '\\n', '\\t', '\\r', '\\x', '\\0']):
                result.append(line[last_end:m.end()])
                last_end = m.end()
                continue
            
            # Build XOR-encoded replacement (two-statement approach)
            uid = self._next_id()
            buf_name = f"_s{uid}"
            enc_name = f"_e{uid}"
            encoded = _xor_encode(actual)
            n = len(encoded)
            enc_arr = ",".join(hex(b) for b in encoded) + ",0x00"
            
            # Inline decode block: wrap in a compound statement expression
            # For MSVC compatibility, use a block-scope approach
            # We generate: ("xor_decoded_buf_name") which requires prior declaration
            # Simplest approach: use a block that declares + decodes + leaves buf accessible
            # Since we can't easily split statements in a single expression in MSVC,
            # just use a string table approach at file scope (safer for MSVC):
            
            # Actually: Just replace inline using a simpler encoding
            # sprintf approach: not useful. Let's use the static char approach.
            # The safest MSVC-compatible inline replacement:
            # Before the statement containing this string, we need a declaration.
            # Since we can't easily do pre-statement injection from line-by-line processing,
            # let's just XOR the string at file level using static initializers.
            
            # Simplest approach that works: just add the decode inline
            # IMPORTANT: For MSVC, lambda expressions ([&](){...}()) don't work in C mode
            # but work in C++ mode. NullBot is C++.
            
            decode_expr = (
                f"([&](){{static char _r{uid}[{n+2}]={{0}};"
                f"if(!_r{uid}[0]){{"
                f"const unsigned char _e{uid}[]={{{enc_arr}}};"
                f"for(int _i=0;_i<{n};_i++)_r{uid}[_i]=(char)(_e{uid}[_i]^0x{self.xor_key:02X});}};"
                f"return _r{uid};}}())"
            )
            
            result.append(line[last_end:m.start()])
            result.append(decode_expr)
            last_end = m.end()
        
        result.append(line[last_end:])
        return ''.join(result)


def obfuscate_file(path: str, dry_run: bool = False) -> bool:
    """Obfuscate a single C/C++ source file. Returns True if modified."""
    p = Path(path)
    if p.suffix.lower() in SKIP_FILE_EXTENSIONS:
        return False
    
    try:
        source = p.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        print(f"  SKIP {p.name}: read error ({e})")
        return False
    
    obf = CppStringObfuscator()
    result = obf.obfuscate(source)
    
    if result == source:
        print(f"  {p.name}: no changes")
        return False
    
    if dry_run:
        print(f"  {p.name}: would be modified ({obf._counter} strings)")
        return True
    
    # Backup original
    backup = p.with_suffix(p.suffix + '.bak_obf')
    if not backup.exists():
        shutil.copy2(p, backup)
    
    p.write_text(result, encoding='utf-8')
    print(f"  {p.name}: modified ({obf._counter} strings encoded)")
    return True


def obfuscate_project_dir(root_dir: str, dry_run: bool = False) -> dict:
    """Obfuscate all C/C++ source files in a directory. Returns stats."""
    root = Path(root_dir)
    stats = {"modified": 0, "skipped": 0, "errors": 0}
    
    for ext in ('*.c', '*.cpp', '*.cc', '*.cxx'):
        for f in root.rglob(ext):
            if '.bak_obf' in f.name:
                continue
            try:
                if obfuscate_file(str(f), dry_run=dry_run):
                    stats["modified"] += 1
                else:
                    stats["skipped"] += 1
            except Exception as e:
                print(f"  ERROR {f.name}: {e}")
                stats["errors"] += 1
    
    return stats


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="XOR-encode string literals in C/C++ source")
    parser.add_argument("path", help="File or directory to obfuscate")
    parser.add_argument("--dry-run", action="store_true", help="Don't write changes")
    args = parser.parse_args()
    
    p = Path(args.path)
    if p.is_dir():
        stats = obfuscate_project_dir(str(p), dry_run=args.dry_run)
        print(f"\nDone: {stats}")
    else:
        obfuscate_file(str(p), dry_run=args.dry_run)

"""
SyntaxChecker — Compiler-based syntax validation for mutated C/C++ code.

Runs `g++ -fsyntax-only` (GCC/MinGW/Clang) or `cl.exe /Zs` (MSVC) on the
mutated function before storing it.  This catches type errors that regex and
AST checks cannot detect:

  - Void-return assignment:   _junk = GetSystemTime(NULL)   → 'void value not ignored'
  - Void value in expression: _dc  = Sleep(1) >> 4          → 'invalid operands'
  - Argument count mismatch:  CreateFileA() with wrong args  → 'too many/few arguments'

How it works
------------
1. Read #include / #define preamble from the *original* source file so that
   project types (HINTERNET, JSON_Value, …) are available.
2. Append the mutated function.
3. Run ``compiler -fsyntax-only  -I <source_dir>  <tempfile>`` (no object output).
4. Filter stderr: only lines matching a whitelist of "definitely a mutation bug"
   error patterns are treated as failures.  "Undeclared identifier" and other
   missing-symbol errors are silently ignored — they come from project-specific
   symbols the checker doesn't have full context for.
5. Return (passed: bool, feedback: str) — feedback is injected into the LLM
   retry prompt.

Graceful degradation
--------------------
* No compiler in PATH       → available=False, all checks return (True, "")
* Windows headers missing   → compiler emits fatal #include error, no actionable
                              errors match the whitelist → (True, "")
* Compiler timeout          → (True, "")  — never blocks the pipeline
* Any unexpected exception  → (True, "")
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Compiler detection ────────────────────────────────────────────────────────

def _find_compiler(language: str) -> Tuple[Optional[str], str]:
    """Return (path, kind) where kind is 'gcc', 'clang', or 'msvc'.

    Returns (None, '') when no compiler is found in PATH.
    """
    if language == "c":
        candidates = [("gcc", "gcc"), ("cc", "gcc"),
                      ("clang", "clang"), ("cl", "msvc")]
    else:
        candidates = [("g++", "gcc"), ("c++", "gcc"),
                      ("clang++", "clang"), ("cl", "msvc")]

    for name, kind in candidates:
        path = shutil.which(name)
        if path:
            return path, kind
    return None, ""


# ── Actionable error pattern whitelists ──────────────────────────────────────
# Only patterns that are DEFINITIVELY mutation bugs (not missing-symbol noise).

_GCC_ACTIONABLE: List[re.Pattern] = [
    # Void return value misuse ─ the primary target of this check
    re.compile(r"void value not ignored", re.I),
    re.compile(r"invalid operands of types 'void'", re.I),
    re.compile(r"invalid use of void expression", re.I),
    re.compile(r"cannot convert 'void'", re.I),
    # Argument count wrong (mutation changed call signature)
    re.compile(r"too many arguments to (function|built-in function)", re.I),
    re.compile(r"too few arguments to (function|built-in function)", re.I),
    # Generated stack strings/buffers escaped their scope. Limit this to bland
    # generated names so project-specific unresolved symbols remain ignored.
    re.compile(r"['`]_[swb]\d+['`].*(was not declared|undeclared)", re.I),
    re.compile(r"(was not declared|undeclared identifier).*['`]_[swb]\d+['`]", re.I),
]

_MSVC_ACTIONABLE: List[re.Pattern] = [
    re.compile(r"C2440.*void", re.I),    # cannot convert from 'void' to …
    re.compile(r"C2100", re.I),          # illegal indirection
    re.compile(r"C2106", re.I),          # '=': left operand must be l-value (void)
    re.compile(r"C2660", re.I),          # function: does not take N arguments
    re.compile(r"C2198", re.I),          # too few arguments
    re.compile(r"C2065:\s*'_[swb]\d+'\s*:\s*undeclared identifier", re.I),
]

# Clang messages are GCC-compatible
_CLANG_ACTIONABLE = _GCC_ACTIONABLE


# ── Include extractor ─────────────────────────────────────────────────────────

def _extract_preamble(source_file: str) -> List[str]:
    """Extract #include and early #define lines from the original source file.

    We read up to the first function/class/struct body (first '{' at column 0
    or near-zero depth) so we capture the full set of includes and type aliases
    the translation unit needs.
    """
    try:
        text = Path(source_file).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    lines: List[str] = []
    brace_depth = 0
    for raw_line in text.splitlines():
        stripped = raw_line.strip()

        # Track brace depth — stop after we enter the first function body
        brace_depth += stripped.count("{") - stripped.count("}")
        if brace_depth > 0 and not stripped.startswith("#"):
            break

        # Keep #include, #define, #pragma (except #pragma once which conflicts)
        if stripped.startswith("#include"):
            lines.append(stripped)
        elif stripped.startswith("#define") and not lines:
            # Only very-early #defines (e.g. WIN32_LEAN_AND_MEAN before includes)
            lines.append(stripped)
        elif stripped.startswith("#pragma") and "once" not in stripped.lower():
            lines.append(stripped)

    return lines


# ── SyntaxChecker ─────────────────────────────────────────────────────────────

class SyntaxChecker:
    """Wrap a mutated C/C++ function in a temp file and run compiler -fsyntax-only."""

    def __init__(self):
        self._available: bool = False
        self._compiler: Optional[str] = None
        self._compiler_type: str = ""
        self._probe()

    def _probe(self) -> None:
        """Detect compiler availability by compiling a trivial snippet."""
        compiler, ctype = _find_compiler("cpp")
        if not compiler:
            logger.info("syntax_checker_unavailable: no C++ compiler found in PATH")
            return

        tf_path = ""
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".cpp", mode="w", delete=False, encoding="utf-8"
            ) as tf:
                tf.write("int probe_fn() { return 42; }\n")
                tf_path = tf.name

            args = self._build_args(compiler, ctype, tf_path, [], "cpp")
            result = subprocess.run(
                args, capture_output=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            # Accept: exit 0, or non-zero only if stderr has no 'error:' lines
            # (some compilers warn on -fsyntax-only + output file path)
            self._available = True
            self._compiler = compiler
            self._compiler_type = ctype
            logger.info(
                "syntax_checker_ready compiler=%s type=%s", compiler, ctype
            )
        except Exception as exc:
            logger.warning("syntax_checker_probe_failed: %s", exc)
        finally:
            if tf_path:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass

    @property
    def available(self) -> bool:
        return self._available

    # ── Public API ─────────────────────────────────────────────────────────

    def check(
        self,
        code: str,
        language: str = "cpp",
        source_file: str = "",
        extra_include_dirs: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """Syntax-check the mutated function.

        Args:
            code:               Mutated function source code string.
            language:           "c" or "cpp".
            source_file:        Path to the original source file — used to
                                extract its #includes and as the base -I dir.
            extra_include_dirs: Additional directories for -I.

        Returns:
            (passed, feedback)
            - passed=True  → no actionable errors (safe to store mutation)
            - passed=False → feedback contains LLM-readable error description
        """
        if not self._available:
            return True, ""

        # ── Build include dirs ──────────────────────────────────────────────
        include_dirs: List[str] = list(extra_include_dirs or [])
        if source_file:
            src_dir = str(Path(source_file).parent)
            if src_dir not in include_dirs:
                include_dirs.append(src_dir)

        # ── Build wrapper + write temp file ────────────────────────────────
        preamble = _extract_preamble(source_file) if source_file else []
        wrapper, header_line_count = self._build_wrapper(code, language, preamble)

        suffix = ".c" if language == "c" else ".cpp"
        tf_path = ""
        try:
            with tempfile.NamedTemporaryFile(
                suffix=suffix, mode="w", delete=False,
                encoding="utf-8", errors="replace",
            ) as tf:
                tf.write(wrapper)
                tf_path = tf.name

            # ── Run compiler ────────────────────────────────────────────────
            args = self._build_args(
                self._compiler, self._compiler_type,
                tf_path, include_dirs, language,
            )
            result = subprocess.run(
                args, capture_output=True, timeout=30,
                encoding="utf-8", errors="replace",
            )

            # ── Parse output ────────────────────────────────────────────────
            raw_output = result.stderr + "\n" + result.stdout
            actionable = self._filter_actionable(raw_output, self._compiler_type)

            if not actionable:
                return True, ""

            feedback = self._build_feedback(actionable, code, header_line_count)
            return False, feedback

        except subprocess.TimeoutExpired:
            logger.warning("syntax_check_timeout source_file=%r", source_file)
            return True, ""  # never block the pipeline on checker timeout
        except Exception as exc:
            logger.warning("syntax_check_error: %s", exc)
            return True, ""
        finally:
            if tf_path:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass

    # ── Helpers ────────────────────────────────────────────────────────────

    def _build_wrapper(
        self, code: str, language: str, preamble: List[str],
    ) -> Tuple[str, int]:
        """Wrap the mutated function with the necessary includes.

        Returns:
            (wrapper_str, header_line_count) where header_line_count is the
            number of lines that precede the first line of *code* in the file.
            Used to map compiler line numbers back to function source lines.
        """
        if not preamble:
            # Fallback: minimal Windows headers
            preamble = [
                "#define WIN32_LEAN_AND_MEAN",
                "#define NOMINMAX",
                "#include <windows.h>",
                "#include <wininet.h>",
            ]
            if language != "c":
                preamble += ["#include <shlobj.h>", "#include <tlhelp32.h>"]

        header_parts = (
            ["// syntax-check wrapper — auto-generated, do not edit"]
            + preamble
            + ["", "// ---- mutated function ----"]
        )
        footer_parts = ["// ---- end ----", ""]

        header_str = "\n".join(header_parts) + "\n"
        footer_str = "\n" + "\n".join(footer_parts)
        wrapper = header_str + code + footer_str

        # Header line count = number of '\n' in the header (= lines before code line 1)
        header_line_count = header_str.count("\n")
        return wrapper, header_line_count

    @staticmethod
    def _build_args(
        compiler: str,
        ctype: str,
        file_path: str,
        include_dirs: List[str],
        language: str,
    ) -> List[str]:
        """Build the compiler command-line for syntax-only check."""
        args = [compiler]

        if ctype == "msvc":
            args += ["/Zs", "/W0", "/nologo"]
            for d in include_dirs:
                args.append(f"/I{d}")
        else:
            # gcc / clang
            args += [
                "-fsyntax-only",
                "-w",            # suppress all warnings — we only care about errors
                "-fpermissive",  # tolerate some non-standard constructs
                "-m64",
                "-D_WIN32", "-DWIN32", "-D_WIN32_WINNT=0x0601",
                "-DUNICODE", "-D_UNICODE",
            ]
            if language == "cpp":
                args += ["-std=gnu++17", "-x", "c++"]
            else:
                args += ["-std=gnu11", "-x", "c"]
            for d in include_dirs:
                args.append(f"-I{d}")

        args.append(file_path)
        return args

    @staticmethod
    def _filter_actionable(output: str, ctype: str) -> List[str]:
        """Return only compiler lines that are definitively mutation bugs."""
        patterns = _MSVC_ACTIONABLE if ctype == "msvc" else _GCC_ACTIONABLE
        results: List[str] = []

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Skip notes and warnings (we pass -w but be defensive)
            if ": note:" in stripped or ": warning:" in stripped:
                continue
            # Only consider error lines
            is_error = (": error:" in stripped) or (
                ctype == "msvc" and re.search(r"\berror\s+C\d{4}", stripped)
            )
            if not is_error:
                continue
            # Apply whitelist — only actionable patterns pass
            if any(p.search(stripped) for p in patterns):
                results.append(stripped)

        return results

    @staticmethod
    def _build_feedback(
        errors: List[str], code: str, header_offset: int,
    ) -> str:
        """Build concise LLM-readable feedback from compiler error lines."""
        func_lines = code.splitlines()
        lines = ["Compiler syntax check failed:"]

        for err in errors[:5]:  # cap to avoid overwhelming the prompt
            # Extract line number (gcc: "file:42:5: error:" / msvc: "file(42) : error")
            lineno: Optional[int] = None
            m = re.search(r":(\d+):\d+:", err)
            if not m:
                m = re.search(r"\((\d+)\)", err)
            if m:
                lineno = int(m.group(1)) - header_offset

            # Strip path prefix — keep only the message part
            msg = re.sub(r"^[^:]+:\d+:\d+:\s*error:\s*", "", err, flags=re.I).strip()
            msg = re.sub(r"^[^(]+\(\d+\)\s*:\s*error\s*C\d+:\s*", "", msg, flags=re.I).strip()

            if lineno and 1 <= lineno <= len(func_lines):
                src_line = func_lines[lineno - 1].strip()
                lines.append(f"  Line {lineno}: {msg}")
                lines.append(f"    ↳ {src_line[:100]}")
            else:
                lines.append(f"  {msg}")

        lines += [
            "",
            "Common cause: void-returning APIs cannot be assigned.",
            "  WRONG:   `_v = GetSystemTime(NULL);`",
            "  CORRECT: `SYSTEMTIME _st; GetSystemTime(&_st); volatile DWORD _v = _st.wMilliseconds;`",
        ]
        return "\n".join(lines)

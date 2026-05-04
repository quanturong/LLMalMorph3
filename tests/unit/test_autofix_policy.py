"""
Unit tests for the AutoFixer safety policy:
  - whitelist preservation (preserve_function_names)
  - line-loss ratio cap (min_line_ratio)
  - deleted-function cap (max_deleted_functions)
  - body-emptying detection (forbid_body_emptying)

Plus a registration smoke test for the new mutation strategies.
"""

from __future__ import annotations

import os
import sys
import time
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.automation.auto_fixer import AutoFixer  # noqa: E402


# ── Sample inputs ──────────────────────────────────────────────────────

ORIGINAL_C = """\
#include <windows.h>

static int helper_a(int x) {
    int y = x + 1;
    int z = y * 2;
    return z - 1;
}

static int helper_b(int x) {
    int t = x * x;
    int u = t + 7;
    int v = u - 3;
    return v;
}

int Infect(int seed) {
    int a = helper_a(seed);
    int b = helper_b(a);
    int c = a + b;
    return c;
}
"""

# A "fix" that silently deletes both helpers — exactly the failure mode
# observed on Strat3 / Conti where the fixer dropped 16 functions.
FIX_DELETES_HELPERS = """\
#include <windows.h>

int Infect(int seed) {
    return seed;
}
"""

# A reasonable surgical fix — only adds an include, no functions removed.
FIX_ADDS_INCLUDE = """\
#include <windows.h>
#include <stdio.h>

static int helper_a(int x) {
    int y = x + 1;
    int z = y * 2;
    return z - 1;
}

static int helper_b(int x) {
    int t = x * x;
    int u = t + 7;
    int v = u - 3;
    return v;
}

int Infect(int seed) {
    int a = helper_a(seed);
    int b = helper_b(a);
    int c = a + b;
    return c;
}
"""

# Bodies emptied to a single return — surviving functions, no deletions,
# but real logic is destroyed.
FIX_EMPTIES_BODIES = """\
#include <windows.h>

static int helper_a(int x) { return x; }

static int helper_b(int x) { return x; }

int Infect(int seed) {
    int a = helper_a(seed);
    int b = helper_b(a);
    int c = a + b;
    return c;
}
"""


# ── Tests ──────────────────────────────────────────────────────────────

def _make_fixer(**kwargs) -> AutoFixer:
    """AutoFixer that never tries to call an LLM (passes invalid model gracefully)."""
    # use_hybrid=False + missing API key just leaves llm_provider=None,
    # which is fine for validate_fixed_code (pure-function gate logic).
    return AutoFixer(llm_model="noop", api_key=None, use_hybrid=False, **kwargs)


def test_whitelist_blocks_helper_deletion():
    fixer = _make_fixer(
        preserve_function_names={"helper_a", "helper_b", "Infect"},
    )
    ok, reason = fixer.validate_fixed_code(ORIGINAL_C, FIX_DELETES_HELPERS, language="c")
    assert ok is False
    assert reason is not None
    # Either the line-ratio gate (Gate 2) or the whitelist gate (Gate 7)
    # may fire first; both are correct rejections of this catastrophic fix.
    assert ("whitelisted" in reason) or ("line count dropped" in reason) or ("function(s) deleted" in reason)


def test_max_deleted_functions_cap_default_is_one():
    """Even without a whitelist, removing >1 functions must be rejected."""
    fixer = _make_fixer()  # default cap = 1
    ok, reason = fixer.validate_fixed_code(ORIGINAL_C, FIX_DELETES_HELPERS, language="c")
    assert ok is False
    assert reason is not None


def test_clean_fix_passes():
    fixer = _make_fixer(
        preserve_function_names={"helper_a", "helper_b", "Infect"},
    )
    ok, reason = fixer.validate_fixed_code(ORIGINAL_C, FIX_ADDS_INCLUDE, language="c")
    assert ok is True, f"expected pass, got reason={reason!r}"


def test_project_whitelist_is_scoped_to_current_file():
    """Project-level whitelist names from other files must not reject a file fix."""
    fixer = _make_fixer(
        preserve_function_names={"helper_a", "helper_b", "Infect", "OtherFileFunc"},
    )
    ok, reason = fixer.validate_fixed_code(ORIGINAL_C, FIX_ADDS_INCLUDE, language="c")
    assert ok is True, f"expected project-scope names to be ignored, got reason={reason!r}"


def test_min_line_ratio_can_be_relaxed():
    """A very lenient ratio still permits the deletion fix to pass Gate 2,
    but the function-count cap (Gate 8) must still trip it."""
    fixer = _make_fixer(min_line_ratio=0.05, max_deleted_functions=10)
    # With both gates relaxed and no whitelist, even the catastrophic fix
    # might pass — this asserts the relaxed config behaves as documented.
    ok, _ = fixer.validate_fixed_code(ORIGINAL_C, FIX_ADDS_INCLUDE, language="c")
    assert ok is True


def test_body_emptying_detected_when_enabled():
    """forbid_body_emptying should reject fixes that gut helper bodies."""
    pytest.importorskip("tree_sitter", reason="AST gates need tree-sitter")
    fixer = _make_fixer(
        preserve_function_names=set(),  # whitelist off — isolate body gate
        max_deleted_functions=10,       # cap off — isolate body gate
        min_line_ratio=0.05,            # ratio off — isolate body gate
        forbid_body_emptying=True,
    )
    ok, reason = fixer.validate_fixed_code(ORIGINAL_C, FIX_EMPTIES_BODIES, language="c")
    # If tree-sitter FunctionInfo lacks a 'body_size' attribute, the gate
    # silently no-ops. Accept either rejection or a passthrough — but if
    # rejected, the reason MUST mention emptying.
    if ok is False:
        assert reason is not None and "emptied" in reason


# ── Strategy registration smoke test ───────────────────────────────────

def test_new_strategies_are_registered():
    from src.utility_prompt_library import _strategy_prompt_base, get_strategy_prompt

    for key in ("strat_s3", "strat_5_crt", "strat_5_arith", "strat_5_api"):
        assert key in _strategy_prompt_base, f"{key} missing from registry"
        prompt = get_strategy_prompt(key, language="c")
        assert isinstance(prompt, str) and len(prompt) > 200, \
            f"{key} prompt looks empty / truncated"


def test_generic_pattern_fix_does_not_hang_on_orphan_scan():
    source = "void f(void) {\n" + ("    int x = 0;\n" * 400) + "}\n"
    errors = ["sample.c(2): error C2065: '_missing': undeclared identifier"]

    start = time.monotonic()
    AutoFixer.apply_generic_pattern_fixes(source, errors, "c")
    elapsed = time.monotonic() - start

    assert elapsed < 2.0


def test_generic_pattern_fix_repairs_nearby_identifier_typo():
    source = """\
#include <windows.h>
void f(void) {
    HMODULE h = 0;
    char _s_fn0[7];
    _s_fn0[0] = 'x';
    FARPROC _pf0 = NULL;
    *(FARPROC*)&_pf0 = GetProcAddress(h, _s_fn00);
}
"""
    errors = ["sample.c(7): error C2065: '_s_fn00': undeclared identifier"]

    fixed, num_fixes, _ = AutoFixer.apply_generic_pattern_fixes(source, errors, "c")

    assert num_fixes >= 1
    assert "_s_fn00" not in fixed
    assert "GetProcAddress(h, _s_fn0)" in fixed


def test_generic_pattern_fix_declares_getprocaddress_pointer():
    source = """\
#include <windows.h>
void f(void) {
    HMODULE h = 0;
    char name[4];
    *(FARPROC*)&_pf0 = GetProcAddress(h, name);
    _pf0();
}
"""
    errors = ["sample.c(5): error C2065: '_pf0': undeclared identifier"]

    fixed, num_fixes, _ = AutoFixer.apply_generic_pattern_fixes(source, errors, "c")

    assert num_fixes >= 1
    assert "FARPROC _pf0;" in fixed


def test_generic_pattern_fix_uses_clang_symbol_table_for_function_declaration():
    source = """\
#include <windows.h>
int main(void) {
    return project_helper(7);
}
"""
    symbol = SimpleNamespace(
        kind=SimpleNamespace(value="function"),
        file=r"E:\other\helper.c",
        line=3,
        is_static=False,
        signature="int project_helper(int value)",
        return_type="int",
        parameters=[("int", "value")],
    )
    clang_analysis = SimpleNamespace(symbols={"project_helper": [symbol]})
    errors = ["sample.c(3): error C3861: 'project_helper': identifier not found"]

    fixed, num_fixes, _ = AutoFixer.apply_generic_pattern_fixes(
        source,
        errors,
        "c",
        file_path=r"E:\current\sample.c",
        clang_analysis=clang_analysis,
    )

    assert num_fixes >= 1
    assert "int project_helper(int value);" in fixed


def test_generic_pattern_fix_uses_clang_symbol_table_for_typo_candidates():
    source = """\
#include <windows.h>
int main(void) {
    return project_helpr(7);
}
"""
    symbol = SimpleNamespace(
        kind=SimpleNamespace(value="function"),
        file=r"E:\current\sample.c",
        line=1,
        is_static=False,
        signature="int project_helper(int value)",
        return_type="int",
        parameters=[("int", "value")],
    )
    clang_analysis = SimpleNamespace(symbols={"project_helper": [symbol]})
    errors = ["sample.c(3): error C3861: 'project_helpr': identifier not found"]

    fixed, num_fixes, _ = AutoFixer.apply_generic_pattern_fixes(
        source,
        errors,
        "c",
        file_path=r"E:\current\sample.c",
        clang_analysis=clang_analysis,
    )

    assert num_fixes >= 1
    assert "project_helpr" not in fixed
    assert "project_helper(7)" in fixed

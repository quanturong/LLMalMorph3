from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from automation.mutation_validator import MutationValidator


def test_rejects_wide_call_argument_changed_to_narrow_buffer():
    validator = MutationValidator()
    if not validator.available:
        return

    original = r'''
void f(void) {
    Sink(L"C:\\Users\\Public");
}
'''
    mutated = r'''
void f(void) {
    char _s0[16];
    _s0[0]='C';
    _s0[1]=':';
    _s0[2]='\\';
    _s0[3]=0;
    Sink(_s0);
}
'''

    ok, reason = validator.validate(original, mutated, language="cpp", strategy="strat_1")

    assert ok is False
    assert reason is not None
    assert "character-width mismatch" in reason


def test_accepts_wide_call_argument_preserved_as_wide_buffer():
    validator = MutationValidator()
    if not validator.available:
        return

    original = r'''
void f(void) {
    Sink(L"C:\\Users\\Public");
}
'''
    mutated = r'''
void f(void) {
    wchar_t _s0[16];
    _s0[0]=L'C';
    _s0[1]=L':';
    _s0[2]=L'\\';
    _s0[3]=0;
    Sink(_s0);
}
'''

    ok, reason = validator.validate(original, mutated, language="cpp", strategy="strat_1")

    assert ok is True, reason


def test_accepts_narrow_call_argument_preserved_as_narrow_buffer():
    validator = MutationValidator()
    if not validator.available:
        return

    original = r'''
void f(void) {
    Sink("POST");
}
'''
    mutated = r'''
void f(void) {
    char _s0[5];
    _s0[0]='P';
    _s0[1]='O';
    _s0[2]='S';
    _s0[3]='T';
    _s0[4]=0;
    Sink(_s0);
}
'''

    ok, reason = validator.validate(original, mutated, language="cpp", strategy="strat_1")

    assert ok is True, reason

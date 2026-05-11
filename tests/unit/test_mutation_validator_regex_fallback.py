import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from automation.mutation_validator import MutationValidator


def test_regex_fallback_rejects_generated_string_scope_escape():
    original = """
void f()
{
    Use("172.");
}
""".lstrip()
    mutated = """
void f()
{
    {
        char _s1[5]; _s1[0]='1'; _s1[1]='7'; _s1[2]='2'; _s1[3]='.'; _s1[4]=0;
        volatile int _dc0 = (int)(sizeof(void*) << 3);
    }

    Use(_s1);
}
""".lstrip()

    passed, reason = MutationValidator().validate(original, mutated, "cpp", strategy="strat_1")

    assert not passed
    assert reason is not None
    assert "Variable scope regression" in reason
    assert "_s1" in reason

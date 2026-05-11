import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from automation.syntax_checker import SyntaxChecker


def test_syntax_checker_treats_generated_s_name_undeclared_as_actionable():
    output = "file.cpp:12:22: error: '_s1' was not declared in this scope"

    actionable = SyntaxChecker._filter_actionable(output, "gcc")

    assert actionable == [output]


def test_syntax_checker_ignores_project_specific_undeclared_symbols():
    output = "file.cpp:12:22: error: 'ProjectGlobal' was not declared in this scope"

    actionable = SyntaxChecker._filter_actionable(output, "gcc")

    assert actionable == []

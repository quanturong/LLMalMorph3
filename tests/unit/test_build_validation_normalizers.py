from types import SimpleNamespace

from agents.build_validation_agent import BuildValidationAgent


class _Log:
    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


def test_generated_string_scope_blocks_are_unwrapped(tmp_path):
    src = tmp_path / "network_scanner.cpp"
    src.write_text(
        """
void f()
{
    if (1)
    {
        char _s1[5]; _s1[0]='1'; _s1[1]='7'; _s1[2]='2'; _s1[3]='.'; _s1[4]=0;
        char _s2[3]; _s2[0]='1'; _s2[1]='0'; _s2[2]=0;
        volatile int _dc0 = (int)(sizeof(void*) << 3);
    }

    Use(_s1);
    Use(_s2);
}
""".lstrip(),
        encoding="utf-8",
    )
    project = SimpleNamespace(source_files=[str(src)], header_files=[], root_dir=str(tmp_path))
    agent = BuildValidationAgent.__new__(BuildValidationAgent)

    assert agent._normalize_generated_string_scope_blocks(project, _Log()) == 1
    text = src.read_text(encoding="utf-8")
    assert "    {\n        char _s1" not in text
    assert "char _s1[5]" in text
    assert "Use(_s1);" in text


def test_conflicting_local_redeclaration_removes_unused_placeholder(tmp_path):
    src = tmp_path / "main.cpp"
    src.write_text(
        """
int main()
{
    HANDLE String;
    HANDLE hLocalSearch = NULL;
    PSTRING_LIST String = NULL;
    Use(String);
}
""".lstrip(),
        encoding="utf-8",
    )
    project = SimpleNamespace(source_files=[str(src)], header_files=[], root_dir=str(tmp_path))
    agent = BuildValidationAgent.__new__(BuildValidationAgent)

    assert agent._normalize_conflicting_local_redeclarations(project, _Log()) == 1
    text = src.read_text(encoding="utf-8")
    assert "HANDLE String;" not in text
    assert "PSTRING_LIST String = NULL;" in text


def test_bsd_queue_foreach_cursor_uses_element_pointer_type(tmp_path):
    src = tmp_path / "main.cpp"
    src.write_text(
        """
typedef struct item_ {
    int value;
    TAILQ_ENTRY(item_) Entries;
} ITEM, *PITEM;
typedef TAILQ_HEAD(item_list_, item_) ITEM_LIST, *PITEM_LIST;

void f()
{
    PITEM_LIST Item = NULL;
    TAILQ_FOREACH(Item, &g_Items, Entries) {
        Use(Item->value);
    }
}
""".lstrip(),
        encoding="utf-8",
    )
    project = SimpleNamespace(source_files=[str(src)], header_files=[], root_dir=str(tmp_path))
    agent = BuildValidationAgent.__new__(BuildValidationAgent)

    assert agent._normalize_bsd_queue_foreach_cursor_types(project, _Log()) == 1
    text = src.read_text(encoding="utf-8")
    assert "PITEM Item = NULL;" in text
    assert "PITEM_LIST Item = NULL;" not in text


def test_sdk_typedef_normalizer_preserves_bsd_queue_typedefs(tmp_path, monkeypatch):
    src = tmp_path / "main.cpp"
    src.write_text(
        """
typedef struct string_ {
    WCHAR wszString[16384];
    TAILQ_ENTRY(string_) Entries;
} STRING, * PSTRING;

typedef TAILQ_HEAD(string_list_, string_) STRING_LIST, * PSTRING_LIST;

void f()
{
    PSTRING String = NULL;
    TAILQ_FOREACH(String, &g_HostList, Entries) {
        Use(String->wszString);
    }
}
""".lstrip(),
        encoding="utf-8",
    )
    project = SimpleNamespace(source_files=[str(src)], header_files=[], root_dir=str(tmp_path))
    agent = BuildValidationAgent.__new__(BuildValidationAgent)
    monkeypatch.setattr(agent, "_sdk_declares_symbols", lambda symbols: {"STRING", "PSTRING"})

    assert agent._normalize_sdk_typedef_redefinitions(project, _Log()) == 0
    text = src.read_text(encoding="utf-8")
    assert "typedef struct string_" in text
    assert "} STRING, * PSTRING;" in text


def test_extra_file_scope_closing_brace_removed(tmp_path):
    src = tmp_path / "dcc.cpp"
    src.write_text(
        """
DWORD WINAPI FirstThread(LPVOID param)
{
    while (1) {
        break;
    }
}
}

DWORD WINAPI NextThread(LPVOID param)
{
    return 0;
}
""".lstrip(),
        encoding="utf-8",
    )
    project = SimpleNamespace(source_files=[str(src)], header_files=[], root_dir=str(tmp_path))
    agent = BuildValidationAgent.__new__(BuildValidationAgent)

    assert agent._normalize_extra_file_scope_closing_braces(project, _Log()) == 1
    text = src.read_text(encoding="utf-8")
    assert sum(1 for line in text.splitlines() if line.strip() == "}") == 3
    assert "DWORD WINAPI FirstThread" in text
    assert "DWORD WINAPI NextThread" in text

from types import SimpleNamespace

from src.project_compiler import ProjectCompiler


def test_discover_local_link_inputs_includes_root_and_project_files(tmp_path):
    root_lib = tmp_path / "detours.lib"
    root_lib.write_bytes(b"fake")
    nested = tmp_path / "nested"
    nested.mkdir()
    nested_obj = nested / "helper.obj"
    nested_obj.write_bytes(b"fake")
    ignored = tmp_path / "note.txt"
    ignored.write_text("skip", encoding="utf-8")

    project = SimpleNamespace(
        root_dir=str(tmp_path),
        other_files=[str(nested_obj), str(ignored)],
        build_files=[],
    )

    found = ProjectCompiler._discover_local_link_inputs(project, (".lib", ".obj"))

    assert str(root_lib.resolve()) in found
    assert str(nested_obj.resolve()) in found
    assert str(ignored.resolve()) not in found

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
AUTOMATION = ROOT / "src" / "automation"
if str(AUTOMATION) not in sys.path:
    sys.path.insert(0, str(AUTOMATION))

from vendor_classifier import classify_source_file, filter_vendor_files


def test_known_amalgamation_file_is_vendor(tmp_path: Path):
    path = tmp_path / "sqlite3.c"
    path.write_text("/* SQLite amalgamation */\nint sqlite3_open(void) { return 0; }\n")

    result = classify_source_file(str(path))

    assert result.is_vendor
    assert result.score >= 3
    assert any(reason.startswith("known_vendor_name") for reason in result.reasons)


def test_large_project_named_source_is_not_vendor_by_size_alone(tmp_path: Path):
    path = tmp_path / "Source.cpp"
    path.write_text("int WinMain(void) { return 0; }\n" + ("int helper;\n" * 25000))

    result = classify_source_file(str(path), read_content=False)

    assert not result.is_vendor
    assert result.score < 3


def test_vendor_filter_keeps_project_code(tmp_path: Path):
    vendor = tmp_path / "parson.c"
    vendor.write_text("/* parson json parser */\nint json_parse(void) { return 0; }\n")
    project = tmp_path / "CNC.cpp"
    project.write_text("int connect_panel(void) { return 0; }\n")

    kept = filter_vendor_files([str(vendor), str(project)])

    assert kept == [str(project)]

"""
collect_results.py
==================
Organises test_results/ into per-variant subfolders that each contain:
  - the compiled .exe
  - mutation_result.json      (LLM mutation summary)
  - variant_source.json       (mutated source listing)
  - source_parse_result.json  (AST parse of original)
  - behavior_analysis_result.json  (sandbox behaviour)
  - decision_result.json      (detection/evasion decision)
  - sandbox_raw_report.json   (raw VT/sandbox report)

Matching strategy (per artifacts_prod_* run folder):
  1. Read project_name from every *.json artifact.
  2. For each exe, try to match:
        a) project_name is an exact prefix of exe_stem before last _XXXXXXXX
        b) Fallback: look at work_prod_*/variant_build_{buildID}/ source files
           to find project-specific filenames and cross-ref with known project maps.
  3. Copy all matched files into test_results/{patch}__{label}__{buildID}/
"""

import json
import os
import re
import shutil
from pathlib import Path

PATCH_RUNS = Path(r"E:\LLMalMorph2\project_mutation_output\patch_runs")
TEST_RESULTS = Path(r"E:\LLMalMorph2\test_results")

# Known project labels (for naming output folders) — maps (project_name_in_json) → folder_label
PROJECT_LABELS = {
    "NullBot - Dec 2006":          "NullBot_Dec2006",
    "ShadowBot v3 - March 2007":   "ShadowBotv3_Mar2007",
    "VCProject":                   "Projeto-Memz",
    "trojanCockroach":             "TrojanCockroach",
    "Win32.Fungus":                "Win32Fungus",
    "Win32.D.a":                   "Win32DBot",
    "Win32.MiniPig - Nov 2006":    "Win32MiniPig_Nov2006",
    "Win32.ogw0rm - Nov 2008":     "Win32ogw0rm_Nov2008",
    "Win32.Warskype - Jun 2013":   "Win32Warskype_Jun2013",
    "Worm.Win32.Warskype":          "Win32Warskype",
    "xTBot":                       "xTBot",
    "xTBot 0.0.2 - 2 Feb 2002":    "xTBot_2002",
    # Fallbacks for older runs we don't rename
}

JSON_TYPES = {
    "mutation_result.json",
    "variant_source.json",
    "source_parse_result.json",
    "behavior_analysis_result.json",
    "decision_result.json",
    "sandbox_raw_report.json",
}


def extract_build_id(exe_path: Path) -> str | None:
    """Extract 8-char hex build ID from exe filename like Foo_a1b2c3d4.exe or variant_build_a1b2_a1b2.exe"""
    m = re.search(r'_([0-9a-f]{8})(?:_[0-9a-f]{8})?\.exe$', exe_path.name, re.IGNORECASE)
    return m.group(1) if m else None


def load_project_name(json_path: Path) -> str | None:
    try:
        data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        return data.get("project_name") or None
    except Exception:
        return None


def find_work_project(work_base: Path, build_id: str) -> str | None:
    """
    Look inside work_base/variant_build_{buildID}/ for recognisable source files
    and map them back to a known project name.
    """
    SIGNATURES = {
        # filename substring → project_name  (checked case-insensitively)
        "nullbot":           "NullBot - Dec 2006",
        "advscan":           "NullBot - Dec 2006",
        "shadowbot":         "ShadowBot v3 - March 2007",
        "vcproject":         "VCProject",
        "trojanCockroach":   "trojanCockroach",
        "trojancock":        "trojanCockroach",
        "Win32.Fungus":      "Win32.Fungus",
        "Win32.D.a":         "Win32.D.a",
        "MiniPig":           "Win32.MiniPig - Nov 2006",
        "ogw0rm":            "Win32.ogw0rm - Nov 2008",
        "warskype":          "Worm.Win32.Warskype",
        "xtbot":             "xTBot 0.0.2 - 2 Feb 2002",
    }
    # work_base is already work_prod_TIMESTAMP — look directly for variant_build_{build_id}
    variant = work_base / f"variant_build_{build_id}"
    if not variant.is_dir():
        return None
    for f in variant.rglob("*"):
        fname_lower = f.name.lower()
        for sig, proj in SIGNATURES.items():
            if sig.lower() in fname_lower:
                return proj
    return None


def process_run(patch_name: str, artifacts_dir: Path, work_base: Path):
    """Process one artifacts_prod_* folder and produce organised subfolders."""
    if not artifacts_dir.is_dir():
        return

    # Load all json artifacts: {project_name: {json_type: path}}
    project_jsons: dict[str, dict[str, Path]] = {}
    for jpath in artifacts_dir.rglob("*.json"):
        if jpath.name not in JSON_TYPES:
            continue
        pname = load_project_name(jpath)
        if not pname:
            continue
        project_jsons.setdefault(pname, {})[jpath.name] = jpath

    # Find all exe files in this run
    for exe_path in artifacts_dir.rglob("*.exe"):
        build_id = extract_build_id(exe_path)
        if not build_id:
            print(f"  [SKIP] Cannot extract build_id from: {exe_path.name}")
            continue

        # Step 1: try direct prefix match
        exe_stem = exe_path.stem  # e.g. "Win32.Fungus_4b05581d" or "variant_build_f3b26f8d_f3b26f8d"
        matched_project = None

        for pname in project_jsons:
            safe = re.escape(pname)
            if re.match(rf'^{safe}_[0-9a-f]{{8}}', exe_stem, re.IGNORECASE):
                matched_project = pname
                break

        # Step 2: fallback via work folder signatures
        if matched_project is None and work_base.is_dir():
            matched_project = find_work_project(work_base, build_id)

        # Step 3: if only one project in run, assign by default
        if matched_project is None and len(project_jsons) == 1:
            matched_project = next(iter(project_jsons))

        if matched_project is None:
            print(f"  [WARN] Could not match project for {exe_path.name}")
            continue

        label = PROJECT_LABELS.get(matched_project, matched_project.replace(" ", "_").replace("/", "_"))
        folder_name = f"{patch_name}__{label}__{build_id}"
        dest_dir = TEST_RESULTS / folder_name
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Copy exe
        dest_exe = dest_dir / exe_path.name
        if not dest_exe.exists():
            try:
                shutil.copy2(exe_path, dest_exe)
                print(f"  [EXE]  {folder_name}/{exe_path.name}")
            except PermissionError:
                print(f"  [DEFENDER BLOCKED] {exe_path.name} — skipping")

        # Copy json files
        for jtype, jsrc in project_jsons.get(matched_project, {}).items():
            jdest = dest_dir / jtype
            if not jdest.exists():
                try:
                    shutil.copy2(jsrc, jdest)
                    print(f"  [JSON] {folder_name}/{jtype}")
                except Exception as e:
                    print(f"  [ERR]  {jtype}: {e}")


def main():
    TEST_RESULTS.mkdir(exist_ok=True)

    for patch_dir in sorted(PATCH_RUNS.iterdir()):
        if not patch_dir.is_dir() or not patch_dir.name.startswith("patch_"):
            continue
        patch_name = patch_dir.name  # patch_01, patch_02, patch_03

        print(f"\n=== {patch_name} ===")

        # Process all artifacts_prod_* runs in this patch
        for artifacts_dir in sorted(patch_dir.glob("artifacts_prod_*")):
            ts = artifacts_dir.name.replace("artifacts_prod_", "")
            work_base = patch_dir / f"work_prod_{ts}"
            print(f"\n  Run: {artifacts_dir.name}")
            process_run(patch_name, artifacts_dir, work_base)


if __name__ == "__main__":
    main()

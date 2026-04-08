"""
batch_compile_patches.py
========================
Batch compile all malware projects in samples/patches_win and report results.

For each project it:
  1. Detects source files and project type (.dsp / flat files)
  2. Builds compile command (cl.exe for C/C++)
  3. Runs compilation in a temp output dir
  4. Collects success/failure + first 30 lines of errors

Output:
  - Console summary table
  - batch_compile_results.json
"""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# ── Compiler setup ────────────────────────────────────────────────────────────
# MSVC cl.exe — found via `where cl`
CL_EXE    = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64\cl.exe"
CL_EXE_X86 = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x86\cl.exe"

# Windows SDK & MSVC include/lib paths (needed for Windows headers)
_VC_ROOT = Path(CL_EXE).parents[3]  # …\MSVC\14.43.34808
_VS_ROOT = Path(CL_EXE).parents[6]  # …\Visual Studio\2022\Community

MSVC_INCLUDE = str(_VC_ROOT / "include")
MSVC_LIB     = str(_VC_ROOT / "lib" / "x64")
MSVC_LIB_X86 = str(_VC_ROOT / "lib" / "x86")

# Windows SDK (auto-detect latest)
_WINSDK_BASE = Path(r"C:\Program Files (x86)\Windows Kits\10")
def _find_sdk_ver():
    inc = _WINSDK_BASE / "Include"
    if inc.exists():
        vers = sorted([d.name for d in inc.iterdir() if d.is_dir() and d.name.startswith("10.")], reverse=True)
        return vers[0] if vers else None
    return None

_SDK_VER = _find_sdk_ver()
SDK_INCLUDES = []
SDK_LIBS = []
SDK_LIBS_X86 = []
if _SDK_VER and _WINSDK_BASE.exists():
    for sub in ("um", "shared", "ucrt"):
        p = _WINSDK_BASE / "Include" / _SDK_VER / sub
        if p.exists():
            SDK_INCLUDES.append(str(p))
    for sub in ("um", "ucrt"):
        p = _WINSDK_BASE / "Lib" / _SDK_VER / sub / "x64"
        if p.exists():
            SDK_LIBS.append(str(p))
        p86 = _WINSDK_BASE / "Lib" / _SDK_VER / sub / "x86"
        if p86.exists():
            SDK_LIBS_X86.append(str(p86))

ALL_INCLUDES  = [MSVC_INCLUDE] + SDK_INCLUDES
ALL_LIBS      = [MSVC_LIB] + SDK_LIBS
ALL_LIBS_X86  = [MSVC_LIB_X86] + SDK_LIBS_X86

# ── Common linker libs for old Windows malware ────────────────────────────────
COMMON_LIBS = [
    "kernel32.lib", "user32.lib", "wsock32.lib", "ws2_32.lib",
    "advapi32.lib", "shell32.lib", "wininet.lib", "urlmon.lib",
    "netapi32.lib", "iphlpapi.lib", "shlwapi.lib", "ole32.lib",
    "psapi.lib", "imagehlp.lib", "version.lib",
    "gdi32.lib", "winmm.lib", "comdlg32.lib", "comctl32.lib",
    "mpr.lib",   # WNet* functions (xTBot, DBot, etc.)
    "legacy_stdio_definitions.lib",
]

PATCHES_ROOT = Path(__file__).parent / "samples" / "patches_win"
OUTPUT_ROOT  = Path(__file__).parent / "batch_compile_output"
RESULTS_FILE = Path(__file__).parent / "batch_compile_results.json"

# Projects where every source file is a separate executable (each defines its own main())
# Must be compiled one .cpp → one .exe, never all together.
PER_FILE_PROJECTS = {"TrojanCockroach"}

# Projects using int main() (not WinMain) → SUBSYSTEM:CONSOLE
CONSOLE_PROJECTS = {"Projeto-Memz", "TrojanCockroach"}


# ─────────────────────────────────────────────────────────────────────────────
# Project discovery
# ─────────────────────────────────────────────────────────────────────────────

def _walk_no_junction(root: Path) -> list[Path]:
    """Walk directory, returning all files (handles Windows junctions)."""
    files = []
    try:
        for entry in root.rglob("*"):
            if entry.is_file():
                files.append(entry)
    except (PermissionError, OSError):
        pass
    return files


def _source_files_from_dsp(dsp_path: Path) -> list[Path]:
    """Parse a .dsp file and extract SOURCE= file paths."""
    sources = []
    base = dsp_path.parent
    try:
        text = dsp_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for m in re.finditer(r'^SOURCE=(.+)$', text, re.MULTILINE):
        rel = m.group(1).strip().replace("\\", os.sep)
        p = (base / rel).resolve()
        if p.exists() and p.suffix.lower() in (".c", ".cpp"):
            sources.append(p)
    return sources


def discover_project(project_dir: Path) -> dict:
    """
    Returns:
        {
          "name": str,
          "dir": Path,
          "language": "c" | "cpp" | "mixed",
          "sources": [Path],
          "extra_includes": [Path],
          "dsp": Path | None,
        }
    """
    all_files = _walk_no_junction(project_dir)
    dsp_files = [f for f in all_files if f.suffix.lower() == ".dsp"]
    src_files  = [f for f in all_files if f.suffix.lower() in (".c", ".cpp")
                  and ".bak" not in f.name.lower()
                  and "compress" not in str(f).lower()]  # skip PayloadMBR compression util

    # Prefer .dsp listed sources (more accurate)
    dsp = dsp_files[0] if dsp_files else None
    if dsp:
        dsp_sources = _source_files_from_dsp(dsp)
        if dsp_sources:
            src_files = dsp_sources

    # Remove duplicates, keep order
    seen = set()
    unique_sources = []
    for s in src_files:
        k = str(s).lower()
        if k not in seen:
            seen.add(k)
            unique_sources.append(s)

    # Detect language
    exts = {s.suffix.lower() for s in unique_sources}
    if ".cpp" in exts and ".c" in exts:
        lang = "mixed"
    elif ".cpp" in exts:
        lang = "cpp"
    else:
        lang = "c"

    # Collect include dirs (all dirs that contain .h files)
    h_dirs = {f.parent for f in all_files if f.suffix.lower() == ".h"}
    extra_includes = list(h_dirs)

    return {
        "name": project_dir.name,
        "dir": project_dir,
        "language": lang,
        "sources": unique_sources,
        "extra_includes": extra_includes,
        "dsp": dsp,
    }


def discover_all_projects(patches_root: Path) -> list[dict]:
    projects = []
    for patch_dir in sorted(patches_root.iterdir()):
        if not patch_dir.is_dir() or patch_dir.name.startswith("."):
            continue
        if patch_dir.name == "patch_manifest.json":
            continue
        for proj_dir in sorted(patch_dir.iterdir()):
            if not proj_dir.is_dir():
                continue
            info = discover_project(proj_dir)
            info["patch"] = patch_dir.name
            projects.append(info)
    return projects


# ─────────────────────────────────────────────────────────────────────────────
# Compilation
# ─────────────────────────────────────────────────────────────────────────────

def build_compile_cmd(project: dict, out_dir: Path) -> list[str]:
    """Build cl.exe command for a project."""
    sources = project["sources"]
    is_cpp  = project["language"] in ("cpp", "mixed")
    is_x86  = project["name"] in ("xTBot0.0.2_2Feb2002",)  # x86 __asm requires 32-bit target

    exe_name = re.sub(r'[^\w]', '_', project["name"]) + ".exe"
    out_exe  = str(out_dir / exe_name)

    cmd = [CL_EXE_X86 if is_x86 else CL_EXE]

    # C++ standard flags — for mixed projects, DON'T use /TP (which forces C++ on .c files).
    # .c files in DBot are included via extern "C" {} in .cpp callers, so they MUST compile as C.
    if project["language"] == "cpp":
        cmd += ["/EHsc", "/TP"]     # all sources are C++
    elif project["language"] == "c":
        cmd += ["/TC"]              # force C mode
    else:  # mixed (.c and .cpp together)
        cmd += ["/EHsc"]            # C++ EH; compiler auto-detects C vs C++ per file extension

    # Common flags for old malware (suppress lots of warnings, allow deprecated APIs)
    # ogw0rm uses #pragma comment(linker, "/ENTRY:Main") which bypasses CRT startup.
    # With /MT (static release CRT), strstr/memset/etc. are fully linked from libcmt.lib
    # without needing import stubs from ucrtbase.dll.
    crt_flag = "/MT" if project["name"] in ("Win32.ogw0rm_Nov2008",) else "/MTd"
    cmd += [
        "/W1",          # warning level 1 (reduce noise)
        "/WX-",         # warnings are not errors
        "/Od",          # no optimisation (faster compile)
        crt_flag,       # CRT linkage
        "/D", "WIN32",
        "/D", "_WINDOWS",
        "/D", "NDEBUG",
        "/D", "_CRT_SECURE_NO_WARNINGS",
        "/D", "_CRT_NONSTDC_NO_WARNINGS",
        "/D", "_WINSOCK_DEPRECATED_NO_WARNINGS",
        "/D", "_MBCS",          # ANSI/MBCS mode — old malware uses char[], not wchar_t
        "/D", "WINDOWS_IGNORE_PACKING_MISMATCH",  # suppress pack mismatch in old code
        "/nologo",
    ]

    # Include paths
    for inc in ALL_INCLUDES + [str(p) for p in project["extra_includes"]]:
        cmd += ["/I", inc]

    # Source files
    cmd += [str(s) for s in sources]

    # Linker flags
    subsystem = "CONSOLE" if project["name"] in CONSOLE_PROJECTS else "WINDOWS"
    # xTBot uses x86 inline __asm (_emit): must be compiled as 32-bit even after source fix
    machine = "X86" if project["name"] in ("xTBot0.0.2_2Feb2002",) else "X64"
    cmd += [
        "/link",
        f"/OUT:{out_exe}",
        f"/SUBSYSTEM:{subsystem}",
        f"/MACHINE:{machine}",
        "/IGNORE:4099",     # suppress PDB not found warnings
    ]
    for lib in ALL_LIBS_X86 if is_x86 else ALL_LIBS:
        cmd += [f"/LIBPATH:{lib}"]
    # ogw0rm uses #pragma /ENTRY:Main which can prevent default lib resolution.
    # Add all three static CRT components explicitly so C runtime functions resolve.
    crt_libs = ["libcmt.lib", "libvcruntime.lib", "libucrt.lib"] if project["name"] == "Win32.ogw0rm_Nov2008" else []
    cmd += crt_libs + COMMON_LIBS

    return cmd


def _compile_per_file(project: dict) -> dict:
    """Compile each source file in the project as its own executable.
    Used for projects like TrojanCockroach where each .cpp has its own main().
    Returns an aggregate result; fails if any file fails.
    """
    name  = project["name"]
    patch = project["patch"]
    out_dir = OUTPUT_ROOT / patch / re.sub(r'[^\w]', '_', name)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_exes = []
    all_errors = []
    any_fail = False

    for src in project["sources"]:
        # Build a single-source pseudo-project
        sub = dict(project)  # shallow copy
        sub["sources"] = [src]
        exe_stem = src.stem
        exe_path = out_dir / (exe_stem + ".exe")

        # Temporarily patch name so build_compile_cmd writes correct /OUT:
        sub["_out_exe"] = str(exe_path)

        # Build command manually (reuse build_compile_cmd logic)
        is_cpp = src.suffix.lower() == ".cpp"
        cmd = [CL_EXE]
        if is_cpp:
            cmd += ["/EHsc", "/TP"]
        else:
            cmd += ["/TC"]
        cmd += [
            "/W1", "/WX-", "/Od", "/MTd",
            "/D", "WIN32", "/D", "_WINDOWS", "/D", "NDEBUG",
            "/D", "_CRT_SECURE_NO_WARNINGS", "/D", "_CRT_NONSTDC_NO_WARNINGS",
            "/D", "_WINSOCK_DEPRECATED_NO_WARNINGS",
            "/D", "_MBCS", "/D", "WINDOWS_IGNORE_PACKING_MISMATCH",
            "/nologo",
        ]
        for inc in ALL_INCLUDES + [str(p) for p in project["extra_includes"]]:
            cmd += ["/I", inc]
        cmd.append(str(src))
        cmd += [
            "/link",
            f"/OUT:{exe_path}",
            "/SUBSYSTEM:CONSOLE",
            "/MACHINE:X64",
            "/IGNORE:4099",
        ]
        for lib in ALL_LIBS:
            cmd += [f"/LIBPATH:{lib}"]
        cmd += COMMON_LIBS

        cmd_str = " ".join(('"' + c + '"') if " " in c else c for c in cmd)
        (out_dir / f"compile_command_{exe_stem}.txt").write_text(cmd_str, encoding="utf-8")

        print(f"  Compiling {src.name} → {exe_stem}.exe ...")
        env = os.environ.copy()
        env["LIB"]     = ";".join(ALL_LIBS)
        env["INCLUDE"] = ";".join(ALL_INCLUDES)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                cwd=str(out_dir), env=env, timeout=120,
            )
            combined = (result.stdout + "\n" + result.stderr).strip()
            (out_dir / f"compile_output_{exe_stem}.txt").write_text(combined, encoding="utf-8")
            success = (result.returncode == 0) and exe_path.exists()
            if success:
                size_kb = round(exe_path.stat().st_size / 1024, 1)
                print(f"    [OK] {exe_stem}.exe ({size_kb} KB)")
                all_exes.append(str(exe_path))
            else:
                print(f"    [FAIL] rc={result.returncode}")
                errs = [l for l in combined.splitlines() if "error" in l.lower() or "fatal" in l.lower()][:10]
                for e in errs[:3]:
                    print(f"      {e.strip()}")
                all_errors.extend(errs)
                any_fail = True
        except subprocess.TimeoutExpired:
            print(f"    [TIMEOUT] {src.name}")
            all_errors.append(f"TIMEOUT: {src.name}")
            any_fail = True
        except Exception as exc:
            print(f"    [ERROR] {src.name}: {exc}")
            all_errors.append(f"ERROR {src.name}: {exc}")
            any_fail = True

    status = "FAIL" if any_fail else "OK"
    return {
        "name": name, "patch": patch,
        "status": status,
        "reason": "per-file compilation",
        "sources": [str(s) for s in project["sources"]],
        "exe": all_exes[0] if all_exes else None,
        "exe_size_kb": round(sum(Path(e).stat().st_size for e in all_exes) / 1024, 1) if all_exes else 0,
        "exes": all_exes,
        "returncode": 1 if any_fail else 0,
        "errors": all_errors,
        "language": project["language"],
        "dsp": str(project["dsp"]) if project["dsp"] else None,
    }


def compile_project(project: dict) -> dict:
    """Compile one project. Returns result dict."""
    if project["name"] in PER_FILE_PROJECTS:
        return _compile_per_file(project)
    name  = project["name"]
    patch = project["patch"]
    out_dir = OUTPUT_ROOT / patch / re.sub(r'[^\w]', '_', name)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not project["sources"]:
        return {
            "name": name, "patch": patch,
            "status": "SKIP",
            "reason": "no source files found",
            "sources": [],
            "exe": None,
            "errors": [],
        }

    cmd = build_compile_cmd(project, out_dir)
    cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmd)

    # Write compile command for reference
    (out_dir / "compile_command.txt").write_text(cmd_str, encoding="utf-8")

    print(f"\n{'='*60}")
    print(f"[{patch}] {name}")
    print(f"  Sources: {len(project['sources'])} files | Lang: {project['language']}")
    print(f"  DSP: {project['dsp'].name if project['dsp'] else 'none'}")
    print(f"  Compiling...")

    env = os.environ.copy()
    env["LIB"]     = ";".join(ALL_LIBS)
    env["INCLUDE"] = ";".join(ALL_INCLUDES)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(out_dir),
            env=env,
            timeout=120,
        )
        stdout = result.stdout
        stderr = result.stderr
        combined = (stdout + "\n" + stderr).strip()
        rc = result.returncode

        exe_name = re.sub(r'[^\w]', '_', name) + ".exe"
        exe_path = out_dir / exe_name
        success  = (rc == 0) and exe_path.exists()

        # Extract first error lines
        error_lines = [l for l in combined.splitlines() if "error" in l.lower() or "fatal" in l.lower()][:30]

        if success:
            size_kb = round(exe_path.stat().st_size / 1024, 1)
            print(f"  [OK] {exe_name} ({size_kb} KB)")
        else:
            print(f"  [FAIL] rc={rc}")
            for e in error_lines[:5]:
                print(f"    {e.strip()}")

        (out_dir / "compile_output.txt").write_text(combined, encoding="utf-8")

        # ── Wipe build intermediates (.obj, .pdb, .ilk, .exp) ─────────────
        for ext in ("*.obj", "*.pdb", "*.ilk", "*.exp", "*.idb"):
            for f in glob.glob(str(out_dir / ext)):
                try:
                    os.unlink(f)
                except OSError:
                    pass

        return {
            "name": name, "patch": patch,
            "status": "OK" if success else "FAIL",
            "reason": "",
            "sources": [str(s) for s in project["sources"]],
            "exe": str(exe_path) if success else None,
            "exe_size_kb": round(exe_path.stat().st_size / 1024, 1) if success else 0,
            "returncode": rc,
            "errors": error_lines,
            "language": project["language"],
            "dsp": str(project["dsp"]) if project["dsp"] else None,
        }

    except subprocess.TimeoutExpired:
        print("  [TIMEOUT]")
        return {
            "name": name, "patch": patch,
            "status": "TIMEOUT",
            "reason": "compile timed out after 120s",
            "sources": [str(s) for s in project["sources"]],
            "exe": None, "errors": [],
        }
    except Exception as exc:
        print(f"  [ERROR] {exc}")
        return {
            "name": name, "patch": patch,
            "status": "ERROR",
            "reason": str(exc),
            "sources": [str(s) for s in project["sources"]],
            "exe": None, "errors": [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if not Path(CL_EXE).exists():
        print(f"ERROR: cl.exe not found at {CL_EXE}")
        sys.exit(1)

    print(f"MSVC include : {MSVC_INCLUDE}")
    print(f"SDK version  : {_SDK_VER}")
    print(f"SDK includes : {SDK_INCLUDES}")
    print(f"Output dir   : {OUTPUT_ROOT}")

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    projects = discover_all_projects(PATCHES_ROOT)
    print(f"\nDiscovered {len(projects)} projects:")
    for p in projects:
        src_count = len(p["sources"])
        dsp = p["dsp"].name if p["dsp"] else "no .dsp"
        print(f"  [{p['patch']}] {p['name']:40s} {src_count} src  lang={p['language']}  {dsp}")

    results = []
    for proj in projects:
        r = compile_project(proj)
        results.append(r)

    # ── Summary ───────────────────────────────────────────────────────────────
    ok      = [r for r in results if r["status"] == "OK"]
    fail    = [r for r in results if r["status"] == "FAIL"]
    skip    = [r for r in results if r["status"] == "SKIP"]
    timeout = [r for r in results if r["status"] == "TIMEOUT"]
    error   = [r for r in results if r["status"] == "ERROR"]

    print(f"\n{'='*60}")
    print(f"BATCH COMPILE SUMMARY  ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    print(f"{'='*60}")
    print(f"  Total    : {len(results)}")
    print(f"  OK       : {len(ok)}")
    print(f"  FAIL     : {len(fail)}")
    print(f"  SKIP     : {len(skip)}")
    print(f"  TIMEOUT  : {len(timeout)}")
    print(f"  ERROR    : {len(error)}")

    if ok:
        print(f"\n  [PASSED]")
        for r in ok:
            print(f"    [{r['patch']}] {r['name']} — {r.get('exe_size_kb','?')} KB")

    if fail:
        print(f"\n  [FAILED]")
        for r in fail:
            print(f"    [{r['patch']}] {r['name']}")
            for e in r["errors"][:3]:
                print(f"      {e.strip()}")

    if skip:
        print(f"\n  [SKIPPED] (no source files found)")
        for r in skip:
            print(f"    [{r['patch']}] {r['name']} — {r['reason']}")

    # Save JSON
    report = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total": len(results), "ok": len(ok), "fail": len(fail),
            "skip": len(skip), "timeout": len(timeout), "error": len(error),
        },
        "results": results,
    }
    RESULTS_FILE.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Results saved → {RESULTS_FILE}")
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())

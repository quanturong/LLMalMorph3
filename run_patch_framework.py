from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


LANG_EXT = {
    "c": {".c"},
    "cpp": {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"},
    "python": {".py", ".pyw"},
    "javascript": {".js", ".mjs", ".cjs"},
}


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()
    return s[:80] if s else "sample"


def _detect_language(sample_dir: Path) -> str:
    counts = {k: 0 for k in LANG_EXT.keys()}

    for p in sample_dir.rglob("*"):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        for lang, exts in LANG_EXT.items():
            if ext in exts:
                counts[lang] += 1

    if counts["cpp"] > 0 and counts["cpp"] >= counts["c"]:
        return "cpp"
    if counts["c"] > 0:
        return "c"
    if counts["python"] > 0:
        return "python"
    if counts["javascript"] > 0:
        return "javascript"
    return "cpp"


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _discover_patch_dirs(patch_root: Path) -> list[Path]:
    return sorted(
        [p for p in patch_root.iterdir() if p.is_dir() and p.name.lower().startswith("patch_")],
        key=lambda p: p.name.lower(),
    )


def _discover_sample_dirs(patch_dir: Path) -> list[Path]:
    return sorted(
        [p for p in patch_dir.iterdir() if p.is_dir()],
        key=lambda p: p.name.lower(),
    )


def _build_samples_for_patch(
    patch_dir: Path,
    root_dir: Path,
    sandbox_backend: str,
    strategy: str,
    num_functions: int,
    max_samples: int,
    sample_offset: int = 0,
) -> list[dict[str, Any]]:
    sample_dirs = _discover_sample_dirs(patch_dir)
    if sample_offset > 0:
        sample_dirs = sample_dirs[sample_offset:]
    if max_samples > 0:
        sample_dirs = sample_dirs[:max_samples]

    samples: list[dict[str, Any]] = []
    for i, sample_dir in enumerate(sample_dirs, start=1):
        rel_path = sample_dir.resolve().relative_to(root_dir.resolve())
        lang = _detect_language(sample_dir)
        sid = _slug(f"{patch_dir.name}_{i:02d}_{sample_dir.name}")
        samples.append(
            {
                "sample_id": sid,
                "project_name": sample_dir.name,
                "source_path": str(rel_path).replace("\\", "/"),
                "language": lang,
                "sandbox_backend": sandbox_backend,
                "priority": 5,
                "requested_strategies": [strategy],
                "num_functions": num_functions,
                "metadata": {
                    "profile": "patch_auto",
                    "patch": patch_dir.name,
                },
            }
        )

    return samples


def _build_patch_config(
    base_cfg: dict[str, Any],
    patch_name: str,
    samples: list[dict[str, Any]],
) -> dict[str, Any]:
    cfg = copy.deepcopy(base_cfg)
    cfg["samples"] = samples

    storage = cfg.setdefault("storage", {})
    storage["db_path"] = f"project_mutation_output/patch_runs/{patch_name}/state_prod_{{timestamp}}.db"
    storage["artifact_dir"] = f"project_mutation_output/patch_runs/{patch_name}/artifacts_prod_{{timestamp}}"
    storage["report_dir"] = f"project_mutation_output/patch_runs/{patch_name}/reports_prod_{{timestamp}}"
    storage["work_dir"] = f"project_mutation_output/patch_runs/{patch_name}/work_prod_{{timestamp}}"

    return cfg


def run_patch(
    root_dir: Path,
    framework_script: Path,
    python_exec: Path,
    generated_cfg_path: Path,
    dry_run: bool,
) -> int:
    cmd = [
        str(python_exec),
        str(framework_script),
        "--config",
        str(generated_cfg_path),
    ]
    if dry_run:
        cmd.append("--dry-run")

    print("RUN:", " ".join(cmd))
    proc = subprocess.run(cmd)
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run production framework automatically for selected patch folder(s)."
    )
    parser.add_argument("--patch-root", default="samples/patches", help="Root directory containing patch_XX folders")
    parser.add_argument("--patch", default="all", help="Patch folder name (e.g., patch_01) or 'all'")
    parser.add_argument("--framework-config", default="configs/framework_production.json", help="Base production config")
    parser.add_argument("--generated-config-dir", default="configs/generated_patches", help="Where generated patch configs are written")
    parser.add_argument("--sandbox-backend", default="cape", help="Sandbox backend for generated sample entries")
    parser.add_argument("--strategy", default="strat_1", help="Mutation strategy")
    parser.add_argument("--num-functions", type=int, default=2, help="num_functions per sample")
    parser.add_argument("--max-samples", type=int, default=0, help="Limit samples per patch (0 = no limit)")
    parser.add_argument("--sample-offset", type=int, default=0, help="Skip first N samples (useful for picking non-first samples)")
    parser.add_argument("--python-exec", default=sys.executable, help="Python executable to run framework")
    parser.add_argument("--dry-run", action="store_true", help="Generate config and run framework in dry-run mode")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    patch_root = (root / args.patch_root).resolve()
    framework_config = (root / args.framework_config).resolve()
    framework_script = (root / "run_production_framework.py").resolve()
    generated_config_dir = (root / args.generated_config_dir).resolve()
    python_exec = Path(args.python_exec)

    if not patch_root.exists():
        raise FileNotFoundError(f"Patch root not found: {patch_root}")
    if not framework_config.exists():
        raise FileNotFoundError(f"Base framework config not found: {framework_config}")
    if not framework_script.exists():
        raise FileNotFoundError(f"Framework runner not found: {framework_script}")

    base_cfg = _load_json(framework_config)

    discovered = _discover_patch_dirs(patch_root)
    if not discovered:
        raise RuntimeError(f"No patch_XX folders found in: {patch_root}")

    if args.patch.lower() == "all":
        selected = discovered
    else:
        selected = [patch_root / args.patch]
        if not selected[0].exists() or not selected[0].is_dir():
            raise FileNotFoundError(f"Selected patch folder not found: {selected[0]}")

    failures: list[tuple[str, int]] = []

    for patch_dir in selected:
        samples = _build_samples_for_patch(
            patch_dir=patch_dir,
            root_dir=root,
            sandbox_backend=args.sandbox_backend,
            strategy=args.strategy,
            num_functions=args.num_functions,
            max_samples=args.max_samples,
            sample_offset=args.sample_offset,
        )
        if not samples:
            print(f"SKIP: {patch_dir.name} has no sample folders")
            continue

        cfg = _build_patch_config(base_cfg, patch_dir.name, samples)
        cfg_path = generated_config_dir / f"framework_{patch_dir.name}.json"
        _save_json(cfg_path, cfg)

        print(f"PATCH {patch_dir.name}: {len(samples)} sample(s), config={cfg_path}")
        rc = run_patch(
            root_dir=root,
            framework_script=framework_script,
            python_exec=python_exec,
            generated_cfg_path=cfg_path,
            dry_run=args.dry_run,
        )
        if rc != 0:
            failures.append((patch_dir.name, rc))

    if failures:
        print("FAILED PATCHES:", failures)
        return 1

    print("DONE: all selected patch runs finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

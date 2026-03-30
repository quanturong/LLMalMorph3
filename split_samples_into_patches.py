from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
import subprocess
from pathlib import Path
from typing import Iterable


def _chunk_even(items: list[Path], n_chunks: int) -> list[list[Path]]:
    total = len(items)
    base = total // n_chunks
    rem = total % n_chunks
    chunks: list[list[Path]] = []
    start = 0
    for i in range(n_chunks):
        size = base + (1 if i < rem else 0)
        end = start + size
        chunks.append(items[start:end])
        start = end
    return chunks


def _safe_remove(path: Path) -> None:
    if not path.exists():
        return
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path)


def _mk_windows_junction(src: Path, dst: Path) -> bool:
    cmd = ["cmd", "/c", "mklink", "/J", str(dst), str(src)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode == 0 and dst.exists()


def _link_or_copy_dir(src: Path, dst: Path, fallback_copy: bool = True) -> str:
    try:
        os.symlink(str(src), str(dst), target_is_directory=True)
        return "symlink"
    except Exception:
        if os.name == "nt":
            if _mk_windows_junction(src, dst):
                return "junction"
        if fallback_copy:
            shutil.copytree(src, dst)
            return "copy"
        raise


def _write_patch_manifest(
    output_dir: Path,
    source_dir: Path,
    patch_map: dict[str, list[Path]],
    link_modes: dict[str, str],
) -> Path:
    payload: dict[str, object] = {
        "source_dir": str(source_dir.resolve()),
        "patch_count": len(patch_map),
        "total_samples": sum(len(v) for v in patch_map.values()),
        "patches": {},
    }

    patches_obj: dict[str, object] = {}
    for patch_name, sample_dirs in patch_map.items():
        patches_obj[patch_name] = {
            "count": len(sample_dirs),
            "items": [
                {
                    "name": p.name,
                    "source_path": str(p.resolve()),
                    "link_mode": link_modes.get(f"{patch_name}/{p.name}", "unknown"),
                }
                for p in sample_dirs
            ],
        }
    payload["patches"] = patches_obj

    manifest_path = output_dir / "patch_manifest.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return manifest_path


def split_into_patches(
    source_dir: Path,
    output_dir: Path,
    num_patches: int,
    shuffle: bool,
    seed: int,
    force: bool,
) -> tuple[dict[str, list[Path]], dict[str, str], Path]:
    if not source_dir.exists() or not source_dir.is_dir():
        raise FileNotFoundError(f"Source samples folder not found: {source_dir}")

    samples = [p for p in sorted(source_dir.iterdir(), key=lambda x: x.name.lower()) if p.is_dir()]
    if not samples:
        raise RuntimeError(f"No sample directories found in: {source_dir}")
    if len(samples) < num_patches:
        raise RuntimeError(
            f"Not enough samples ({len(samples)}) for {num_patches} patches"
        )

    if shuffle:
        rnd = random.Random(seed)
        rnd.shuffle(samples)

    output_dir.mkdir(parents=True, exist_ok=True)

    chunks = _chunk_even(samples, num_patches)
    patch_map: dict[str, list[Path]] = {}
    link_modes: dict[str, str] = {}

    for idx, chunk in enumerate(chunks, start=1):
        patch_name = f"patch_{idx:02d}"
        patch_dir = output_dir / patch_name
        patch_dir.mkdir(parents=True, exist_ok=True)

        for sample_dir in chunk:
            dst = patch_dir / sample_dir.name
            if dst.exists() or dst.is_symlink():
                if force:
                    _safe_remove(dst)
                else:
                    # keep existing layout idempotent
                    continue
            mode = _link_or_copy_dir(sample_dir, dst, fallback_copy=True)
            link_modes[f"{patch_name}/{sample_dir.name}"] = mode

        patch_map[patch_name] = chunk

        listing_path = patch_dir / "samples.txt"
        with listing_path.open("w", encoding="utf-8") as f:
            for item in chunk:
                f.write(f"{item.name}\n")

    manifest = _write_patch_manifest(output_dir, source_dir, patch_map, link_modes)
    return patch_map, link_modes, manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Split samples into N patch folders (balanced), using links/junctions with copy fallback."
    )
    parser.add_argument(
        "--source",
        default="samples/Samples",
        help="Source directory containing malware sample folders",
    )
    parser.add_argument(
        "--output",
        default="samples/patches",
        help="Output root for patch folders",
    )
    parser.add_argument(
        "--num-patches",
        type=int,
        default=6,
        help="Number of patch folders to create",
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Shuffle sample order before splitting",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed for --shuffle",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing entries in patch folders",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    source_dir = (root / args.source).resolve()
    output_dir = (root / args.output).resolve()

    patch_map, link_modes, manifest = split_into_patches(
        source_dir=source_dir,
        output_dir=output_dir,
        num_patches=args.num_patches,
        shuffle=args.shuffle,
        seed=args.seed,
        force=args.force,
    )

    total = sum(len(v) for v in patch_map.values())
    print(f"OK: split {total} samples into {len(patch_map)} patches")
    for patch_name, items in patch_map.items():
        print(f"  - {patch_name}: {len(items)} samples")
    modes = {}
    for m in link_modes.values():
        modes[m] = modes.get(m, 0) + 1
    if modes:
        print(f"Link/copy modes: {modes}")
    print(f"Manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

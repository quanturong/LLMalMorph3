"""
Build patches_win/ containing only Windows-compilable C/C++ samples.
Creates 3 patches (5 + 5 + 4) using Windows NTFS junctions.
Does NOT modify the original patches.
"""
import os
import subprocess
import json
from pathlib import Path

PATCH_ROOT = Path(r'E:\LLMalMorph2\samples\patches')
OUT_ROOT = Path(r'E:\LLMalMorph2\samples\patches_win')

# 14 Windows-compilable samples, grouped 5+5+4
PATCHES = {
    'patch_01': [
        'patch_01/HellBotv3.0_10June2005',
        'patch_01/Flanders-Trojan',
        'patch_02/NullBot - Dec 2006',
        'patch_02/Projeto-Memz',
        'patch_03/ShadowBotv3_March2007',
    ],
    'patch_02': [
        'patch_04/TrojanCockroach',
        'patch_05/W32.MyDoom.A',
        'patch_05/Win32.DBot.a',
        'patch_05/Win32.Fungus',
        'patch_05/Win32.MiniPig_Nov2006',
    ],
    'patch_03': [
        'patch_06/Win32.RedPetya',
        'patch_06/Win32.ogw0rm_Nov2008',
        'patch_06/Worm.Win32.Warskype',
        'patch_06/xTBot0.0.2_2Feb2002',
    ],
}


def make_junction(src: Path, dst: Path) -> str:
    result = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(dst), str(src)],
        capture_output=True, text=True
    )
    if result.returncode == 0 and dst.exists():
        return 'junction'
    # fallback: real copy
    import shutil
    shutil.copytree(src, dst)
    return 'copy'


def main():
    OUT_ROOT.mkdir(parents=True, exist_ok=True)

    manifest = {}
    for patch_name, sample_list in PATCHES.items():
        patch_dir = OUT_ROOT / patch_name
        patch_dir.mkdir(exist_ok=True)
        print(f'\n=== {patch_name} ===')

        items = []
        sample_names_txt = []
        for rel_path in sample_list:
            src = PATCH_ROOT / Path(rel_path.replace('/', os.sep))
            sample_name = src.name
            dst = patch_dir / sample_name

            if dst.exists():
                print(f'  SKIP (exists): {sample_name}')
                mode = 'exists'
            else:
                mode = make_junction(src, dst)
                print(f'  {mode.upper()}: {sample_name}  <-- {rel_path}')

            items.append({'name': sample_name, 'source': rel_path, 'mode': mode})
            sample_names_txt.append(sample_name)

        # Write samples.txt
        (patch_dir / 'samples.txt').write_text('\n'.join(sample_names_txt) + '\n', encoding='utf-8')

        manifest[patch_name] = {
            'count': len(items),
            'items': items,
        }

    # Write manifest
    manifest_path = OUT_ROOT / 'patch_manifest.json'
    manifest_path.write_text(
        json.dumps({'total_patches': len(PATCHES), 'patches': manifest}, indent=2, ensure_ascii=False),
        encoding='utf-8'
    )

    print(f'\nDone. patches_win/ created at {OUT_ROOT}')
    print(f'Run: python run_patch_framework.py --patch-root samples/patches_win --patch patch_01')


if __name__ == '__main__':
    main()

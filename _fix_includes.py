import re

path = r'project_mutation_output\rerun_fungus_v7_20260423_023150\work\variant_build_37257755\Win32.Fungus\Win32.Fungus\includes.h'

# Read original from samples
orig = open(r'samples\malware_50\Win32.Fungus\Win32.Fungus\Win32.Fungus\includes.h', encoding='utf-8').read()

# Add wininet.h after shlwapi.lib pragma
new = orig.replace(
    '#pragma comment(lib, "shlwapi.lib")',
    '#pragma comment(lib, "shlwapi.lib")\n#include <wininet.h>\n#pragma comment(lib, "wininet.lib")'
)
open(path, 'w', encoding='utf-8').write(new)
print("Done:", new.count('wininet'), "wininet occurrences")

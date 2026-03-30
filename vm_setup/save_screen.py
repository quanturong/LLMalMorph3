from PIL import Image
import sys, glob, os
# find latest screen
files = sorted(glob.glob("/tmp/vm_screen*.ppm"), key=os.path.getmtime)
latest = files[-1] if files else "/tmp/vm_screen8.ppm"
print(f"Reading: {latest}")
img = Image.open(latest)
img.save("/mnt/e/LLMalMorph2/vm_setup/vm_screen.png")
print(f"Saved PNG: {img.size}")
gray = img.convert("L")
w, h = img.size
# More detailed rendering - use OCR-like approach
CHARS = " .:-=+*#%@"
for y in range(0, h, 16):  # every 16px = ~1 text row
    line = ""
    for x in range(0, w, 8):  # every 8px = ~1 text col
        p = gray.getpixel((x, y))
        idx = min(p * len(CHARS) // 256, len(CHARS) - 1)
        line += CHARS[idx]
    stripped = line.rstrip()
    if stripped.strip():
        print(f"{y:3d}|{stripped}")

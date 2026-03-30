import glob, os
from PIL import Image
files = sorted(glob.glob("/tmp/vm_screen*.ppm"), key=os.path.getmtime)
latest = files[-1] if files else "/tmp/vm_screen_now.ppm"
print(f"File: {latest}")
img = Image.open(latest)
gray = img.convert('L')
pixels = list(gray.getdata())
nonblack = sum(1 for p in pixels if p > 10)
print(f'Size: {img.size}, Non-black(>10): {nonblack}/{len(pixels)}, Min: {min(pixels)}, Max: {max(pixels)}')
w, h = img.size
CHARS = " .:-=+*#%@"
for y in range(0, h, 16):
    line = ""
    for x in range(0, w, 8):
        p = gray.getpixel((x, y))
        idx = min(p * len(CHARS) // 256, len(CHARS) - 1)
        line += CHARS[idx]
    stripped = line.rstrip()
    if stripped.strip():
        print(f"{y:3d}|{stripped}")

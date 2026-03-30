from PIL import Image
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "/opt/CAPEv2/vm_setup/screen.ppm"
img = Image.open(path)
w, h = img.size

# Full screen at maximum detail
cols, rows = 200, 60
bw, bh = w // cols, h // rows
chars = " .:-=+*#%@"

for r in range(rows):
    line = ""
    for c in range(cols):
        x0, y0 = c * bw, r * bh
        x1, y1 = x0 + bw, y0 + bh
        region = img.crop((x0, y0, x1, y1))
        pixels = list(region.getdata())
        avg = sum(sum(p[:3]) for p in pixels) / (len(pixels) * 3) if pixels else 0
        idx = min(int(avg / 256 * len(chars)), len(chars) - 1)
        line += chars[idx]
    print(line.rstrip())

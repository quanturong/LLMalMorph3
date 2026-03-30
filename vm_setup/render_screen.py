#!/usr/bin/env python3
from PIL import Image
import sys

path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/vm_screen_after_dl.ppm'
img = Image.open(path)
w, h = img.size
print(f'Image: {w}x{h}')
chars = ' .:-=+*#%@'
cols = 140
rows = 45
for r in range(rows):
    line = ''
    for c in range(cols):
        px = img.getpixel((c * w // cols, r * h // rows))
        brightness = sum(px[:3]) / (3 * 255)
        line += chars[int(brightness * (len(chars) - 1))]
    print(line)

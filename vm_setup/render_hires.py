#!/usr/bin/env python3
from PIL import Image
import sys

path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/vm_now.ppm'
img = Image.open(path)
w, h = img.size

# Focus on the CMD window area (top 75% of screen)
chars = ' .:-=+*#%@'
cols = 160
rows = 55

for r in range(rows):
    line = ''
    y = int(r * h * 0.72 / rows)
    for c in range(cols):
        x = c * w // cols
        px = img.getpixel((x, y))
        brightness = sum(px[:3]) / (3 * 255)
        line += chars[int(brightness * (len(chars) - 1))]
    print(line)

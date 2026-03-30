#!/bin/bash
# Take screenshot and render
(echo "screendump /opt/CAPEv2/vm_setup/screen.ppm"; sleep 2) | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock
sleep 1
python3 /mnt/e/LLMalMorph2/vm_setup/render_lower.py /opt/CAPEv2/vm_setup/screen.ppm

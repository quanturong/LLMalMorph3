#!/bin/bash
# Take screenshot via QEMU monitor
(echo "screendump /opt/CAPEv2/vm_setup/screen.ppm"; sleep 2) | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock
sleep 1
if [ -f /opt/CAPEv2/vm_setup/screen.ppm ]; then
    echo "Screenshot saved!"
    ls -la /opt/CAPEv2/vm_setup/screen.ppm
    python3 /mnt/e/LLMalMorph2/vm_setup/render_lower.py
else
    echo "Screenshot not found, trying alternative..."
    # Try with explicit socat timeout
    echo "screendump /root/screen.ppm" | socat -t 3 - UNIX-CONNECT:/tmp/qemu-monitor.sock
    sleep 2
    ls -la /root/screen.ppm 2>/dev/null
fi

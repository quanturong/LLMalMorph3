#!/bin/bash
echo "Waiting for VM to boot (checking every 5s for up to 2 minutes)..."
for i in $(seq 1 24); do
    sleep 5
    elapsed=$((i * 5))
    if ping -c 1 -W 1 192.168.122.100 2>/dev/null | grep -q "bytes from"; then
        echo ""
        echo "=== PING SUCCESS at ${elapsed}s! ==="
        ping -c 3 -W 2 192.168.122.100
        exit 0
    fi
    printf "."
done
echo ""
echo "=== Ping still failing after 120s ==="
echo "Checking ARP:"
arping -c 2 -I br0 192.168.122.100
echo "Checking ports:"
for port in 135 445 8000; do
    echo -n "Port $port: "
    timeout 3 nc -zv -w 2 192.168.122.100 $port 2>&1 || echo "timeout"
done
sleep 1
python3 /opt/CAPEv2/vm_setup/render_screen.py /tmp/vm_auto_setup.ppm

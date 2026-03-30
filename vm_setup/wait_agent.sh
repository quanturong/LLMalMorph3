#!/bin/bash
echo "Waiting for VM boot and agent startup..."
echo "Testing ping and port 8000 every 10s for 3 minutes..."

for i in $(seq 1 18); do
    sleep 10
    elapsed=$((i * 10))
    
    # Test ping
    ping_ok=0
    if ping -c 1 -W 1 192.168.122.100 >/dev/null 2>&1; then
        ping_ok=1
    fi
    
    # Test port 8000
    port_ok=0
    if timeout 2 nc -z 192.168.122.100 8000 2>/dev/null; then
        port_ok=1
    fi
    
    echo "[${elapsed}s] ping=$ping_ok port8000=$port_ok"
    
    if [ "$port_ok" -eq 1 ]; then
        echo ""
        echo "=== AGENT IS RUNNING! ==="
        echo "Testing agent status:"
        curl -s http://192.168.122.100:8000/status 2>/dev/null || echo "(no response from curl)"
        exit 0
    fi
done

echo ""
echo "=== Agent not running after 3 minutes ==="
echo "Final connectivity check:"
ping -c 2 -W 2 192.168.122.100
for port in 135 445 3389 8000; do
    echo -n "Port $port: "
    timeout 2 nc -zv 192.168.122.100 $port 2>&1
done

#!/bin/bash
echo "Testing TCP ports on 192.168.122.100..."
for port in 135 445 3389 8000; do
    echo -n "Port $port: "
    timeout 3 nc -zv -w 2 192.168.122.100 $port 2>&1 || echo "timeout/closed"
done
echo "Done"

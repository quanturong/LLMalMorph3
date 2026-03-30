#!/bin/bash
SOCK="/tmp/qemu-monitor.sock"

send_key() {
    printf "sendkey $1\n" | socat - UNIX-CONNECT:$SOCK
    sleep 0.1
}

send_string() {
    local str="$1"
    for (( i=0; i<${#str}; i++ )); do
        local c="${str:$i:1}"
        case "$c" in
            [a-z]) send_key "$c" ;;
            [A-Z]) send_key "shift-$(echo $c | tr 'A-Z' 'a-z')" ;;
            [0-9]) send_key "$c" ;;
            ' ') send_key "spc" ;;
            '-') send_key "minus" ;;
            '_') send_key "shift-minus" ;;
            '.') send_key "dot" ;;
            '/') send_key "slash" ;;
            \\) send_key "backslash" ;;
            ':') send_key "shift-semicolon" ;;
            ';') send_key "semicolon" ;;
            '"') send_key "shift-apostrophe" ;;
            "'") send_key "apostrophe" ;;
            '=') send_key "equal" ;;
            ',') send_key "comma" ;;
            *) echo "WARN: Unknown char: [$c]" ;;
        esac
    done
}

# Close Sysprep with Alt+F4
echo "=== Close Sysprep ==="
send_key "alt-f4"
sleep 3

# Open admin CMD: Win+R, type cmd, Ctrl+Shift+Enter for admin
echo "=== Open Run ==="
send_key "meta_l-r"
sleep 3

echo "=== Type cmd ==="
send_string "cmd"
sleep 0.5

# Press Enter (not Ctrl+Shift+Enter which may not work)
send_key "ret"
sleep 3

# Disable firewall first (short command)
echo "=== Disable firewall ==="
send_string "netsh advfirewall set allprofiles state off"
send_key "ret"
sleep 3

# Set static IP
echo "=== Set IP ==="
send_string 'netsh interface ip set address "Ethernet" static 192.168.122.100 255.255.255.0 192.168.122.1'
send_key "ret"
sleep 5

# Screenshot
printf "screendump /tmp/vm_manual_ip.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

echo "=== Check ping ==="
ping -c 2 -W 2 192.168.122.100 || echo "Still not reachable"

echo "=== Try Ethernet 2 ==="
send_string 'netsh interface ip set address "Ethernet 2" static 192.168.122.100 255.255.255.0 192.168.122.1'
send_key "ret"
sleep 5

ping -c 2 -W 2 192.168.122.100 || echo "Still not reachable"

echo "Done!"

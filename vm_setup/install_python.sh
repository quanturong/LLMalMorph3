#!/bin/bash
SOCK=/tmp/qemu-monitor.sock

send() {
    printf "sendkey %s\n" "$1" | socat - UNIX-CONNECT:$SOCK
    sleep 0.12
}

send_string() {
    local str="$1"
    for (( i=0; i<${#str}; i++ )); do
        local c="${str:$i:1}"
        case "$c" in
            [a-z]) send "$c" ;;
            [A-Z]) send "shift-$(echo $c | tr A-Z a-z)" ;;
            [0-9]) send "$c" ;;
            ' ') send "spc" ;;
            '-') send "minus" ;;
            '.') send "dot" ;;
            '/') send "slash" ;;
            \\) send "backslash" ;;
            ':') send "shift-semicolon" ;;
            '_') send "shift-minus" ;;
            '=') send "equal" ;;
            ',') send "comma" ;;
            ';') send "semicolon" ;;
            '"') send "shift-apostrophe" ;;
            *) echo "Unknown char: $c" ;;
        esac
    done
}

echo "=== Step 1: Close Sysprep dialog ==="
# Alt+F4 to close Sysprep dialog
send "alt-F4"
sleep 3

echo "=== Step 2: Open CMD via Win+R ==="
send "meta_l-r"
sleep 3
send_string "cmd"
sleep 0.5
send "ret"
sleep 3

echo "=== Step 3: Install Python ==="
send_string "C:\\python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0"
sleep 0.5
send "ret"
echo "Waiting 90s for Python install..."
sleep 90

echo "=== Step 4: Start the CAPE agent ==="
# Try the common Python install paths
send_string "\"C:\\Program Files\\Python310\\python.exe\" C:\\cape_agent\\agent.py"
sleep 0.5
send "ret"
sleep 5

echo "=== Done ==="

#!/bin/bash
SOCK="/tmp/qemu-monitor.sock"

send_key() {
    printf "sendkey $1\n" | socat - UNIX-CONNECT:$SOCK
    sleep 0.08
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
            '(') send_key "shift-9" ;;
            ')') send_key "shift-0" ;;
            '&') send_key "shift-7" ;;
            '|') send_key "shift-backslash" ;;
            '!') send_key "shift-1" ;;
            '@') send_key "shift-2" ;;
            '#') send_key "shift-3" ;;
            '%') send_key "shift-5" ;;
            *) echo "WARN: Unknown char: [$c]" ;;
        esac
    done
}

# Break any stuck command
echo "=== Ctrl+C ==="
send_key "ctrl-c"
sleep 2
send_key "ctrl-c"
sleep 2

# Check if at prompt
echo "=== Try ipconfig ==="
send_string "ipconfig"
send_key "ret"
sleep 3

printf "screendump /tmp/vm_ipconfig.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

echo "=== Set IP manually ==="
# Try setting IP on various adapter names
send_string 'netsh interface ip set address "Ethernet" static 192.168.122.100 255.255.255.0 192.168.122.1'
send_key "ret"
sleep 3

printf "screendump /tmp/vm_setip.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

echo "Done!"

#!/bin/bash
SOCK=/tmp/qemu-monitor.sock

send() {
    printf "sendkey %s\n" "$1" | socat - UNIX-CONNECT:$SOCK
    sleep 0.15
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
            "'") send "apostrophe" ;;
            '(') send "shift-9" ;;
            ')') send "shift-0" ;;
            '!') send "shift-1" ;;
            '@') send "shift-2" ;;
            '#') send "shift-3" ;;
            '$') send "shift-4" ;;
            '%') send "shift-5" ;;
            '&') send "shift-7" ;;
            '*') send "shift-8" ;;
            '+') send "shift-equal" ;;
            '<') send "shift-comma" ;;
            '>') send "shift-dot" ;;
            '?') send "shift-slash" ;;
            '{') send "shift-bracket_left" ;;
            '}') send "shift-bracket_right" ;;
            '[') send "bracket_left" ;;
            ']') send "bracket_right" ;;
            '|') send "shift-backslash" ;;
            '~') send "shift-grave_accent" ;;
            *) echo "Unknown char: $c" ;;
        esac
    done
}

echo "=== Trying to open CMD and disable firewall ==="

# First, try closing any Sysprep dialog by pressing Enter
send "ret"
sleep 1

# Press Escape to dismiss any dialogs
send "escape"
sleep 1

# Try Win+R to open Run dialog
send "meta_l-r"
sleep 3

# Type cmd
send_string "cmd"
sleep 0.5

# Press Enter to open CMD
send "ret"
sleep 3

# Type the firewall disable command
send_string "netsh advfirewall set allprofiles state off"
sleep 0.5
send "ret"
sleep 3

# Also try setting the IP explicitly
send_string "netsh interface ip set address \"Ethernet\" static 192.168.122.100 255.255.255.0 192.168.122.1"
sleep 0.5
send "ret"
sleep 3

echo "=== Done sending commands ==="

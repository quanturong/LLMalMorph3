#!/bin/bash
# Send keystrokes to QEMU VM via monitor socket
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

send_enter() {
    send_key "ret"
    sleep 1
}

echo "=== Download setup2.bat ==="
send_string 'powershell -c "iwr http://10.0.2.2:8888/setup2.bat -o C:\s2.bat"'
send_enter  

echo "=== Wait 10s for download ==="
sleep 10

echo "=== Run setup2.bat ==="
send_string 'C:\s2.bat'
send_enter

echo "=== Sent! Waiting for Python download + install (will take ~5 min) ==="

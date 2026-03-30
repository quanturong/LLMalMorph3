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
            *) echo "WARN: Unknown char: [$c]" ;;
        esac
    done
}

# Make sure we're at a CMD prompt
echo "=== Ctrl+C to break ==="
send_key "ctrl-c"
sleep 1
send_key "ctrl-c"
sleep 1

echo "=== cls ==="
send_string "cls"
send_key "ret"
sleep 1

echo "=== ipconfig /renew ==="
send_string "ipconfig /renew"
send_key "ret"
sleep 10

printf "screendump /tmp/vm_iprenew.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

echo "Done!"

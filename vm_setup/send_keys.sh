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
            '+') send_key "shift-equal" ;;
            ',') send_key "comma" ;;
            '(') send_key "shift-9" ;;
            ')') send_key "shift-0" ;;
            '{') send_key "shift-bracket_left" ;;
            '}') send_key "shift-bracket_right" ;;
            '[') send_key "bracket_left" ;;
            ']') send_key "bracket_right" ;;
            '&') send_key "shift-7" ;;
            '|') send_key "shift-backslash" ;;
            '!') send_key "shift-1" ;;
            '@') send_key "shift-2" ;;
            '#') send_key "shift-3" ;;
            '$') send_key "shift-4" ;;
            '%') send_key "shift-5" ;;
            '^') send_key "shift-6" ;;
            '*') send_key "shift-8" ;;
            '~') send_key "shift-grave_accent" ;;
            '`') send_key "grave_accent" ;;
            '<') send_key "shift-comma" ;;
            '>') send_key "shift-dot" ;;
            '?') send_key "shift-slash" ;;
            *) echo "Unknown char: $c" ;;
        esac
    done
}

send_enter() {
    send_key "ret"
    sleep 0.5
}

echo "=== Sending download command to VM ==="

# First, take a screenshot to see current state
printf "screendump /tmp/vm_screen_before.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

# Type the PowerShell download command
# powershell -c "iwr http://10.0.2.2:8888/setup_all.bat -o C:\s.bat"
send_string 'powershell -c "iwr http://10.0.2.2:8888/setup_all.bat -o C:\s.bat"'
send_enter

echo "=== Download command sent, waiting 10 seconds ==="
sleep 10

# Take screenshot after download
printf "screendump /tmp/vm_screen_after_dl.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

# Now run the bat file
send_string 'C:\s.bat'
send_enter

echo "=== Setup script started ==="
sleep 5

# Take screenshot
printf "screendump /tmp/vm_screen_running.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

echo "=== Done sending commands ==="

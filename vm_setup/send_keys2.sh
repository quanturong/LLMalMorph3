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
            '&') send_key "shift-7" ;;
            '|') send_key "shift-backslash" ;;
            '!') send_key "shift-1" ;;
            '@') send_key "shift-2" ;;
            '#') send_key "shift-3" ;;
            '%') send_key "shift-5" ;;
            *) echo "Unknown char: $c" ;;
        esac
    done
}

send_enter() {
    send_key "ret"
    sleep 0.5
}

send_ctrl_c() {
    send_key "ctrl-c"
    sleep 0.3
}

echo "=== Step 1: Take initial screenshot ==="
printf "screendump /tmp/vm_screen_s1.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

echo "=== Step 2: Cancel any pending command with Ctrl+C ==="
send_ctrl_c
sleep 0.5

echo "=== Step 3: Send download command ==="
# Use curl to download - simpler than PowerShell
# curl http://10.0.2.2:8888/setup_all.bat -o C:\s.bat
send_string 'powershell -c "iwr http://10.0.2.2:8888/setup_all.bat -o C:\s.bat"'
send_enter

echo "=== Waiting 15 seconds for download ==="
sleep 15

echo "=== Step 4: Screenshot after download ==="
printf "screendump /tmp/vm_screen_s2.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

echo "=== Step 5: Run the setup batch file ==="
send_string 'C:\s.bat'
send_enter

echo "=== Waiting 10 seconds ==="
sleep 10

echo "=== Step 6: Screenshot after running setup ==="
printf "screendump /tmp/vm_screen_s3.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

echo "=== All done ==="

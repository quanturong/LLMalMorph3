#!/bin/bash
SOCK="/tmp/qemu-monitor.sock"

send_key() {
    printf "sendkey $1\n" | socat - UNIX-CONNECT:$SOCK
    sleep 0.12
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

# Step 1: Click on desktop to dismiss any focus issues
echo "Step 1: Click desktop"
send_key "meta_l-d"
sleep 2

# Step 2: Close Sysprep if open
echo "Step 2: Close Sysprep (Alt+F4)"
send_key "alt-f4"
sleep 2

# Step 3: Take screenshot to see state
echo "Step 3: Screenshot"
printf "screendump /tmp/vm_step3.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

# Step 4: Open CMD via Win+R
echo "Step 4: Open Run"
send_key "meta_l-r"
sleep 3

# Step 5: Type cmd
echo "Step 5: Type cmd"
send_string "cmd"
send_key "ret"
sleep 3

# Step 6: Screenshot to see CMD
echo "Step 6: Screenshot"
printf "screendump /tmp/vm_step6.ppm\n" | socat - UNIX-CONNECT:$SOCK
sleep 1

# Step 7: Disable firewall
echo "Step 7: Disable firewall"
send_string "netsh advfirewall set allprofiles state off"
send_key "ret"
sleep 5

echo "Step 7b: Check if ping works now"
ping -c 1 -W 2 192.168.122.100 && echo "PING WORKS!" || echo "Still blocked"

# Step 8: Run full setup
echo "Step 8: Run setup"
send_string 'C:\final_setup.bat'
send_key "ret"

echo "Done - setup starting!"

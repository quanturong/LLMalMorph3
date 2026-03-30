#!/bin/bash
# Copy agent startup to all startup folders on the VM disk

# Source file
SRC=/mnt/e/LLMalMorph2/vm_setup/start_agent.bat

# Startup locations
LOCATIONS=(
    "/mnt/win10/start_agent.bat"
    "/mnt/win10/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/start_agent.bat"
    "/mnt/win10/Users/Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/start_agent.bat"
    "/mnt/win10/Users/cape/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/start_agent.bat"
)

for dest in "${LOCATIONS[@]}"; do
    dir=$(dirname "$dest")
    if [ -d "$dir" ]; then
        cp "$SRC" "$dest"
        echo "OK: $dest"
    else
        echo "SKIP (dir not found): $dest"
    fi
done

echo ""
echo "=== Verifying key files ==="
echo -n "Python3: "; ls /mnt/win10/Python3/python.exe 2>&1
echo -n "Agent: "; ls /mnt/win10/cape_agent/agent.py 2>&1
echo -n "Root bat: "; ls /mnt/win10/start_agent.bat 2>&1

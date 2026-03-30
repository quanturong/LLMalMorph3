#!/bin/bash
SOFTWARE_HIVE="/mnt/win10/Windows/System32/config/SOFTWARE"

echo "=== Set RunOnce to start agent ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Microsoft\Windows\CurrentVersion\RunOnce
ed CapeSetup
C:\start_agent.bat
q
y
CMDS

echo "=== Set Run key (persistent) ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Microsoft\Windows\CurrentVersion\Run
nv 1 CapeAgent
ed CapeAgent
C:\start_agent.bat
q
y
CMDS

echo "=== Verify Winlogon AutoLogon ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Microsoft\Windows NT\CurrentVersion\Winlogon
cat AutoAdminLogon
cat DefaultUserName
q
n
CMDS

echo "=== Done ==="

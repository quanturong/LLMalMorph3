#!/bin/bash

SYSTEM_HIVE="/mnt/win10/Windows/System32/config/SYSTEM"
SOFTWARE_HIVE="/mnt/win10/Windows/System32/config/SOFTWARE"

echo "=== Fixing firewall in SYSTEM hive ==="
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile
ed EnableFirewall
0
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile
ed EnableFirewall
0
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
ed EnableFirewall
0
q
y
CMDS

echo "=== Setting RunOnce in SOFTWARE hive ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Microsoft\Windows\CurrentVersion\RunOnce
nv 1 CapeSetup
ed CapeSetup
C:\final_setup.bat
q
y
CMDS

echo "=== Disabling Defender in SOFTWARE hive ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Policies\Microsoft\Windows Defender
nv 4 DisableAntiSpyware
ed DisableAntiSpyware
1
q
y
CMDS

echo "=== Done with registry edits ==="

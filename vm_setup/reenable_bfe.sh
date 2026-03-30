#!/bin/bash
SYSTEM_HIVE="/mnt/win10/Windows/System32/config/SYSTEM"

echo "=== Re-enable BFE (Start=2) ==="
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services\BFE
ed Start
2
q
y
CMDS

echo "=== Re-enable mpssvc (Start=2) - firewall will use EnableFirewall=0 policy ==="
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services\mpssvc
ed Start
2
q
y
CMDS

echo "=== Verify all values ==="
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services\BFE
cat Start
cd \ControlSet001\Services\mpssvc
cat Start
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile
cat EnableFirewall
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile
cat EnableFirewall
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
cat EnableFirewall
q
n
CMDS

echo "=== Done ==="

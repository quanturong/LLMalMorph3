#!/bin/bash
set -e

echo "=== Mounting disk ==="
qemu-nbd --connect=/dev/nbd0 /opt/CAPEv2/vm_setup/win10-cape.qcow2
sleep 2
ntfsfix /dev/nbd0p2 2>/dev/null || true
mount -t ntfs-3g /dev/nbd0p2 /mnt/win10
echo "Mounted!"

SYSTEM_HIVE="/mnt/win10/Windows/System32/config/SYSTEM"
SOFTWARE_HIVE="/mnt/win10/Windows/System32/config/SOFTWARE"

echo "=== Creating registry import file ==="
# Create a .reg file to disable firewall via reged
cat > /tmp/disable_firewall.reg << 'EOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile]
"EnableFirewall"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile]
"EnableFirewall"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile]
"EnableFirewall"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MpsSvc]
"Start"=dword:00000004
EOF

# Use reged to import into SYSTEM hive
# reged needs the paths relative to HKLM, and the hive corresponds to SYSTEM
echo "=== Importing into SYSTEM hive ==="
# First check what ControlSet is active using chntpw
echo "Checking ControlSets..."
chntpw -e "$SYSTEM_HIVE" << 'CMDS' 2>/dev/null | grep -E "ControlSet|Select|Current"
ls Select
cat Select\Current
q
CMDS

# reged can import .reg files
# Format: reged -I -C <hivefile> <prefix> <regfile>
# The SYSTEM hive maps to HKLM\SYSTEM, so we use prefix HKEY_LOCAL_MACHINE\SYSTEM
# For ControlSet001 (usually the active one):

# Create a simpler approach: use chntpw directly to set values
echo "=== Disabling firewall via chntpw ==="
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile
ed EnableFirewall
4
0
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile
ed EnableFirewall
4
0
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
ed EnableFirewall
4
0
cd \ControlSet001\Services\MpsSvc
ed Start
4
4
q
y
CMDS

echo "=== Disabling Windows Defender in SOFTWARE hive ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Policies\Microsoft\Windows Defender
nk Real-Time Protection
cd Real-Time Protection
nv 4 DisableRealtimeMonitoring
ed DisableRealtimeMonitoring
4
1
cd \Policies\Microsoft\Windows Defender
nv 4 DisableAntiSpyware
ed DisableAntiSpyware
4
1
q
y
CMDS

echo "=== Setting RunOnce for final_setup.bat ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Microsoft\Windows\CurrentVersion\RunOnce
nv 1 CapeSetup
ed CapeSetup
1
C:\final_setup.bat
q
y
CMDS

echo "=== Unmounting ==="
sync
umount /mnt/win10
qemu-nbd --disconnect /dev/nbd0
echo "=== Done! ==="

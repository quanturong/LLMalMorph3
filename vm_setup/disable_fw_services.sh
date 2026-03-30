#!/bin/bash
SYSTEM_HIVE="/mnt/win10/Windows/System32/config/SYSTEM"
SOFTWARE_HIVE="/mnt/win10/Windows/System32/config/SOFTWARE"

echo "=== Step 1: Disable mpssvc (Firewall) service ==="
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services\mpssvc
ed Start
4
q
y
CMDS

echo "=== Step 2: Disable BFE (Base Filtering Engine) service ==="
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services\BFE
ed Start
4
q
y
CMDS

echo "=== Step 3: Verify EnableFirewall=0 ==="
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile
cat EnableFirewall
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile
cat EnableFirewall
cd \ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
cat EnableFirewall
q
n
CMDS

echo "=== Step 4: Set AutoLogon in SOFTWARE hive ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Microsoft\Windows NT\CurrentVersion\Winlogon
ed AutoAdminLogon
1
ed DefaultUserName
Administrator
ed DefaultPassword
cape
q
y
CMDS

echo "=== Step 5: Add Active Setup command ==="
chntpw -e "$SOFTWARE_HIVE" << 'CMDS'
cd Microsoft\Active Setup\Installed Components
nk {CAPE-SETUP-001}
cd {CAPE-SETUP-001}
nv 1 StubPath
ed StubPath
cmd /c C:\final_setup.bat
nv 1 Version
ed Version
1,0,0,0
q
y
CMDS

echo "=== All registry modifications complete ==="

#!/bin/bash
SYSTEM_HIVE="/mnt/win10/Windows/System32/config/SYSTEM"

echo "=== Finding firewall service keys ==="
# Search for firewall-related services
chntpw -e "$SYSTEM_HIVE" << 'CMDS'
cd ControlSet001\Services
ls mpssvc
ls MpsSvc
ls MPSSVC
ls BFE
ls bfe
ls SharedAccess
q
n
CMDS

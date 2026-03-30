#!/bin/bash
# Update files on mounted Windows disk
SRC="/mnt/e/LLMalMorph2/vm_setup/final_setup.bat"
DST1="/mnt/win10/final_setup.bat"
DST2="/mnt/win10/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/final_setup.bat"

cp "$SRC" "$DST1"
cp "$SRC" "$DST2"
echo "Updated both copies of final_setup.bat"

# Verify
ls -la "$DST1" "$DST2"

# Unmount disk
sync
umount /mnt/win10
qemu-nbd --disconnect /dev/nbd0
echo "Disk unmounted."

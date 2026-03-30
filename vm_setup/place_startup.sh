#!/bin/bash
STARTUP="/mnt/win10/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"
mkdir -p "$STARTUP"
cp /mnt/win10/final_setup.bat "$STARTUP/final_setup.bat"
echo "Script placed in Startup folder!"
ls -la "$STARTUP/"

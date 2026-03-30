@echo off
:: CAPE Agent Startup Script
:: Disable firewall first
netsh advfirewall set allprofiles state off >nul 2>&1

:: Set static IP if DHCP didn't assign correctly
:: netsh interface ip set address "Ethernet" static 192.168.122.100 255.255.255.0 192.168.122.1

:: Kill any existing agent
taskkill /f /im python.exe >nul 2>&1

:: Start the CAPE agent
start "" /b C:\Python3\python.exe C:\cape_agent\agent.py

:: Keep the window open
exit

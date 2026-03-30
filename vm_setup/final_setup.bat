@echo off
echo === CAPE VM Final Setup ===

echo Disabling Windows Defender...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
sc config WinDefend start= disabled
sc stop WinDefend 2>nul

echo Disabling Firewall...
netsh advfirewall set allprofiles state off

echo Disabling Windows Update...
sc config wuauserv start= disabled
sc stop wuauserv 2>nul
sc config UsoSvc start= disabled
sc stop UsoSvc 2>nul

echo Disabling UAC...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f

echo Disabling SmartScreen...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f

echo Power plan...
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0

echo Installing Python 3.10 from C:\python_installer.exe ...
if exist C:\python_installer.exe (
    C:\python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    echo Waiting 120 seconds for Python installation...
    timeout /t 120 /nobreak
    echo Deleting Python installer...
    del C:\python_installer.exe
) else (
    echo Python installer not found, skipping...
)

echo Setting agent autorun...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v CapeAgent /t REG_SZ /d "python.exe C:\cape_agent\agent.py" /f

echo Setting auto-logon for Administrator...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d Administrator /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "" /f

echo Setting IP to 192.168.122.100...
netsh interface ip set address "Ethernet" static 192.168.122.100 255.255.255.0 192.168.122.1 2>nul
netsh interface ip set address "Ethernet 2" static 192.168.122.100 255.255.255.0 192.168.122.1 2>nul
netsh interface ip set address "Ethernet Instance 0" static 192.168.122.100 255.255.255.0 192.168.122.1 2>nul
netsh interface ip set dns "Ethernet" static 8.8.8.8 2>nul
netsh interface ip set dns "Ethernet 2" static 8.8.8.8 2>nul

echo Removing self from Startup...
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\final_setup.bat" 2>nul

echo === Setup Complete ===
echo System configured for CAPE.

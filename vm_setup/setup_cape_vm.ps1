# CAPE VM Setup Script - Runs automatically on first logon
# This script configures the Windows guest for CAPE sandbox analysis

$ErrorActionPreference = "Continue"
$LogFile = "C:\cape_setup.log"

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts - $msg" | Tee-Object -FilePath $LogFile -Append
}

Log "=== CAPE VM Setup Starting ==="

# 1. Disable Windows Defender
Log "Disabling Windows Defender..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue

    # Disable via registry
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -Type DWord -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -Force

    # Disable Defender services
    Set-Service -Name WinDefend -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name WdNisSvc -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name WinDefend -Force -ErrorAction SilentlyContinue
    Stop-Service -Name WdNisSvc -Force -ErrorAction SilentlyContinue

    Log "Windows Defender disabled."
} catch {
    Log "Warning: Some Defender settings could not be changed: $_"
}

# 2. Disable Windows Firewall
Log "Disabling Windows Firewall..."
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Log "Firewall disabled."
} catch {
    Log "Warning: Could not disable firewall: $_"
}

# 3. Disable Windows Update
Log "Disabling Windows Update..."
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name UsoSvc -Force -ErrorAction SilentlyContinue
    Set-Service -Name UsoSvc -StartupType Disabled -ErrorAction SilentlyContinue
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
    Log "Windows Update disabled."
} catch {
    Log "Warning: Could not disable Windows Update: $_"
}

# 4. Disable UAC
Log "Disabling UAC..."
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force
    Log "UAC disabled."
} catch {
    Log "Warning: Could not disable UAC: $_"
}

# 5. Set static IP (192.168.122.100 on the VirtIO adapter)
Log "Setting static IP..."
try {
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if ($adapter) {
        # Remove existing IP configuration
        Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

        # Set static IP
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress "192.168.122.100" -PrefixLength 24 -DefaultGateway "192.168.122.1" -ErrorAction Stop
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("8.8.8.8","8.8.4.4")
        Log "Static IP set to 192.168.122.100 on adapter $($adapter.Name)"
    } else {
        Log "ERROR: No active network adapter found!"
    }
} catch {
    Log "Warning: Could not set static IP: $_"
}

# 6. Download and install Python
Log "Downloading Python 3.10..."
$pythonUrl = "https://www.python.org/ftp/python/3.10.11/python-3.10.11-amd64.exe"
$pythonInstaller = "C:\python_installer.exe"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
    Log "Python downloaded. Installing..."

    # Silent install Python
    Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0", "Include_pip=1" -Wait -NoNewWindow
    Log "Python installed."

    # Clean up installer
    Remove-Item $pythonInstaller -Force -ErrorAction SilentlyContinue
} catch {
    Log "ERROR: Could not download/install Python: $_"
    # Fallback: try embedded Python
    Log "Trying embedded Python fallback..."
    try {
        $embUrl = "https://www.python.org/ftp/python/3.10.11/python-3.10.11-embed-amd64.zip"
        $embZip = "C:\python_embed.zip"
        Invoke-WebRequest -Uri $embUrl -OutFile $embZip -UseBasicParsing
        Expand-Archive -Path $embZip -DestinationPath "C:\Python310" -Force
        $env:PATH = "C:\Python310;$env:PATH"
        [System.Environment]::SetEnvironmentVariable("PATH", "C:\Python310;$([System.Environment]::GetEnvironmentVariable('PATH', 'Machine'))", "Machine")
        Remove-Item $embZip -Force -ErrorAction SilentlyContinue
        Log "Embedded Python installed to C:\Python310"
    } catch {
        Log "ERROR: Could not install embedded Python either: $_"
    }
}

# 7. Copy agent.py from setup CD and configure autorun
Log "Setting up CAPE agent..."
try {
    # Create agent directory
    New-Item -Path "C:\cape_agent" -ItemType Directory -Force | Out-Null

    # Find agent.py on any drive
    $agentFound = $false
    foreach ($drive in (Get-PSDrive -PSProvider FileSystem).Root) {
        $agentPath = Join-Path $drive "agent.py"
        if (Test-Path $agentPath) {
            Copy-Item $agentPath "C:\cape_agent\agent.py" -Force
            Log "Copied agent.py from $agentPath"
            $agentFound = $true
            break
        }
    }

    if (-not $agentFound) {
        # Download from CAPE host
        Log "agent.py not found on drives, downloading from CAPE host..."
        try {
            Invoke-WebRequest -Uri "http://192.168.122.1:8090/agent/agent.py" -OutFile "C:\cape_agent\agent.py" -UseBasicParsing -ErrorAction Stop
            Log "Downloaded agent.py from CAPE host"
            $agentFound = $true
        } catch {
            Log "Could not download agent.py from host: $_"
        }
    }

    if ($agentFound) {
        # Create startup batch file to run agent
        $startupBat = @"
@echo off
cd C:\cape_agent
C:\Python310\python.exe agent.py 2>nul || python.exe agent.py 2>nul || "C:\Program Files\Python310\python.exe" agent.py
"@
        $startupFolder = [System.Environment]::GetFolderPath("CommonStartup")
        $startupBat | Out-File -FilePath "$startupFolder\cape_agent.bat" -Encoding ASCII -Force
        Log "Agent autorun configured at $startupFolder\cape_agent.bat"

        # Also create a scheduled task for reliability
        $action = New-ScheduledTaskAction -Execute "python.exe" -Argument "C:\cape_agent\agent.py" -WorkingDirectory "C:\cape_agent"
        $trigger = New-ScheduledTaskTrigger -AtLogon
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0)
        $principal = New-ScheduledTaskPrincipal -UserId "cape" -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName "CAPE Agent" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
        Log "Scheduled task 'CAPE Agent' created."
    } else {
        Log "ERROR: agent.py not found anywhere!"
    }
} catch {
    Log "Warning: Error setting up agent: $_"
}

# 8. Disable unnecessary services
Log "Disabling unnecessary services..."
$servicesToDisable = @(
    "WSearch",       # Windows Search
    "SysMain",       # Superfetch
    "DiagTrack",     # Diagnostics Tracking
    "dmwappushservice", # WAP Push
    "MapsBroker",    # Downloaded Maps Manager
    "lfsvc",         # Geolocation Service
    "SharedAccess",  # Internet Connection Sharing
    "RemoteRegistry" # Remote Registry
)
foreach ($svc in $servicesToDisable) {
    try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    } catch {}
}
Log "Unnecessary services disabled."

# 9. Disable SmartScreen
Log "Disabling SmartScreen..."
try {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force
    Log "SmartScreen disabled."
} catch {
    Log "Warning: Could not disable SmartScreen: $_"
}

# 10. Enable PowerShell remoting (for management)
Log "Enabling PowerShell remoting..."
try {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force -ErrorAction SilentlyContinue
    Log "PowerShell remoting enabled."
} catch {
    Log "Warning: Could not enable PS remoting: $_"
}

# 11. Set power plan to high performance (prevent sleep)
Log "Setting power plan..."
try {
    powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    powercfg /change monitor-timeout-ac 0
    powercfg /change standby-timeout-ac 0
    powercfg /change hibernate-timeout-ac 0
    Log "Power plan set to High Performance, sleep disabled."
} catch {
    Log "Warning: Could not set power plan: $_"
}

# 12. Create a marker file
"CAPE VM setup completed at $(Get-Date)" | Out-File "C:\cape_setup_complete.txt" -Force

Log "=== CAPE VM Setup Complete ==="
Log "IP: 192.168.122.100"
Log "User: cape / Password: cape"
Log "Agent: C:\cape_agent\agent.py"
Log ""
Log "VM is ready for CAPE snapshot."

# Start the agent immediately
Log "Starting CAPE agent now..."
try {
    Start-Process -FilePath "python.exe" -ArgumentList "C:\cape_agent\agent.py" -WorkingDirectory "C:\cape_agent" -WindowStyle Hidden
    Log "Agent started."
} catch {
    Log "Warning: Could not start agent immediately: $_"
}

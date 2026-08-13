#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Pritrak DLP Agent Remote Installer
    
.DESCRIPTION
    One-liner installation: irm http://SERVER:8080/api/install/agent.ps1 | iex
    
.NOTES
    Copyright (C) 2026 Pritrak Security
#>

param(
    [string]$ServerIP,
    [string]$Mode = "Monitor",
    [string]$InstallPath = "$env:ProgramFiles\Pritrak\DLPAgent"
)

# Auto-detect server IP from the request URL if not provided
if (-not $ServerIP) {
    # Try to get from environment or use the URL we were fetched from
    $ServerIP = $env:PRITRAK_SERVER
    if (-not $ServerIP) {
        # Default - should be replaced by backend dynamically
        $ServerIP = "{{SERVER_IP}}"
    }
}

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Colors
function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  PRITRAK DLP AGENT INSTALLER" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Info "Server: $ServerIP"
Write-Info "Mode: $Mode"
Write-Info "Install Path: $InstallPath"
Write-Host ""

# Check admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "This script requires Administrator privileges"
    Write-Host ""
    Write-Host "Run PowerShell as Administrator and try again:" -ForegroundColor Yellow
    Write-Host "  irm http://$ServerIP`:8080/api/install/agent.ps1 | iex" -ForegroundColor White
    exit 1
}

# Create install directory
Write-Info "Creating installation directory..."
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallPath\logs" -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallPath\config" -Force | Out-Null

# Generate device ID
$DeviceId = [guid]::NewGuid().ToString()
$Hostname = $env:COMPUTERNAME
$Username = $env:USERNAME

# Create configuration
$config = @{
    server_ip = $ServerIP
    server_port = 8080
    device_id = $DeviceId
    hostname = $Hostname
    mode = $Mode
    heartbeat_interval = 30
    log_level = "info"
    features = @{
        file_monitoring = $true
        usb_monitoring = $true
        network_monitoring = ($Mode -eq "Full")
        email_monitoring = ($Mode -eq "Full")
        clipboard_monitoring = $true
    }
}

$configPath = "$InstallPath\config\config.json"
$config | ConvertTo-Json -Depth 5 | Set-Content $configPath -Encoding UTF8
Write-Success "Configuration saved to $configPath"

# Download the monitoring agent script
Write-Info "Downloading agent components..."

$agentScript = @'
#Requires -RunAsAdministrator
# Pritrak DLP Monitoring Agent
# This runs as a Windows Service

param(
    [string]$ConfigPath = "$env:ProgramFiles\Pritrak\DLPAgent\config\config.json"
)

$ErrorActionPreference = "SilentlyContinue"

# Load config
$config = Get-Content $ConfigPath | ConvertFrom-Json
$ServerUrl = "http://$($config.server_ip):$($config.server_port)"
$DeviceId = $config.device_id

function Send-Event {
    param($EventData)
    try {
        $EventData.device_id = $DeviceId
        $EventData.hostname = $env:COMPUTERNAME
        $EventData.username = $env:USERNAME
        $EventData.timestamp = (Get-Date).ToString("o")
        
        Invoke-RestMethod -Uri "$ServerUrl/api/events" `
            -Method POST `
            -ContentType "application/json" `
            -Body ($EventData | ConvertTo-Json -Depth 5) `
            -TimeoutSec 5 | Out-Null
    } catch {}
}

function Send-Heartbeat {
    try {
        $heartbeat = @{
            device_id = $DeviceId
            hostname = $env:COMPUTERNAME
            status = "online"
            agent_version = "2.0.0"
            os_version = [System.Environment]::OSVersion.VersionString
        }
        Invoke-RestMethod -Uri "$ServerUrl/api/devices/heartbeat" `
            -Method POST `
            -ContentType "application/json" `
            -Body ($heartbeat | ConvertTo-Json) `
            -TimeoutSec 5 | Out-Null
    } catch {}
}

# Register USB event watcher
$usbQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBControllerDevice'"
$usbWatcher = New-Object System.Management.ManagementEventWatcher $usbQuery

Register-ObjectEvent -InputObject $usbWatcher -EventName EventArrived -Action {
    Send-Event @{
        event_type = "USB_DEVICE_CONNECTED"
        event_code = 1
        device = @{
            type = "USB"
        }
    }
} | Out-Null
$usbWatcher.Start()

# File system watcher for sensitive paths
$sensitiveePaths = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "C:\Confidential"
)

$watchers = @()
foreach ($path in $sensitivePaths) {
    if (Test-Path $path) {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $path
        $watcher.Filter = "*.*"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        
        Register-ObjectEvent -InputObject $watcher -EventName Created -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            Send-Event @{
                event_type = "FILE_CREATED"
                event_code = 16
                file = @{
                    path = $filePath
                    name = [System.IO.Path]::GetFileName($filePath)
                }
            }
        } | Out-Null
        
        $watchers += $watcher
    }
}

# Network connection monitor
$networkJob = Start-Job -ScriptBlock {
    param($ServerUrl, $DeviceId)
    while ($true) {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
            Where-Object { $_.RemotePort -in @(80, 443, 25, 587, 465) }
        
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -in @("chrome", "firefox", "msedge", "OUTLOOK")) {
                # Log but don't block in monitor mode
            }
        }
        Start-Sleep -Seconds 5
    }
} -ArgumentList $ServerUrl, $DeviceId

# Main heartbeat loop
Write-Host "Pritrak DLP Agent started - Device ID: $DeviceId"
while ($true) {
    Send-Heartbeat
    Start-Sleep -Seconds $config.heartbeat_interval
}
'@

$agentScript | Set-Content "$InstallPath\PritrakAgent.ps1" -Encoding UTF8
Write-Success "Agent script installed"

# Create Windows Service wrapper
Write-Info "Creating Windows Service..."

$serviceScript = @"
# Pritrak DLP Service Wrapper
`$ErrorActionPreference = "SilentlyContinue"
`$configPath = "$InstallPath\config\config.json"
`$logPath = "$InstallPath\logs\agent.log"

Start-Transcript -Path `$logPath -Append

& "$InstallPath\PritrakAgent.ps1" -ConfigPath `$configPath

Stop-Transcript
"@

$serviceScript | Set-Content "$InstallPath\ServiceWrapper.ps1" -Encoding UTF8

# Use NSSM or create scheduled task
$taskName = "PritrakDLPAgent"

# Remove existing task if any
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Create scheduled task to run at startup
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallPath\PritrakAgent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Write-Success "Scheduled task created: $taskName"

# Register device with server
Write-Info "Registering device with server..."
try {
    $registration = @{
        device_id = $DeviceId
        hostname = $Hostname
        username = $Username
        os_version = [System.Environment]::OSVersion.VersionString
        agent_version = "2.0.0"
        install_mode = $Mode
    }
    
    $response = Invoke-RestMethod -Uri "http://$ServerIP`:8080/api/devices/register" `
        -Method POST `
        -ContentType "application/json" `
        -Body ($registration | ConvertTo-Json) `
        -TimeoutSec 10
    
    Write-Success "Device registered successfully!"
    Write-Host "         Device ID: $DeviceId" -ForegroundColor Gray
} catch {
    Write-Warn "Could not register with server (will retry on agent start)"
}

# Start the agent now
Write-Info "Starting agent..."
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 2

$task = Get-ScheduledTask -TaskName $taskName
if ($task.State -eq "Running") {
    Write-Success "Agent is running!"
} else {
    Write-Warn "Agent scheduled but not running yet"
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Device ID:    $DeviceId" -ForegroundColor White
Write-Host "  Server:       http://$ServerIP`:8080" -ForegroundColor White
Write-Host "  Mode:         $Mode" -ForegroundColor White
Write-Host "  Install Path: $InstallPath" -ForegroundColor White
Write-Host ""
Write-Host "  View in dashboard: http://$ServerIP`:5173" -ForegroundColor Cyan
Write-Host ""

# Save device ID for reference
$DeviceId | Set-Content "$InstallPath\device_id.txt"

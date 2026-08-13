<#
.SYNOPSIS
    PRITRAK DLP Agent - Universal Installer
    
.DESCRIPTION
    Installs the Pritrak DLP agent with automatic fallback:
    1. Tries to install kernel-mode drivers (minifilter + WFP) for maximum protection
    2. Falls back to usermode PowerShell agent if kernel drivers fail
    
.EXAMPLE
    irm http://10.10.1.55:8080/api/install/agent-kernel.ps1 | iex
    
.NOTES
    Requires Administrator privileges
    Copyright (C) 2026 Pritrak Security
#>

param(
    [string]$ServerIP,
    [switch]$SkipTestSigningCheck,
    [switch]$UsermodeOnly,
    [string]$InstallPath = "$env:ProgramFiles\Pritrak\DLP"
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Pause-AndExit {
    param([int]$ExitCode = 1)
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch {}
    exit $ExitCode
}

function Write-Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  PRITRAK DLP AGENT - UNIVERSAL INSTALLER v2.0" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step { param($step, $msg) Write-Host "[$step] $msg" -ForegroundColor Cyan }
function Write-OK { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-FAIL { param($msg) Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-WARN { param($msg) Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Info { param($msg) Write-Host "  $msg" -ForegroundColor Gray }

# ============================================================================
# ERROR HANDLING
# ============================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

trap {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  ERROR OCCURRED" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Yellow
    Pause-AndExit 1
}

# ============================================================================
# CONFIGURATION
# ============================================================================

$AgentVersion = "2.0.0"
$MinifilterServiceName = "PritrakDLPFilter"
$WfpServiceName = "PritrakDLPNetwork"
$global:KernelModeActive = $false
$global:UserModeActive = $false
$global:DeviceId = $null

# Auto-detect server IP if not provided
if (-not $ServerIP) {
    $ServerIP = "{{SERVER_IP}}"
    if ($ServerIP -eq "{{SERVER_IP}}") {
        $ServerIP = "10.10.1.55"
    }
}

$BaseUrl = "http://${ServerIP}:8080"

# ============================================================================
# CLEANUP FUNCTION - Remove old agents
# ============================================================================

function Remove-OldAgents {
    Write-Step "0" "Cleaning up existing agents..."
    
    $cleaned = $false
    
    # Stop and remove scheduled tasks
    $taskPatterns = @("*Pritrak*", "*DLP*Agent*", "*dlp*agent*")
    foreach ($pattern in $taskPatterns) {
        $tasks = Get-ScheduledTask -TaskName $pattern -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            try {
                Stop-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Info "Removed scheduled task: $($task.TaskName)"
                $cleaned = $true
            } catch {}
        }
    }
    
    # Stop any running agent PowerShell processes (but not our own installer)
    $currentPID = $PID
    $agentProcesses = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue | 
        Where-Object { 
            $_.ProcessId -ne $currentPID -and 
            $_.CommandLine -and 
            ($_.CommandLine -like "*agent*" -or $_.CommandLine -like "*DLP*" -or $_.CommandLine -like "*Pritrak*")
        }
    
    foreach ($proc in $agentProcesses) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Info "Stopped agent process: PID $($proc.ProcessId)"
            $cleaned = $true
        } catch {}
    }
    
    # Unload existing kernel drivers
    fltmc unload $MinifilterServiceName 2>&1 | Out-Null
    sc.exe stop $WfpServiceName 2>&1 | Out-Null
    sc.exe delete $MinifilterServiceName 2>&1 | Out-Null
    sc.exe delete $WfpServiceName 2>&1 | Out-Null
    
    # Check for driver files
    $driverPath = "$env:SystemRoot\System32\drivers"
    if (Test-Path "$driverPath\PritrakDLPFilter.sys") {
        Remove-Item "$driverPath\PritrakDLPFilter.sys" -Force -ErrorAction SilentlyContinue
        $cleaned = $true
    }
    if (Test-Path "$driverPath\PritrakDLPNetwork.sys") {
        Remove-Item "$driverPath\PritrakDLPNetwork.sys" -Force -ErrorAction SilentlyContinue
        $cleaned = $true
    }
    
    # Remove old installation directory config (keep device_id if exists)
    $oldDeviceId = $null
    if (Test-Path "$InstallPath\device_id.txt") {
        $oldDeviceId = Get-Content "$InstallPath\device_id.txt" -ErrorAction SilentlyContinue
    }
    
    if ($cleaned) {
        Write-OK "Old agents cleaned up"
    } else {
        Write-OK "No existing agents found"
    }
    
    Start-Sleep -Milliseconds 500
    
    return $oldDeviceId
}

# ============================================================================
# DRIVER HELPER FUNCTIONS
# ============================================================================

function Test-KernelDriver {
    param([string]$ServiceName)
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return ($service -and $service.Status -eq 'Running')
}

function Test-MinifilterLoaded {
    param([string]$FilterName)
    $result = fltmc filters 2>$null | Select-String -Pattern $FilterName
    return ($null -ne $result)
}

function Get-DriverLoadError {
    param([string]$ServiceName)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Service Control Manager'
            Level = 2,3
        } -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$ServiceName*" }
        
        if ($events) {
            return $events[0].Message
        }
    } catch {}
    return "No specific error found in event logs"
}

function Install-MinifilterDriver {
    param([string]$DriverPath)
    
    Write-Step "3a" "Installing Minifilter driver..."
    
    $sysDriverPath = "$env:SystemRoot\System32\drivers"
    
    try {
        Copy-Item -Path $DriverPath -Destination "$sysDriverPath\PritrakDLPFilter.sys" -Force -ErrorAction Stop
        Write-OK "Driver copied to system32\drivers"
    } catch {
        Write-FAIL "Failed to copy driver: $_"
        return $false
    }
    
    # Remove existing service if present
    sc.exe delete $MinifilterServiceName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
    
    # Create service
    $result = sc.exe create $MinifilterServiceName type= filesys start= demand binPath= "$sysDriverPath\PritrakDLPFilter.sys" group= "FSFilter Activity Monitor" depend= FltMgr 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-FAIL "sc.exe create failed: $result"
        return $false
    }
    
    # Set altitude in registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$MinifilterServiceName\Instances"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "DefaultInstance" -Value $MinifilterServiceName
    
    $instancePath = "$regPath\$MinifilterServiceName"
    New-Item -Path $instancePath -Force | Out-Null
    Set-ItemProperty -Path $instancePath -Name "Altitude" -Value "360000"
    Set-ItemProperty -Path $instancePath -Name "Flags" -Value 0 -Type DWord
    
    Write-OK "Minifilter service created with altitude 360000"
    return $true
}

function Install-WfpDriver {
    param([string]$DriverPath)
    
    Write-Step "3b" "Installing WFP driver..."
    
    $sysDriverPath = "$env:SystemRoot\System32\drivers"
    
    try {
        Copy-Item -Path $DriverPath -Destination "$sysDriverPath\PritrakDLPNetwork.sys" -Force -ErrorAction Stop
        Write-OK "Driver copied to system32\drivers"
    } catch {
        Write-FAIL "Failed to copy driver: $_"
        return $false
    }
    
    # Remove existing service if present
    sc.exe delete $WfpServiceName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
    
    $result = sc.exe create $WfpServiceName type= kernel start= demand binPath= "$sysDriverPath\PritrakDLPNetwork.sys" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-WARN "sc.exe create WFP failed: $result"
        return $false
    }
    
    Write-OK "WFP service created"
    return $true
}

function Start-KernelDrivers {
    Write-Step "4" "Loading kernel drivers..."
    
    $minifilterLoaded = $false
    $wfpLoaded = $false
    
    # Try to load minifilter
    Write-Info "Loading minifilter via fltmc..."
    $fltResult = fltmc load $MinifilterServiceName 2>&1
    Start-Sleep -Seconds 2
    
    if (Test-MinifilterLoaded $MinifilterServiceName) {
        Write-OK "Minifilter loaded successfully"
        $minifilterLoaded = $true
    } else {
        Write-FAIL "Minifilter failed to load"
        Write-Info "fltmc output: $fltResult"
        
        # Check event log for details
        $errorMsg = Get-DriverLoadError $MinifilterServiceName
        Write-Info "Event log: $errorMsg"
    }
    
    # Try to load WFP driver
    Write-Info "Loading WFP driver..."
    $scResult = sc.exe start $WfpServiceName 2>&1
    Start-Sleep -Seconds 1
    
    if (Test-KernelDriver $WfpServiceName) {
        Write-OK "WFP driver loaded successfully"
        $wfpLoaded = $true
    } else {
        Write-WARN "WFP driver not started: $scResult"
    }
    
    return @{
        MinifilterLoaded = $minifilterLoaded
        WfpLoaded = $wfpLoaded
    }
}

# ============================================================================
# USERMODE AGENT FUNCTIONS
# ============================================================================

function Install-UsermodeAgent {
    Write-Step "5" "Installing usermode monitoring agent..."
    
    # Create install directory
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    New-Item -ItemType Directory -Path "$InstallPath\logs" -Force | Out-Null
    
    # Download the PowerShell agent
    try {
        Invoke-WebRequest -Uri "$BaseUrl/api/install/simple-agent.ps1" -OutFile "$InstallPath\simple-agent.ps1" -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        Write-OK "Downloaded simple-agent.ps1"
    } catch {
        Write-WARN "Failed to download agent, creating embedded version..."
        
        # Create embedded agent script
        $agentScript = @'
# Pritrak DLP Usermode Agent
param(
    [string]$BackendUrl = "{{BACKEND_URL}}",
    [string]$DeviceId = "{{DEVICE_ID}}",
    [string]$WatchPath = "$env:USERPROFILE\Desktop",
    [int]$HeartbeatIntervalSeconds = 30
)

$global:EventQueue = [System.Collections.ArrayList]::new()
$global:EventLock = [System.Object]::new()
$global:MaxContentSize = 1048576
$global:TextExtensions = @('.txt', '.doc', '.docx', '.csv', '.json', '.xml', '.md', '.log', '.ps1', '.py', '.js')

function Get-FileContentForClassification {
    param([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) { return "" }
        $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
        if ($global:TextExtensions -notcontains $ext) { return "" }
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        if ($fileInfo.Length -gt $global:MaxContentSize -or $fileInfo.Length -lt 3) { return "" }
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        if ($content.Length -gt 102400) { $content = $content.Substring(0, 102400) }
        return $content
    } catch { return "" }
}

function Add-FileEvent {
    param([string]$EventType, [string]$FilePath, [string]$FileName)
    # Get actual username from file path when running as SYSTEM
    $actualUsername = $env:USERNAME
    if ($FilePath -match 'C:\\Users\\([^\\]+)\\') { $actualUsername = $matches[1] }
    $event = @{
        event_type = $EventType
        file_path = $FilePath
        file_name = $FileName
        file_size = 0
        file_content = ""
        username = $actualUsername
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    if (Test-Path $FilePath -ErrorAction SilentlyContinue) {
        try {
            $fileInfo = Get-Item $FilePath
            $event.file_size = $fileInfo.Length
            if ($EventType -in @("file_created", "file_modified")) {
                $event.file_content = Get-FileContentForClassification -FilePath $FilePath
            }
        } catch {}
    }
    [System.Threading.Monitor]::Enter($global:EventLock)
    try { $global:EventQueue.Add($event) | Out-Null }
    finally { [System.Threading.Monitor]::Exit($global:EventLock) }
}

function Send-Heartbeat {
    $heartbeat = @{
        device_id = $DeviceId
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os_version = [System.Environment]::OSVersion.VersionString
        agent_version = "2.0.0-ps"
        ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1 -ExpandProperty IPAddress)
    } | ConvertTo-Json
    try { Invoke-RestMethod -Uri "$BackendUrl/api/devices/heartbeat" -Method POST -Body $heartbeat -ContentType "application/json" -ErrorAction Stop | Out-Null } catch {}
}

function Send-EventBatch {
    $eventsToSend = @()
    [System.Threading.Monitor]::Enter($global:EventLock)
    try {
        if ($global:EventQueue.Count -gt 0) {
            $eventsToSend = $global:EventQueue.ToArray()
            $global:EventQueue.Clear()
        }
    } finally { [System.Threading.Monitor]::Exit($global:EventLock) }
    if ($eventsToSend.Count -eq 0) { return }
    $batch = @{ device_id = $DeviceId; events = $eventsToSend } | ConvertTo-Json -Depth 10
    try { Invoke-RestMethod -Uri "$BackendUrl/api/v1/events/batch" -Method POST -Body $batch -ContentType "application/json" -ErrorAction Stop | Out-Null } catch {}
}

# Watch all common folders
$watchPaths = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
$watchers = @()

foreach ($path in $watchPaths) {
    if (Test-Path $path) {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $path
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        
        Register-ObjectEvent -InputObject $watcher -EventName Created -Action { Add-FileEvent -EventType "file_created" -FilePath $Event.SourceEventArgs.FullPath -FileName $Event.SourceEventArgs.Name } | Out-Null
        Register-ObjectEvent -InputObject $watcher -EventName Changed -Action { Add-FileEvent -EventType "file_modified" -FilePath $Event.SourceEventArgs.FullPath -FileName $Event.SourceEventArgs.Name } | Out-Null
        Register-ObjectEvent -InputObject $watcher -EventName Deleted -Action { Add-FileEvent -EventType "file_deleted" -FilePath $Event.SourceEventArgs.FullPath -FileName $Event.SourceEventArgs.Name } | Out-Null
        Register-ObjectEvent -InputObject $watcher -EventName Renamed -Action { Add-FileEvent -EventType "file_renamed" -FilePath $Event.SourceEventArgs.FullPath -FileName $Event.SourceEventArgs.Name } | Out-Null
        
        $watchers += $watcher
    }
}

# Send initial heartbeat
Send-Heartbeat

$lastHeartbeat = Get-Date
$lastEventSend = Get-Date

while ($true) {
    $now = Get-Date
    if (($now - $lastHeartbeat).TotalSeconds -ge $HeartbeatIntervalSeconds) {
        Send-Heartbeat
        $lastHeartbeat = $now
    }
    if (($now - $lastEventSend).TotalSeconds -ge 5) {
        Send-EventBatch
        $lastEventSend = $now
    }
    Start-Sleep -Milliseconds 500
}
'@
        $agentScript = $agentScript -replace '\{\{BACKEND_URL\}\}', $BaseUrl
        $agentScript = $agentScript -replace '\{\{DEVICE_ID\}\}', $global:DeviceId
        Set-Content -Path "$InstallPath\simple-agent.ps1" -Value $agentScript -Encoding UTF8
        Write-OK "Created embedded agent"
    }
    
    # Create scheduled task to run agent at startup
    $taskName = "PritrakDLPAgent"
    
    # Remove existing task
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallPath\simple-agent.ps1`" -BackendUrl `"$BaseUrl`" -DeviceId `"$global:DeviceId`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-OK "Scheduled task created: $taskName"
    
    # Start the agent now
    Write-Info "Starting agent..."
    Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    $taskInfo = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($taskInfo -and $taskInfo.State -eq 'Running') {
        Write-OK "Usermode agent is running"
        $global:UserModeActive = $true
    } else {
        # Try starting directly
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallPath\simple-agent.ps1`" -BackendUrl `"$BaseUrl`" -DeviceId `"$global:DeviceId`"" -WindowStyle Hidden
        Write-OK "Agent started directly"
        $global:UserModeActive = $true
    }
    
    return $true
}

function Configure-Device {
    Write-Step "2" "Configuring device..."
    
    # Only generate new ID if we don't have one already (from cleanup)
    if (-not $global:DeviceId) {
        $global:DeviceId = [guid]::NewGuid().ToString()
    }
    
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    New-Item -ItemType Directory -Path "$InstallPath\config" -Force | Out-Null
    
    $config = @{
        device_id = $global:DeviceId
        server_ip = $ServerIP
        server_port = 8080
        mode = "hybrid"
        version = $AgentVersion
        installed_at = (Get-Date).ToString("o")
    }
    
    $config | ConvertTo-Json -Depth 5 | Set-Content "$InstallPath\config\config.json" -Encoding UTF8
    $global:DeviceId | Set-Content "$InstallPath\device_id.txt"
    
    Write-OK "Device ID: $global:DeviceId"
    
    return $true
}

function Register-WithBackend {
    Write-Step "6" "Registering with backend..."
    
    try {
        $registration = @{
            device_id = $global:DeviceId
            hostname = $env:COMPUTERNAME
            username = $env:USERNAME
            os_version = [System.Environment]::OSVersion.VersionString
            agent_version = $AgentVersion
            enforcement_mode = if ($global:KernelModeActive) { "kernel" } else { "usermode" }
        }
        
        Invoke-RestMethod -Uri "$BaseUrl/api/devices/register" -Method POST -ContentType "application/json" -Body ($registration | ConvertTo-Json) -TimeoutSec 10 | Out-Null
        Write-OK "Registered with backend"
        return $true
    } catch {
        # Try alternate endpoint
        try {
            Invoke-RestMethod -Uri "$BaseUrl/api/devices" -Method POST -ContentType "application/json" -Body ($registration | ConvertTo-Json) -TimeoutSec 10 | Out-Null
            Write-OK "Registered with backend (alternate endpoint)"
            return $true
        } catch {
            Write-WARN "Backend registration failed - will retry on heartbeat"
            return $false
        }
    }
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================

Write-Banner

# Step 0: Clean up existing agents FIRST
$oldDeviceId = Remove-OldAgents

# Step 1: Check admin privileges
Write-Step "1" "Checking prerequisites..."

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-FAIL "Administrator privileges required"
    Write-Host ""
    Write-Host "Please run PowerShell as Administrator:" -ForegroundColor Yellow
    Write-Host "  1. Right-click PowerShell" -ForegroundColor Gray
    Write-Host "  2. Select 'Run as Administrator'" -ForegroundColor Gray
    Write-Host "  3. Run: irm http://${ServerIP}:8080/api/install/kernel | iex" -ForegroundColor White
    Pause-AndExit 1
}
Write-OK "Running as Administrator"

# Configure device (reuse old device ID if available)
if ($oldDeviceId) {
    Write-Info "Reusing existing device ID: $oldDeviceId"
    $global:DeviceId = $oldDeviceId
}
Configure-Device

# Determine installation mode
$kernelModeAvailable = $false

if (-not $UsermodeOnly) {
    # Check test signing for kernel mode
    if (-not $SkipTestSigningCheck) {
        $testSigningEnabled = bcdedit /enum 2>$null | Select-String -Pattern "testsigning\s+Yes"
        if ($testSigningEnabled) {
            Write-OK "Test signing enabled - kernel mode available"
            $kernelModeAvailable = $true
        } else {
            Write-WARN "Test signing not enabled - kernel drivers will likely fail"
            Write-Info "Kernel installation will be attempted, but may fall back to usermode"
        }
    } else {
        $kernelModeAvailable = $true
    }
}

# Try kernel mode installation
if (-not $UsermodeOnly) {
    Write-Step "3" "Downloading and installing kernel drivers..."
    
    $driversPath = "$env:TEMP\PritrakDrivers"
    New-Item -ItemType Directory -Path $driversPath -Force | Out-Null
    
    try {
        Write-Info "Downloading minifilter driver..."
        Invoke-WebRequest -Uri "$BaseUrl/api/drivers/minifilter.sys" -OutFile "$driversPath\PritrakDLPFilter.sys" -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        
        Write-Info "Downloading WFP driver..."
        Invoke-WebRequest -Uri "$BaseUrl/api/drivers/wfp.sys" -OutFile "$driversPath\PritrakDLPNetwork.sys" -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        
        Write-OK "Drivers downloaded"
        
        # Install drivers
        $miniInstalled = Install-MinifilterDriver -DriverPath "$driversPath\PritrakDLPFilter.sys"
        $wfpInstalled = Install-WfpDriver -DriverPath "$driversPath\PritrakDLPNetwork.sys"
        
        if ($miniInstalled) {
            # Try to load drivers
            $loadResult = Start-KernelDrivers
            
            if ($loadResult.MinifilterLoaded) {
                $global:KernelModeActive = $true
                Write-OK "Kernel mode protection ACTIVE"
            } else {
                Write-WARN "Kernel drivers installed but failed to load"
                Write-Info "Falling back to usermode agent..."
            }
        }
    } catch {
        Write-WARN "Kernel driver installation failed: $_"
        Write-Info "Falling back to usermode agent..."
    }
}

# Install usermode agent (always, as backup or primary)
Install-UsermodeAgent

# Register with backend
Register-WithBackend

# Send initial heartbeat
Write-Step "7" "Sending initial heartbeat..."
try {
    $heartbeat = @{
        device_id = $global:DeviceId
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os_version = [System.Environment]::OSVersion.VersionString
        agent_version = $AgentVersion
        ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1 -ExpandProperty IPAddress)
    } | ConvertTo-Json
    
    Invoke-RestMethod -Uri "$BaseUrl/api/devices/heartbeat" -Method POST -Body $heartbeat -ContentType "application/json" -TimeoutSec 10 | Out-Null
    Write-OK "Heartbeat sent"
} catch {
    Write-WARN "Heartbeat failed (will retry automatically)"
}

# Final summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

$kernelStatus = if ($global:KernelModeActive) { "ACTIVE (kernel-level protection)" } else { "NOT ACTIVE" }
$usermodeStatus = if ($global:UserModeActive) { "ACTIVE (file monitoring + classification)" } else { "NOT ACTIVE" }

Write-Host "  Kernel Mode:   $kernelStatus" -ForegroundColor $(if ($global:KernelModeActive) { 'Green' } else { 'Yellow' })
Write-Host "  Usermode:      $usermodeStatus" -ForegroundColor $(if ($global:UserModeActive) { 'Green' } else { 'Red' })
Write-Host ""
Write-Host "  Device ID:     $global:DeviceId" -ForegroundColor Gray
Write-Host "  Install Path:  $InstallPath" -ForegroundColor Gray
Write-Host "  Server:        $ServerIP" -ForegroundColor Gray
Write-Host ""
Write-Host "  Dashboard: http://${ServerIP}:5173" -ForegroundColor Cyan
Write-Host ""

if (-not $global:KernelModeActive -and -not $UsermodeOnly) {
    Write-Host "  NOTE: Kernel drivers did not load. For full kernel protection:" -ForegroundColor Yellow
    Write-Host "    1. Run: bcdedit /set testsigning on" -ForegroundColor White
    Write-Host "    2. Reboot the computer" -ForegroundColor White
    Write-Host "    3. Run: fltmc load PritrakDLPFilter" -ForegroundColor White
    Write-Host ""
}

Write-Host "  The agent is monitoring files and sending events to the server." -ForegroundColor Green
Write-Host "  Create a file with 'admin' in the content to test classification." -ForegroundColor Gray
Write-Host ""

Pause-AndExit 0

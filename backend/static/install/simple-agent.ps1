# Pritrak DLP Agent - PowerShell Version v2.0
# Monitors file changes across all user folders and sends events to backend

param(
    [string]$BackendUrl = "http://localhost:8080",
    [string]$DeviceId = "",
    [int]$HeartbeatIntervalSeconds = 30,
    [int]$EventBatchIntervalSeconds = 5
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Generate device ID if not provided
if ([string]::IsNullOrEmpty($DeviceId)) {
    $hostname = $env:COMPUTERNAME
    $DeviceId = "DEVICE-$hostname-" + [guid]::NewGuid().ToString().Substring(0, 8)
}

# Get all user profile paths to monitor
$watchPaths = @()

# Add current user paths if available
if ($env:USERPROFILE -and (Test-Path $env:USERPROFILE)) {
    $watchPaths += "$env:USERPROFILE\Desktop"
    $watchPaths += "$env:USERPROFILE\Documents"
    $watchPaths += "$env:USERPROFILE\Downloads"
}

# Also scan all user profiles on the system (for SYSTEM account)
$usersFolder = "C:\Users"
if (Test-Path $usersFolder) {
    Get-ChildItem -Path $usersFolder -Directory | Where-Object { 
        $_.Name -notin @("Public", "Default", "Default User", "All Users") 
    } | ForEach-Object {
        $userPath = $_.FullName
        @("Desktop", "Documents", "Downloads") | ForEach-Object {
            $fullPath = Join-Path $userPath $_
            if ((Test-Path $fullPath) -and ($fullPath -notin $watchPaths)) {
                $watchPaths += $fullPath
            }
        }
    }
}

# Text file extensions for content reading
$global:TextExtensions = @('.txt', '.doc', '.docx', '.csv', '.json', '.xml', '.md', '.log', '.ps1', '.py', '.js', '.html', '.htm', '.ini', '.cfg', '.yaml', '.yml')
$global:MaxContentSize = 1048576  # 1MB

# Event queue
$global:EventQueue = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
$global:Watchers = @()

# ============================================================================
# LOGGING
# ============================================================================

$logFile = "$env:ProgramFiles\Pritrak\DLP\logs\agent.log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
    try {
        Add-Content -Path $logFile -Value $logLine -ErrorAction SilentlyContinue
    } catch {}
    
    # Also write to console if interactive
    if ($Host.UI.RawUI.WindowTitle) {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "OK" { "Green" }
            default { "Gray" }
        }
        Write-Host $logLine -ForegroundColor $color
    }
}

# ============================================================================
# FILE CONTENT HELPER
# ============================================================================

function Get-FileContentForClassification {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath -ErrorAction SilentlyContinue)) { return "" }
        
        $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
        if ($global:TextExtensions -notcontains $ext) { return "" }
        
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        if ($fileInfo.Length -gt $global:MaxContentSize -or $fileInfo.Length -lt 3) { return "" }
        
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        if ($content.Length -gt 102400) { $content = $content.Substring(0, 102400) }
        
        return $content
    } catch {
        return ""
    }
}

# ============================================================================
# EVENT HANDLING
# ============================================================================

function Add-FileEvent {
    param(
        [string]$EventType,
        [string]$FilePath,
        [string]$FileName
    )
    
    # Skip temp files and system files
    if ($FileName -like "~*" -or $FileName -like "*.tmp" -or $FilePath -like "*\AppData\*") {
        return
    }
    
    # Try to get actual user from file path or file owner
    $actualUsername = $env:USERNAME
    if ($FilePath -match 'C:\\Users\\([^\\]+)\\') {
        $actualUsername = $matches[1]
    }
    
    $event = @{
        event_type = $EventType
        file_path = $FilePath
        file_name = $FileName
        file_size = 0
        file_content = ""
        username = $actualUsername
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    
    # Get file info and content
    if (Test-Path $FilePath -ErrorAction SilentlyContinue) {
        try {
            $fileInfo = Get-Item $FilePath -ErrorAction Stop
            $event.file_size = $fileInfo.Length
            
            # Read content for create/modify events
            if ($EventType -in @("file_created", "file_modified")) {
                $event.file_content = Get-FileContentForClassification -FilePath $FilePath
            }
        } catch {}
    }
    
    $global:EventQueue.Add($event) | Out-Null
    
    $hasContent = if ($event.file_content) { " [+content:$($event.file_content.Length)chars]" } else { "" }
    Write-Log "Queued: $EventType - $FileName$hasContent"
}

function Send-EventBatch {
    if ($global:EventQueue.Count -eq 0) { return }
    
    # Copy and clear queue atomically
    $eventsToSend = @($global:EventQueue.ToArray())
    $global:EventQueue.Clear()
    
    if ($eventsToSend.Count -eq 0) { return }
    
    $batch = @{
        device_id = $DeviceId
        events = $eventsToSend
    } | ConvertTo-Json -Depth 10 -Compress

    try {
        $response = Invoke-RestMethod -Uri "$BackendUrl/api/v1/events/batch" -Method POST -Body $batch -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
        Write-Log "Sent $($eventsToSend.Count) events - Processed: $($response.processed)" "OK"
    } catch {
        Write-Log "Event batch failed: $_" "ERROR"
        # Re-queue events
        foreach ($ev in $eventsToSend) {
            $global:EventQueue.Add($ev) | Out-Null
        }
    }
}

function Send-Heartbeat {
    $heartbeat = @{
        device_id = $DeviceId
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os_version = [System.Environment]::OSVersion.VersionString
        agent_version = "2.0.0-ps"
        ip_address = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.*" } | Select-Object -First 1 -ExpandProperty IPAddress)
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri "$BackendUrl/api/devices/heartbeat" -Method POST -Body $heartbeat -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop | Out-Null
        Write-Log "Heartbeat sent" "OK"
    } catch {
        Write-Log "Heartbeat failed: $_" "WARN"
    }
}

function Register-Device {
    $registration = @{
        device_id = $DeviceId
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os_version = [System.Environment]::OSVersion.VersionString
        agent_version = "2.0.0-ps"
        ip_address = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.*" } | Select-Object -First 1 -ExpandProperty IPAddress)
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri "$BackendUrl/api/devices" -Method POST -Body $registration -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop | Out-Null
        Write-Log "Device registered: $DeviceId" "OK"
    } catch {
        Write-Log "Device registration (may already exist): $_" "WARN"
    }
}

# ============================================================================
# FILE WATCHER
# ============================================================================

function Start-AllWatchers {
    foreach ($watchPath in $watchPaths) {
        if (-not (Test-Path $watchPath)) { continue }
        
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $watchPath
            $watcher.IncludeSubdirectories = $true
            $watcher.EnableRaisingEvents = $true
            $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite -bor [System.IO.NotifyFilters]::DirectoryName
            
            Register-ObjectEvent -InputObject $watcher -EventName Created -Action {
                Add-FileEvent -EventType "file_created" -FilePath $Event.SourceEventArgs.FullPath -FileName $Event.SourceEventArgs.Name
            } | Out-Null
            
            Register-ObjectEvent -InputObject $watcher -EventName Changed -Action {
                Add-FileEvent -EventType "file_modified" -FilePath $Event.SourceEventArgs.FullPath -FileName $Event.SourceEventArgs.Name
            } | Out-Null
            
            Register-ObjectEvent -InputObject $watcher -EventName Deleted -Action {
                Add-FileEvent -EventType "file_deleted" -FilePath $Event.SourceEventArgs.FullPath -FileName $Event.SourceEventArgs.Name
            } | Out-Null
            
            Register-ObjectEvent -InputObject $watcher -EventName Renamed -Action {
                Add-FileEvent -EventType "file_renamed" -FilePath $Event.SourceEventArgs.FullPath -FileName $Event.SourceEventArgs.Name
            } | Out-Null
            
            $global:Watchers += $watcher
            Write-Log "Watching: $watchPath" "OK"
        } catch {
            Write-Log "Failed to watch $watchPath : $_" "ERROR"
        }
    }
}

# ============================================================================
# MAIN
# ============================================================================

Write-Log "========================================" "INFO"
Write-Log "  Pritrak DLP Agent v2.0 Starting" "INFO"
Write-Log "========================================" "INFO"
Write-Log "Backend: $BackendUrl" "INFO"
Write-Log "Device ID: $DeviceId" "INFO"
Write-Log "Watch paths: $($watchPaths.Count) folders" "INFO"

try {
    # Register and heartbeat
    Register-Device
    Send-Heartbeat
    
    # Start file watchers
    Start-AllWatchers
    
    if ($global:Watchers.Count -eq 0) {
        Write-Log "No valid watch paths found!" "ERROR"
        exit 1
    }
    
    Write-Log "Agent running - monitoring $($global:Watchers.Count) folders" "OK"
    
    $lastHeartbeat = Get-Date
    $lastEventSend = Get-Date
    
    # Main loop
    while ($true) {
        $now = Get-Date
        
        if (($now - $lastHeartbeat).TotalSeconds -ge $HeartbeatIntervalSeconds) {
            Send-Heartbeat
            $lastHeartbeat = $now
        }
        
        if (($now - $lastEventSend).TotalSeconds -ge $EventBatchIntervalSeconds) {
            Send-EventBatch
            $lastEventSend = $now
        }
        
        Start-Sleep -Milliseconds 500
    }
} finally {
    foreach ($w in $global:Watchers) {
        try { $w.Dispose() } catch {}
    }
    Get-EventSubscriber | Unregister-Event -ErrorAction SilentlyContinue
    Write-Log "Agent stopped" "WARN"
}

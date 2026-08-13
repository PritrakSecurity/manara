# PRITRAK DLP Agent - Bootstrap Installer v1.0
# Install: C:\Program Files\PritrakDLP (binaries) / C:\ProgramData\PritrakDLP (state)
# Mode: MONITOR_ONLY - the agent observes, classifies, and reports. It NEVER blocks.
#Requires -RunAsAdministrator
[CmdletBinding()]
param()
 $ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

 $Server = '{{SERVER_URL}}'
 $Token  = ''
 $InstallDir = Join-Path $env:ProgramFiles 'PritrakDLP'
 $DataDir    = Join-Path $env:ProgramData  'PritrakDLP'
 $Svc        = 'PritrakDLP'

function Write-Step($m) { Write-Host "[Pritrak] $m" -ForegroundColor Cyan }
function Fail($m) { 
    Write-Host "[Pritrak] ERROR: $m" -ForegroundColor Red
    Write-Host ""
    Write-Host "Press Enter to exit..." -ForegroundColor Yellow
    Read-Host
    exit 1 
}

# --- preflight ---
if (-not [Environment]::Is64BitOperatingSystem) { Fail 'x64 Windows required.' }
 $build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
if ($build -lt 17763) { Fail "Windows build $build unsupported (need 17763+)." }

# --- manifest + download ---
Write-Step 'Fetching agent manifest'
 $mf = $null
try {
    $mf = Invoke-RestMethod "$Server/api/v1/install/manifest?arch=x64&channel=stable" -TimeoutSec 30
} catch {
    Fail "Agent backend not available at $Server (the /api/v1/install/* pipeline is not deployed on this server yet). No files were changed."
}
 $art = $mf.artifacts | Where-Object arch -eq 'x64' | Select-Object -First 1
if (-not $art) { Fail 'No x64 artifact in manifest.' }

 $zip = Join-Path $env:TEMP $art.name
Write-Step "Downloading $($art.name) ($([math]::Round($art.size_bytes/1MB,1)) MB)"
Invoke-WebRequest "$Server/api/v1/install/artifacts/$($art.name)" -OutFile $zip -UseBasicParsing -TimeoutSec 300

# --- integrity ---
 $hash = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($hash -ne $art.sha256.ToUpper()) { Fail "SHA256 mismatch. Expected $($art.sha256) got $hash" }
Write-Step 'Integrity verified'

# --- idempotency: stop existing, then upgrade ---
Write-Step 'Stopping existing agent (if running)'
 $existingSvc = Get-Service $Svc -ErrorAction SilentlyContinue
if ($existingSvc) {
    Stop-Service $Svc -Force -ErrorAction SilentlyContinue
    # Wait for service to actually stop
    $timeout = 10
    while ($existingSvc.Status -ne 'Stopped' -and $timeout -gt 0) {
        Start-Sleep -Seconds 1
        $existingSvc = Get-Service $Svc -ErrorAction SilentlyContinue
        $timeout--
    }
}

# Kill any lingering user-mode agent processes
Get-Process PritrakDLP -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# --- extract ---
New-Item -ItemType Directory -Force -Path $InstallDir,$DataDir,"$DataDir\logs","$DataDir\policy" | Out-Null
try {
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
} catch {
    # File may still be locked: remove or rename the existing exe, then retry
    Write-Host '[Pritrak] WARNING: extraction failed, removing locked binaries and retrying' -ForegroundColor Yellow
    $lockedExe = "$InstallDir\PritrakDLP.exe"
    if (Test-Path $lockedExe) {
        try { Remove-Item -LiteralPath $lockedExe -Force -ErrorAction Stop }
        catch { Rename-Item -LiteralPath $lockedExe -NewName 'PritrakDLP.exe.old' -Force -ErrorAction SilentlyContinue }
    }
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
}
Remove-Item $zip -Force

# --- harden data dir ---
Write-Step 'Applying ACL to data directory'
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null

# --- config ---
@{
  schema_version = 1
  server_url = $Server
  agent_id = ''
  data_root = $DataDir
  log_level = 'info'
  enforcement_mode = 'MONITOR_ONLY'
  heartbeat_interval_sec = 30
} | ConvertTo-Json -Depth 4 | Set-Content "$DataDir\config.json" -Encoding UTF8

# --- service ---
if (-not (Test-Path "$InstallDir\PritrakDLP.exe")) { Fail "PritrakDLP.exe not found in $InstallDir. The downloaded package is empty or invalid." }

if (-not (Get-Service $Svc -ErrorAction SilentlyContinue)) {
    Write-Step 'Creating service'
    try {
        $binaryPath = "`"$InstallDir\PritrakDLP.exe`" --service"
        New-Service -Name $Svc -BinaryPathName $binaryPath -DisplayName "Pritrak DLP Agent" -StartupType Automatic -ErrorAction Stop | Out-Null
    } catch {
        Fail "Failed to create service: $($_.Exception.Message)"
    }
}
& sc.exe failure     $Svc reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
& sc.exe failureflag $Svc 1 | Out-Null

Write-Step 'Starting service'
try {
    Start-Service -Name $Svc -ErrorAction Stop
} catch {
    # If it's already running, ignore the error
    if ($_.Exception.Message -notmatch "already running") {
        Fail "Failed to start service: $($_.Exception.Message)"
    }
}

Start-Sleep -Seconds 5
 $s = Get-Service $Svc
if ($s.Status -ne 'Running') { Fail "Service failed to start. See $DataDir\logs" }

Write-Host ''
Write-Host '  Pritrak DLP Agent installed.' -ForegroundColor Green
Write-Host "  Mode    : MONITOR_ONLY (no blocking)"
Write-Host "  Server  : $Server"
Write-Host "  Logs    : $DataDir\logs"
Write-Host "  Enrolling in background; the device will appear in the console within ~60s."
Write-Host ''
Write-Host "Press Enter to exit..." -ForegroundColor Yellow
Read-Host

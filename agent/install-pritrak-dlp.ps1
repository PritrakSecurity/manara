<#
.SYNOPSIS
    PRITRAK DLP Agent Complete Installer
    
.DESCRIPTION
    This script deploys the complete PRITRAK DLP solution:
    1. Kernel minifilter driver (enforcement)
    2. User-mode DLP service (classification + notifications)
    3. Backend connectivity configuration
    
.PARAMETER ServerIP
    IP address or hostname of the PRITRAK backend server
    
.PARAMETER ServerPort
    Port of the PRITRAK backend server (default: 8080)
    
.PARAMETER TestMode
    Enable test signing mode for development
    
.EXAMPLE
    # Install with backend connection
    .\install-pritrak-dlp.ps1 -ServerIP 10.10.1.55 -ServerPort 8080
    
    # Install in test mode (driver test signing)
    .\install-pritrak-dlp.ps1 -ServerIP 10.10.1.55 -TestMode
    
.NOTES
    Requires Administrator privileges
    Requires Windows 10/11 x64 or Windows Server 2016+
    For test mode: bcdedit /set testsigning on (requires reboot)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP,
    
    [int]$ServerPort = 8080,
    
    [switch]$TestMode,
    
    [switch]$Force,
    
    [switch]$SkipDriver,
    
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

# Configuration
$InstallDir = "C:\Program Files\PRITRAK\DLP"
$DriverDir = "$InstallDir\driver"
$ServiceDir = "$InstallDir\service"
$LogDir = "$InstallDir\logs"
$ConfigDir = "$InstallDir\config"

$DriverName = "PritrakDLP"
$ServiceName = "PritrakDLPService"
$FilterName = "PritrakDLP"

# Logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage -ForegroundColor White }
    }
    
    if (Test-Path $LogDir) {
        Add-Content -Path "$LogDir\install.log" -Value $logMessage
    }
}

# Check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check Windows version
    $os = Get-CimInstance Win32_OperatingSystem
    $version = [Version]$os.Version
    if ($version.Major -lt 10) {
        throw "Windows 10 or later required"
    }
    
    # Check 64-bit
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw "64-bit Windows required"
    }
    
    # Check admin privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges required"
    }
    
    # Check test signing if needed (for unsigned drivers)
    if ($TestMode) {
        $bcdedit = & bcdedit /enum | Select-String "testsigning"
        if ($bcdedit -notmatch "Yes") {
            Write-Log "Test signing not enabled. Run: bcdedit /set testsigning on" -Level WARN
            Write-Log "A reboot is required after enabling test signing" -Level WARN
            
            if (-not $Force) {
                $response = Read-Host "Enable test signing now? (Y/N)"
                if ($response -eq 'Y') {
                    & bcdedit /set testsigning on
                    Write-Log "Test signing enabled. Please reboot and run installer again." -Level WARN
                    exit 0
                }
            }
        }
    }
    
    # Check backend connectivity
    Write-Log "Testing connection to backend at ${ServerIP}:${ServerPort}..."
    try {
        $response = Invoke-WebRequest -Uri "http://${ServerIP}:${ServerPort}/api/health" -TimeoutSec 5 -UseBasicParsing
        Write-Log "Backend connection successful" -Level SUCCESS
    } catch {
        Write-Log "Cannot reach backend at ${ServerIP}:${ServerPort}" -Level WARN
        Write-Log "Installation will continue, but agent may not function properly" -Level WARN
    }
    
    Write-Log "Prerequisites check passed" -Level SUCCESS
}

# Create directory structure
function Initialize-Directories {
    Write-Log "Creating directory structure..."
    
    $dirs = @($InstallDir, $DriverDir, $ServiceDir, $LogDir, $ConfigDir)
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
    
    Write-Log "Directories created" -Level SUCCESS
}

# Install kernel driver
function Install-KernelDriver {
    Write-Log "Installing kernel driver..."
    
    $driverSysPath = "C:\Windows\System32\drivers\$DriverName.sys"
    
    # Stop existing driver if running
    Write-Log "Stopping existing driver if running..."
    & fltmc unload $FilterName 2>&1 | Out-Null
    & sc.exe stop $DriverName 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    
    # Delete existing service
    & sc.exe delete $DriverName 2>&1 | Out-Null
    
    # Copy driver file
    $sourceDriver = Join-Path $PSScriptRoot "PritrakDLP.sys"
    if (-not (Test-Path $sourceDriver)) {
        # Try to download from backend
        Write-Log "Downloading driver from backend..."
        try {
            Invoke-WebRequest -Uri "http://${ServerIP}:${ServerPort}/api/download/driver/PritrakDLP.sys" `
                -OutFile $sourceDriver -UseBasicParsing
        } catch {
            throw "Driver file not found and cannot be downloaded from backend"
        }
    }
    
    Copy-Item -Path $sourceDriver -Destination $driverSysPath -Force
    Copy-Item -Path $sourceDriver -Destination "$DriverDir\$DriverName.sys" -Force
    
    # Create service
    Write-Log "Creating driver service..."
    & sc.exe create $DriverName `
        type= filesys `
        start= auto `
        binPath= $driverSysPath `
        group= "FSFilter Activity Monitor" `
        depend= FltMgr 2>&1 | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create driver service"
    }
    
    # Configure minifilter instances
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"
    $instancesPath = "$regPath\Instances"
    
    New-Item -Path $instancesPath -Force | Out-Null
    Set-ItemProperty -Path $instancesPath -Name "DefaultInstance" -Value "$DriverName Instance"
    
    $instancePath = "$instancesPath\$DriverName Instance"
    New-Item -Path $instancePath -Force | Out-Null
    Set-ItemProperty -Path $instancePath -Name "Altitude" -Value "370030"
    Set-ItemProperty -Path $instancePath -Name "Flags" -Value 0 -Type DWord
    
    # Start driver
    Write-Log "Starting driver..."
    $result = & fltmc load $FilterName 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        # Try starting via sc
        & sc.exe start $DriverName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        
        # Verify
        $fltmc = & fltmc 2>&1
        if ($fltmc -notmatch $FilterName) {
            Write-Log "Driver may not have started correctly: $result" -Level WARN
        }
    }
    
    Write-Log "Kernel driver installed" -Level SUCCESS
}

# Install user-mode service
function Install-UserModeService {
    Write-Log "Installing user-mode DLP service..."
    
    $serviceExePath = "$ServiceDir\PritrakDLPService.exe"
    
    # Stop existing service
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName 2>&1 | Out-Null
    
    # Copy service files
    $sourceService = Join-Path $PSScriptRoot "PritrakDLPService.exe"
    if (-not (Test-Path $sourceService)) {
        # Try to download from backend
        Write-Log "Downloading service from backend..."
        try {
            Invoke-WebRequest -Uri "http://${ServerIP}:${ServerPort}/api/download/service/PritrakDLPService.exe" `
                -OutFile $sourceService -UseBasicParsing
        } catch {
            Write-Log "Service executable not found, skipping user-mode service" -Level WARN
            return
        }
    }
    
    Copy-Item -Path $sourceService -Destination $serviceExePath -Force
    
    # Create configuration
    $config = @{
        Server = @{
            IP = $ServerIP
            Port = $ServerPort
            UseTLS = $false
        }
        Classification = @{
            Keywords = @("confidential", "restricted", "secret", "admin", "password", "ssn", "credit card")
            ScanDirectories = @("Desktop", "Documents", "Downloads")
            FileExtensions = @(".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".csv")
        }
        Enforcement = @{
            BlockDelete = $true
            BlockUSBCopy = $true
            BlockNetworkCopy = $false
            AuditMode = $false
        }
    }
    
    $config | ConvertTo-Json -Depth 4 | Set-Content -Path "$ConfigDir\config.json"
    
    # Create service
    Write-Log "Creating DLP service..."
    New-Service -Name $ServiceName `
        -BinaryPathName $serviceExePath `
        -DisplayName "PRITRAK DLP Agent" `
        -Description "Protects sensitive data from unauthorized access, copying, and deletion" `
        -StartupType Automatic | Out-Null
    
    # Start service
    Write-Log "Starting DLP service..."
    Start-Service -Name $ServiceName
    
    Write-Log "User-mode service installed" -Level SUCCESS
}

# Create uninstaller
function Create-Uninstaller {
    $uninstallScript = @'
# PRITRAK DLP Uninstaller
$ErrorActionPreference = 'Stop'

Write-Host "Uninstalling PRITRAK DLP Agent..."

# Stop and remove services
fltmc unload PritrakDLP 2>&1 | Out-Null
sc.exe stop PritrakDLPService 2>&1 | Out-Null
sc.exe stop PritrakDLP 2>&1 | Out-Null
Start-Sleep -Seconds 2
sc.exe delete PritrakDLPService 2>&1 | Out-Null
sc.exe delete PritrakDLP 2>&1 | Out-Null

# Remove driver file
Remove-Item "C:\Windows\System32\drivers\PritrakDLP.sys" -Force -ErrorAction SilentlyContinue

# Remove installation directory
Remove-Item "C:\Program Files\PRITRAK" -Recurse -Force -ErrorAction SilentlyContinue

# Clean registry
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\PritrakDLP" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\PritrakDLPService" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "PRITRAK DLP Agent uninstalled successfully" -ForegroundColor Green
'@

    Set-Content -Path "$InstallDir\uninstall.ps1" -Value $uninstallScript
}

# Verify installation
function Test-Installation {
    Write-Log "Verifying installation..."
    
    $errors = @()
    
    # Check driver
    $fltmc = & fltmc 2>&1
    if ($fltmc -match $FilterName) {
        Write-Log "Kernel driver: LOADED" -Level SUCCESS
    } else {
        $errors += "Kernel driver not loaded"
    }
    
    # Check service
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Log "User-mode service: RUNNING" -Level SUCCESS
    } elseif ($service) {
        $errors += "User-mode service not running (status: $($service.Status))"
    } else {
        Write-Log "User-mode service: NOT INSTALLED (optional)" -Level WARN
    }
    
    # Check files
    if (Test-Path "C:\Windows\System32\drivers\$DriverName.sys") {
        Write-Log "Driver file: PRESENT" -Level SUCCESS
    } else {
        $errors += "Driver file not found"
    }
    
    if ($errors.Count -gt 0) {
        Write-Log "Installation verification found issues:" -Level WARN
        foreach ($err in $errors) {
            Write-Log "  - $err" -Level WARN
        }
    } else {
        Write-Log "Installation verified successfully" -Level SUCCESS
    }
}

# Uninstall
function Uninstall-PritrakDLP {
    Write-Log "Uninstalling PRITRAK DLP Agent..."
    
    # Stop and remove filter
    & fltmc unload $FilterName 2>&1 | Out-Null
    
    # Stop and remove services
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName 2>&1 | Out-Null
    
    Stop-Service -Name $DriverName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $DriverName 2>&1 | Out-Null
    
    Start-Sleep -Seconds 2
    
    # Remove files
    Remove-Item "C:\Windows\System32\drivers\$DriverName.sys" -Force -ErrorAction SilentlyContinue
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Log "PRITRAK DLP Agent uninstalled" -Level SUCCESS
}

# Main
try {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "     PRITRAK DLP Agent Installer            " -ForegroundColor Cyan
    Write-Host "     Enterprise Data Loss Prevention        " -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($Uninstall) {
        Uninstall-PritrakDLP
        exit 0
    }
    
    Test-Prerequisites
    Initialize-Directories
    
    if (-not $SkipDriver) {
        Install-KernelDriver
    }
    
    Install-UserModeService
    Create-Uninstaller
    Test-Installation
    
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "  PRITRAK DLP Agent installed successfully! " -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Server: http://${ServerIP}:${ServerPort}" -ForegroundColor Cyan
    Write-Host "Logs: $LogDir" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "The agent is now protecting this endpoint." -ForegroundColor White
    Write-Host "Restricted files cannot be deleted or copied to USB." -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Log "Installation failed: $_" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level ERROR
    exit 1
}


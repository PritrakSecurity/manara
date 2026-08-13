<#
.SYNOPSIS
    Build and Deploy PRITRAK DLP Kernel Driver
    
.DESCRIPTION
    This script builds the DLP minifilter driver using WDK and optionally
    deploys it to a test machine with test signing enabled.
    
.PARAMETER Action
    build     - Build the driver
    deploy    - Deploy to local machine (requires admin + test signing)
    install   - Install driver
    uninstall - Uninstall driver
    start     - Start driver
    stop      - Stop driver
    status    - Show driver status
    test      - Run quick test
    
.PARAMETER Configuration
    Debug or Release (default: Release)
    
.EXAMPLE
    .\build-driver.ps1 -Action build
    .\build-driver.ps1 -Action deploy
    .\build-driver.ps1 -Action install
    .\build-driver.ps1 -Action start
    
.NOTES
    Requirements:
    - Visual Studio 2022 with WDK 10
    - Test signing enabled on target machine (bcdedit /set testsigning on)
    - Run as Administrator for deployment operations
#>

param(
    [ValidateSet('build', 'deploy', 'install', 'uninstall', 'start', 'stop', 'status', 'test', 'all')]
    [string]$Action = 'build',
    
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = $ScriptDir
$DriverName = 'PritrakDLP'
$ServiceName = 'PritrakDLP'
$OutputDir = Join-Path $ProjectDir "bin\$Platform\$Configuration"
$DriverPath = Join-Path $OutputDir "$DriverName.sys"
$InfPath = Join-Path $ProjectDir "$DriverName.inf"
$SystemDriverPath = "C:\Windows\System32\drivers\$DriverName.sys"

# Colors for output
function Write-Success { Write-Host $args -ForegroundColor Green }
function Write-Warning { Write-Host $args -ForegroundColor Yellow }
function Write-Error { Write-Host $args -ForegroundColor Red }
function Write-Info { Write-Host $args -ForegroundColor Cyan }

# Check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Find MSBuild
function Find-MSBuild {
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    
    if (Test-Path $vsWhere) {
        $msbuildPath = & $vsWhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($msbuildPath) {
            $msbuild = Join-Path $msbuildPath "MSBuild\Current\Bin\MSBuild.exe"
            if (Test-Path $msbuild) {
                return $msbuild
            }
        }
    }
    
    # Fallback to PATH
    $msbuild = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($msbuild) {
        return $msbuild.Path
    }
    
    throw "MSBuild not found. Please install Visual Studio 2022 with WDK."
}

# Build the driver
function Build-Driver {
    Write-Info "Building $DriverName driver ($Configuration|$Platform)..."
    
    $msbuild = Find-MSBuild
    $vcxproj = Join-Path $ProjectDir "$DriverName.vcxproj"
    
    if (-not (Test-Path $vcxproj)) {
        throw "Project file not found: $vcxproj"
    }
    
    $buildArgs = @(
        $vcxproj,
        "/p:Configuration=$Configuration",
        "/p:Platform=$Platform",
        "/t:Build",
        "/v:minimal"
    )
    
    Write-Info "Running: $msbuild $($buildArgs -join ' ')"
    
    & $msbuild @buildArgs
    
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }
    
    if (-not (Test-Path $DriverPath)) {
        throw "Driver file not found after build: $DriverPath"
    }
    
    Write-Success "Build successful: $DriverPath"
    
    # Show file info
    $fileInfo = Get-Item $DriverPath
    Write-Info "Driver size: $([math]::Round($fileInfo.Length / 1KB, 2)) KB"
}

# Create test certificate and sign driver
function Sign-Driver {
    Write-Info "Creating test certificate and signing driver..."
    
    $certStore = 'Cert:\LocalMachine\My'
    $certName = 'PritrakDLP Test Certificate'
    
    # Check for existing certificate
    $cert = Get-ChildItem $certStore | Where-Object { $_.Subject -like "*$certName*" }
    
    if (-not $cert) {
        Write-Info "Creating new test certificate..."
        
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject "CN=$certName" `
            -KeySpec Signature `
            -KeyExportPolicy Exportable `
            -KeyLength 2048 `
            -KeyAlgorithm RSA `
            -HashAlgorithm SHA256 `
            -Provider "Microsoft Strong Cryptographic Provider" `
            -CertStoreLocation $certStore
        
        # Add to Trusted Root
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $rootStore.Open("ReadWrite")
        $rootStore.Add($cert)
        $rootStore.Close()
        
        # Add to Trusted Publishers
        $pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
        $pubStore.Open("ReadWrite")
        $pubStore.Add($cert)
        $pubStore.Close()
        
        Write-Success "Test certificate created and trusted"
    } else {
        Write-Info "Using existing test certificate"
    }
    
    # Sign the driver
    $signTool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter 'signtool.exe' | 
                Where-Object { $_.FullName -like "*x64*" } | 
                Select-Object -First 1
    
    if (-not $signTool) {
        throw "SignTool not found. Please install Windows SDK."
    }
    
    $thumbprint = $cert.Thumbprint
    
    & $signTool.FullName sign /s My /sha1 $thumbprint /fd SHA256 /t http://timestamp.digicert.com $DriverPath
    
    if ($LASTEXITCODE -ne 0) {
        throw "Driver signing failed"
    }
    
    Write-Success "Driver signed successfully"
}

# Deploy driver to local machine
function Deploy-Driver {
    if (-not (Test-Administrator)) {
        throw "Deployment requires Administrator privileges"
    }
    
    Write-Info "Deploying driver to local machine..."
    
    # Stop and unload if running
    Stop-Driver -IgnoreError
    Uninstall-Driver -IgnoreError
    
    # Copy driver file
    Write-Info "Copying driver to $SystemDriverPath"
    Copy-Item -Path $DriverPath -Destination $SystemDriverPath -Force
    
    Write-Success "Driver deployed successfully"
}

# Install driver
function Install-Driver {
    if (-not (Test-Administrator)) {
        throw "Installation requires Administrator privileges"
    }
    
    Write-Info "Installing driver..."
    
    # Use fltmc to load minifilter
    $result = & fltmc load $ServiceName 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        # Try sc create first
        Write-Info "Creating service..."
        
        & sc.exe create $ServiceName `
            type= filesys `
            start= demand `
            binPath= $SystemDriverPath `
            group= "FSFilter Activity Monitor" `
            2>&1 | Out-Null
        
        # Set altitude in registry
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Instances"
        New-Item -Path $regPath -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name "DefaultInstance" -Value "$ServiceName Instance"
        
        $instancePath = "$regPath\$ServiceName Instance"
        New-Item -Path $instancePath -Force | Out-Null
        Set-ItemProperty -Path $instancePath -Name "Altitude" -Value "370030"
        Set-ItemProperty -Path $instancePath -Name "Flags" -Value 0 -Type DWord
        
        Write-Success "Service created"
    } else {
        Write-Success "Driver loaded successfully"
    }
}

# Uninstall driver
function Uninstall-Driver {
    param([switch]$IgnoreError)
    
    if (-not (Test-Administrator)) {
        if (-not $IgnoreError) { throw "Uninstallation requires Administrator privileges" }
        return
    }
    
    Write-Info "Uninstalling driver..."
    
    # Unload minifilter
    & fltmc unload $ServiceName 2>&1 | Out-Null
    
    # Delete service
    & sc.exe delete $ServiceName 2>&1 | Out-Null
    
    # Remove driver file
    if (Test-Path $SystemDriverPath) {
        Remove-Item $SystemDriverPath -Force -ErrorAction SilentlyContinue
    }
    
    if (-not $IgnoreError) {
        Write-Success "Driver uninstalled"
    }
}

# Start driver
function Start-Driver {
    if (-not (Test-Administrator)) {
        throw "Starting driver requires Administrator privileges"
    }
    
    Write-Info "Starting driver..."
    
    $result = & fltmc load $ServiceName 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start driver: $result"
    }
    
    Write-Success "Driver started"
}

# Stop driver
function Stop-Driver {
    param([switch]$IgnoreError)
    
    if (-not (Test-Administrator)) {
        if (-not $IgnoreError) { throw "Stopping driver requires Administrator privileges" }
        return
    }
    
    Write-Info "Stopping driver..."
    
    & fltmc unload $ServiceName 2>&1 | Out-Null
    
    if (-not $IgnoreError) {
        Write-Success "Driver stopped"
    }
}

# Show driver status
function Get-DriverStatus {
    Write-Info "Driver Status"
    Write-Info "============="
    
    # Check if driver file exists
    if (Test-Path $SystemDriverPath) {
        $fileInfo = Get-Item $SystemDriverPath
        Write-Info "Driver file: $SystemDriverPath ($([math]::Round($fileInfo.Length / 1KB, 2)) KB)"
    } else {
        Write-Warning "Driver file not found: $SystemDriverPath"
    }
    
    # Check service status
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Info "Service status: $($service.Status)"
    } else {
        Write-Warning "Service not installed"
    }
    
    # Check if loaded as minifilter
    $fltmc = & fltmc 2>&1
    if ($fltmc -match $ServiceName) {
        Write-Success "Minifilter: LOADED"
        $fltmc | Where-Object { $_ -match $ServiceName }
    } else {
        Write-Warning "Minifilter: NOT LOADED"
    }
    
    # Check instances
    $instances = & fltmc instances 2>&1
    if ($instances -match $ServiceName) {
        Write-Info "`nActive Instances:"
        $instances | Where-Object { $_ -match $ServiceName }
    }
}

# Run quick test
function Test-Driver {
    Write-Info "Running driver test..."
    
    # Check status first
    Get-DriverStatus
    
    # TODO: Add actual tests
    # - Create test file with restricted keyword
    # - Try to delete -> should be blocked
    # - Try to copy to USB -> should be blocked
    
    Write-Warning "Test functionality not yet implemented"
}

# Main execution
try {
    Write-Info "PRITRAK DLP Driver Build Tool"
    Write-Info "=============================="
    Write-Info ""
    
    switch ($Action) {
        'build' {
            Build-Driver
        }
        'deploy' {
            if (-not (Test-Path $DriverPath)) {
                Build-Driver
            }
            Sign-Driver
            Deploy-Driver
        }
        'install' {
            Install-Driver
        }
        'uninstall' {
            Uninstall-Driver
        }
        'start' {
            Start-Driver
        }
        'stop' {
            Stop-Driver
        }
        'status' {
            Get-DriverStatus
        }
        'test' {
            Test-Driver
        }
        'all' {
            Build-Driver
            Sign-Driver
            Deploy-Driver
            Install-Driver
            Start-Driver
            Get-DriverStatus
        }
    }
    
    Write-Host ""
    Write-Success "Done!"
} catch {
    Write-Error "Error: $_"
    exit 1
}


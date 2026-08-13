<#
.SYNOPSIS
    Sign a Pritrak DLP driver with an internal CA (T2 enterprise self-sign).

.DESCRIPTION
    Signs a driver .sys with the organization's internal CA code-signing
    certificate using signtool, with optional RFC3161 timestamping. For kernel
    drivers it performs a catalog signature (/catalog) in addition to the
    embedded signature, and verifies the result under kernel-mode policy.

    After signing, run .\generate-wdac-policy.ps1 with the ROOT thumbprint of
    the internal CA and deploy the compiled supplemental policy so Secure Boot
    machines accept the driver.

.PARAMETER DriverPath
    Path to the driver .sys (or any binary) to sign.

.PARAMETER CertThumbprint
    SHA-1 thumbprint of the internal CA code-signing certificate (leaf) used
    to sign. Must be present in Cert:\LocalMachine\My.

.PARAMETER TimestampUrl
    RFC3161 timestamp URL. Default: http://timestamp.digicert.com. Pass '' to
    skip timestamping (not recommended for kernel drivers).

.PARAMETER CatalogPath
    If provided, additionally create/append a catalog signature at this path
    (creates the .cat if missing and adds the driver hash to it).

.PARAMETER SkipVerify
    Skip the post-signature verification.

.EXAMPLE
    .\sign-driver-internal.ps1 -DriverPath .\PritrakDLP.sys -CertThumbprint A1B2C3D4...

.NOTES
    Requires the Windows SDK (signtool.exe) and Administrator rights.
    The ROOT cert of the internal CA must be allow-listed in the deployed
    supplemental WDAC policy for the driver to load with Secure Boot ON.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$DriverPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$CertThumbprint,

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [string]$CatalogPath,

    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script requires Administrator privileges.'
    }
}

function Find-SignTool {
    $candidates = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
        -Filter 'signtool.exe' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending
    if (-not $candidates) {
        throw 'signtool.exe not found. Install the Windows SDK (Windows Kits\10\bin).'
    }
    return $candidates[0].FullName
}

function Get-SigningCertificate {
    param([string]$Thumbprint)
    $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumbprint } |
        Select-Object -First 1
    if (-not $cert) {
        throw "Certificate with thumbprint '$Thumbprint' not found in Cert:\LocalMachine\My."
    }
    if (-not ($cert.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq 'Code Signing' -or $_.Oid.Value -eq '1.3.6.1.5.5.7.3.3' })) {
        Write-Warning "Certificate '$($cert.Subject)' does not carry a code-signing EKU. Signing may be rejected."
    }
    return $cert
}

Assert-Administrator
$signTool = Find-SignTool
$cert = Get-SigningCertificate -Thumbprint $CertThumbprint
$driver = (Resolve-Path -LiteralPath $DriverPath).Path

$signArgs = @('sign', '/s', 'My', '/sha1', $cert.Thumbprint, '/fd', 'SHA256', '/v')
if ($TimestampUrl) {
    $signArgs += @('/tr', $TimestampUrl, '/td', 'SHA256')
}
if ($CatalogPath) {
    if (-not (Test-Path -LiteralPath $CatalogPath)) {
        Write-Verbose "Catalog does not exist; creating catalog signature: $CatalogPath"
        $signArgs += @('/catalog', $CatalogPath)
    }
    else {
        Write-Verbose "Catalog exists; appending driver to: $CatalogPath"
        $signArgs += @('/cat', $CatalogPath)
    }
}
$signArgs += $driver

if (-not $PSCmdlet.ShouldProcess("sign '$driver' with '$($cert.Subject)'")) {
    return
}

Write-Host "Signing $driver" -ForegroundColor Cyan
Write-Host "Command: $signTool $($signArgs -join ' ')"
$result = & $signTool @signArgs 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "signtool failed. Output: $result"
}
Write-Host $result

if (-not $SkipVerify) {
    Write-Host 'Verifying signature...' -ForegroundColor Cyan
    $verifyResult = & $signTool verify /kp /v $driver 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Post-signature verification FAILED. Output: $verifyResult"
    }
    Write-Host $verifyResult
    Write-Host 'Driver signed and verified.' -ForegroundColor Green
    Write-Host "Remember: allow-list the internal CA ROOT thumbprint in the supplemental WDAC policy before deploying with Secure Boot ON." -ForegroundColor Yellow
}

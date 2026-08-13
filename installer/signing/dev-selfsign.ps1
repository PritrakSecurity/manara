<#
.SYNOPSIS
    Create a self-signed code-signing certificate and sign one or more binaries.

.DESCRIPTION
    T0/T1 development signing. Creates a CodeSigningCert in the LocalMachine
    certificate stores (My, Root, TrustedPublisher) and signs the specified
    binary or binaries with signtool. Optionally applies a timestamp.

    This is for DEVELOPMENT and HOMELAB machines only. Test signing must be
    enabled on the machine for a kernel driver signed this way to load.

.PARAMETER CertName
    Subject name for the generated certificate. Default: 'PritrakDLP Dev'.

.PARAMETER FilePath
    One or more binaries to sign. Can be a glob (e.g. .\*.sys) or a single file.

.PARAMETER CertStoreLocation
    Machine store where the certificate is created. Default: Cert:\LocalMachine\My.

.PARAMETER TimestampUrl
    RFC3161 timestamp server URL. Default: http://timestamp.digicert.com.
    Pass '' to skip timestamping.

.PARAMETER SkipTrustInstall
    If set, the certificate is created but NOT added to Root/TrustedPublisher.
    Use when you will trust the cert through another channel (e.g. GPO).

.PARAMETER PassThru
    If set, output the certificate object after signing.

.EXAMPLE
    .\dev-selfsign.ps1 -FilePath .\PritrakDLP.sys -CertName "PritrakDLP Dev"

.EXAMPLE
    .\dev-selfsign.ps1 -FilePath @('.\PritrakDLP.sys', '.\dlp_wfp.sys') -TimestampUrl ''

.NOTES
    Requires Administrator rights and the Windows SDK (signtool.exe).
    Secure Boot must be OFF for a test-signed kernel driver to load.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$CertName = 'PritrakDLP Dev',

    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$FilePath,

    [string]$CertStoreLocation = 'Cert:\LocalMachine\My',

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [switch]$SkipTrustInstall,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script requires Administrator privileges (certificate stores are machine-wide).'
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

function Resolve-TargetFile {
    param([string[]]$InputPaths)
    $resolved = @()
    foreach ($p in $InputPaths) {
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            $resolved += (Resolve-Path -LiteralPath $p).Path
        }
        else {
            $hits = Get-Item -Path $p -ErrorAction SilentlyContinue
            if (-not $hits) {
                throw "File not found: $p"
            }
            $resolved += $hits.FullName
        }
    }
    return ($resolved | Sort-Object -Unique)
}

function Install-DevCertificate {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Name,
        [string]$StoreLocation,
        [switch]$SkipTrust
    )

    $existing = Get-ChildItem -Path $StoreLocation -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like "*CN=$Name*" } |
        Select-Object -First 1

    if ($existing) {
        Write-Verbose "Reusing existing certificate: $($existing.Thumbprint)"
        return $existing
    }

    if (-not $PSCmdlet.ShouldProcess("create self-signed certificate '$Name'")) {
        return $null
    }

    Write-Verbose "Creating self-signed code-signing certificate '$Name'"
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$Name" `
        -KeySpec Signature `
        -KeyExportPolicy Exportable `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -Provider 'Microsoft Strong Cryptographic Provider' `
        -NotAfter (Get-Date).AddYears(2) `
        -CertStoreLocation $StoreLocation

    if (-not $SkipTrust) {
        if ($PSCmdlet.ShouldProcess("add certificate to Root and TrustedPublisher")) {
            foreach ($storeName in @('Root', 'TrustedPublisher')) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
                $store.Open('ReadWrite')
                $store.Add($cert)
                $store.Close()
            }
            Write-Verbose 'Certificate added to Root and TrustedPublisher.'
        }
    }

    return $cert
}

function Invoke-SignBinary {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$SignToolPath,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$Target,
        [string]$TimeUrl
    )

    if (-not $PSCmdlet.ShouldProcess("sign '$Target'")) {
        return $false
    }

    $sigArgs = @('sign', '/s', 'My', '/sha1', $Cert.Thumbprint, '/fd', 'SHA256', '/v')
    if ($TimeUrl) {
        $sigArgs += @('/tr', $TimeUrl, '/td', 'SHA256')
    }
    $sigArgs += $Target

    Write-Verbose "Running: $SignToolPath $($sigArgs -join ' ')"
    & $SignToolPath @sigArgs 2>&1 | ForEach-Object { Write-Verbose $_ }

    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed to sign '$Target' (exit code $LASTEXITCODE)"
    }
    return $true
}

Assert-Administrator

$signTool = Find-SignTool
Write-Verbose "signtool: $signTool"

$cert = Install-DevCertificate -Name $CertName -StoreLocation $CertStoreLocation -SkipTrust:$SkipTrustInstall
if (-not $cert) {
    throw 'Unable to obtain a code-signing certificate.'
}

$targets = Resolve-TargetFile -InputPaths $FilePath
Write-Verbose "Signing $($targets.Count) file(s)."

$signed = @()
foreach ($target in $targets) {
    if (Invoke-SignBinary -SignToolPath $signTool -Cert $cert -Target $target -TimeUrl $TimestampUrl) {
        $signed += $target
    }
}

Write-Host "Signed $($signed.Count) file(s) with certificate '$CertName' ($($cert.Thumbprint))." -ForegroundColor Green
Write-Host "Test signing must be enabled for a kernel driver to load: run .\enable-testsigning.ps1 -Enable" -ForegroundColor Yellow

if ($PassThru) {
    return $cert
}

<#
.SYNOPSIS
    Verify the signature of a binary (Authenticode or kernel-mode policy).

.DESCRIPTION
    Uses signtool to verify a file's signature. Optionally checks that the
    signer matches an expected subject name or certificate thumbprint, verifies
    the timestamp, and verifies under kernel-mode policy (/kp) for drivers.

.PARAMETER FilePath
    The binary to verify. Required.

.PARAMETER KernelPolicy
    Verify under kernel-mode policy (/kp) instead of Authenticode (/pa).
    Use for driver .sys files.

.PARAMETER VerifyTimestamp
    Also verify the RFC3161 timestamp (/tw).

.PARAMETER ExpectedSubject
    If provided, the signer certificate subject must contain this string.

.PARAMETER ExpectedThumbprint
    If provided, the signer certificate thumbprint must match exactly.

.PARAMETER ShowChain
    Print the full signing certificate chain (verbose output).

.EXAMPLE
    .\verify-signature.ps1 -FilePath .\PritrakDLP.sys -KernelPolicy -ExpectedSubject 'PritrakDLP Dev'

.EXAMPLE
    .\verify-signature.ps1 -FilePath .\agent.exe -VerifyTimestamp -ExpectedThumbprint A1B2C3D4...

.NOTES
    Requires the Windows SDK (signtool.exe). Exit code 0 = verified.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$FilePath,

    [switch]$KernelPolicy,

    [switch]$VerifyTimestamp,

    [string]$ExpectedSubject,

    [string]$ExpectedThumbprint,

    [switch]$ShowChain
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

$signTool = Find-SignTool
$resolved = (Resolve-Path -LiteralPath $FilePath).Path

$policyFlag = if ($KernelPolicy) { '/kp' } else { '/pa' }
$verifyArgs = @('verify', $policyFlag, '/v')
if ($VerifyTimestamp) {
    $verifyArgs += '/tw'
}
$verifyArgs += $resolved

Write-Host "Verifying signature of $resolved" -ForegroundColor Cyan
Write-Host "Command: $signTool $($verifyArgs -join ' ')"
$output = & $signTool @verifyArgs 2>&1 | Out-String

if ($LASTEXITCODE -ne 0) {
    Write-Host $output
    throw "Signature verification FAILED (exit code $LASTEXITCODE)."
}

Write-Host $output
Write-Host 'Signature verification PASSED.' -ForegroundColor Green

$sig = Get-AuthenticodeSignature -FilePath $resolved
if ($sig.Status -ne 'Valid') {
    Write-Host "Authenticode status (advisory): $($sig.Status). Signature may be an embedded/catalog signature not surfaced by Get-AuthenticodeSignature." -ForegroundColor Yellow
}

if ($sig.SignerCertificate) {
    Write-Host "Signer: $($sig.SignerCertificate.Subject)" -ForegroundColor Cyan
    Write-Host "Thumbprint: $($sig.SignerCertificate.Thumbprint)" -ForegroundColor Cyan

    if ($ExpectedSubject -and $sig.SignerCertificate.Subject -notlike "*$ExpectedSubject*") {
        throw "Expected signer subject to contain '$ExpectedSubject' but found '$($sig.SignerCertificate.Subject)'."
    }
    if ($ExpectedThumbprint -and $sig.SignerCertificate.Thumbprint -ine $ExpectedThumbprint) {
        throw "Expected thumbprint '$ExpectedThumbprint' but found '$($sig.SignerCertificate.Thumbprint)'."
    }
}

if ($ShowChain -and $sig.SignerCertificate) {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    [void]$chain.Build($sig.SignerCertificate)
    Write-Host 'Certificate chain:' -ForegroundColor Cyan
    foreach ($el in $chain.ChainElements) {
        Write-Host "  $($el.Certificate.Subject)"
    }
}

Write-Host 'All checks passed.' -ForegroundColor Green

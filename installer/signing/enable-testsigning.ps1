<#
.SYNOPSIS
    Enable or disable test signing for T0/T1 development machines.

.DESCRIPTION
    Wraps 'bcdedit /set testsigning on|off'. Before enabling, this script
    checks that Secure Boot is OFF (test signing cannot work with Secure Boot
    enabled) and that the boot configuration can be modified. It requires a
    reboot to take effect and will offer to reboot the machine.

.PARAMETER Enable
    Turn test signing on.

.PARAMETER Disable
    Turn test signing off (restores normal boot policy).

.PARAMETER Force
    Skip the confirmation prompt.

.PARAMETER Reboot
    Reboot immediately after the boot flag is set. Default: prompt the user.

.EXAMPLE
    .\enable-testsigning.ps1 -Enable -Reboot

.EXAMPLE
    .\enable-testsigning.ps1 -Disable

.NOTES
    Requires Administrator privileges.
    Security implication: a machine with test signing ON will load any
    signature-bearing kernel driver, dramatically weakening kernel integrity.
    Only use on isolated dev/lab machines. Never on production or on machines
    that hold real data.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(ParameterSetName = 'Enable', Mandatory = $true)]
    [switch]$Enable,

    [Parameter(ParameterSetName = 'Disable', Mandatory = $true)]
    [switch]$Disable,

    [switch]$Force,

    [switch]$Reboot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script requires Administrator privileges (boot configuration is machine-wide).'
    }
}

function Get-TestSigningState {
    $output = & bcdedit /enum '{current}' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "bcdedit /enum failed. Output: $output"
    }
    if ($output -match 'testsigning\s+Yes') {
        return 'ON'
    }
    if ($output -match 'testsigning\s+No') {
        return 'OFF'
    }
    return 'UNSET'
}

function Test-SecureBoot {
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        return [bool]$sb
    }
    catch {
        Write-Warning 'Secure Boot status could not be queried (Confirm-SecureBootUEFI unavailable).'
        Write-Warning 'Proceeding without the Secure Boot check.'
        return $false
    }
}

Assert-Administrator

if ($Enable) {
    $desired = 'on'
}
elseif ($Disable) {
    $desired = 'off'
}
else {
    throw 'Specify either -Enable or -Disable.'
}
$current = Get-TestSigningState
Write-Verbose "Current test signing state: $current"

if ($Enable) {
    if (Test-SecureBoot) {
        throw 'Secure Boot is ON. Test signing cannot be used with Secure Boot enabled. Disable Secure Boot (or use the WDAC/attestation tiers) before enabling test signing.'
    }
    if (-not $Force) {
        Write-Host 'WARNING: Enabling test signing lets the kernel load ANY signature-bearing driver.' -ForegroundColor Yellow
        Write-Host 'This severely weakens kernel integrity. Use ONLY on isolated dev/lab machines.' -ForegroundColor Yellow
        if (-not $PSCmdlet.ShouldProcess('enable test signing')) {
            return
        }
    }
}
else {
    if (-not $Force -and -not $PSCmdlet.ShouldProcess('disable test signing')) {
        return
    }
}

if ($current -eq $(if ($Enable) { 'ON' } else { 'OFF' })) {
    Write-Host "Test signing is already set to '$desired'. No change needed." -ForegroundColor Green
    return
}

if (-not $PSCmdlet.ShouldProcess("set test signing to '$desired'")) {
    return
}

$output = & bcdedit /set testsigning $desired 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "bcdedit /set testsigning $desired failed. Output: $output"
}

Write-Host "Test signing set to '$desired'. A reboot is required for the change to take effect." -ForegroundColor Green

if ($Reboot -or $PSCmdlet.ShouldProcess('reboot the machine now')) {
    Write-Host 'Rebooting in 10 seconds. Press Ctrl+C to abort.' -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}

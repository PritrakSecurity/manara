<#
.SYNOPSIS
    Package driver files (sys/inf/catalog) into a .cab for submission.

.DESCRIPTION
    Creates a makecab directive (.ddf) file and produces a compressed .cab
    containing the listed driver files. This is the input format expected by
    the Microsoft Partner Center Hardware API for attestation signing and by
    WDAC supplemental-policy signing workflows.

.PARAMETER SourceDirectory
    Directory that contains the driver files to package.

.PARAMETER DriverFiles
    Files to include, relative to SourceDirectory. Default: *.sys, *.inf, *.cat.

.PARAMETER OutputPath
    Destination .cab file path. Default: <SourceDirectory>\PritrakDLP.cab.

.PARAMETER Compression
    makecab compression type. Default LZX.

.EXAMPLE
    .\build-driver-cab.ps1 -SourceDirectory .\bin\Release\x64 -OutputPath .\dist\PritrakDLP.cab

.NOTES
    Requires makecab.exe (part of the Windows SDK / OS).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$SourceDirectory,

    [string[]]$DriverFiles = @('*.sys', '*.inf', '*.cat'),

    [string]$OutputPath,

    [ValidateSet('LZX', 'MSZIP', 'None')]
    [string]$Compression = 'LZX'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Find-MakeCab {
    $fromPath = Get-Command makecab.exe -ErrorAction SilentlyContinue
    if ($fromPath) {
        return $fromPath.Source
    }
    $candidates = Get-ChildItem -Path "${env:SystemRoot}\System32", "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
        -Filter 'makecab.exe' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending
    if (-not $candidates) {
        throw 'makecab.exe not found.'
    }
    return $candidates[0].FullName
}

$src = (Resolve-Path -LiteralPath $SourceDirectory).Path

$files = @()
foreach ($pattern in $DriverFiles) {
    $hits = @(Get-ChildItem -LiteralPath $src -File -Filter $pattern -ErrorAction SilentlyContinue)
    if ($hits.Count -eq 0) {
        Write-Warning "No files matched '$pattern' in '$src'."
        continue
    }
    $files += $hits
}
$files = @($files | Sort-Object Name -Unique)

if ($files.Count -eq 0) {
    throw 'No driver files matched the given patterns.'
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $src 'PritrakDLP.cab'
}
$outputDir = Split-Path -Parent $OutputPath
if (-not $outputDir) {
    $outputDir = (Get-Location).Path
}
if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
$outputFull = [System.IO.Path]::GetFullPath($OutputPath)

$compressionType = switch ($Compression) {
    'LZX'   { 'LZX' }
    'MSZIP' { 'MSZIP' }
    'None'  { 'None' }
}

$ddfPath = Join-Path ([System.IO.Path]::GetTempPath()) "pritrak-$(Get-Random).ddf"
$ddfLines = @(
    '.OPTION EXPLICIT',
    '.Set CabinetNameTemplate=__OUTPUT__',
    ".Set DiskDirectoryTemplate=$outputDir",
    ".Set CompressionType=$compressionType",
    '.Set Cabinet=on',
    '.Set Compress=on'
)
foreach ($f in $files) {
    $ddfLines += '"' + $f.FullName + '"'
}
Set-Content -LiteralPath $ddfPath -Value $ddfLines -Encoding UTF8

try {
    $makecab = Find-MakeCab
    $outName = [System.IO.Path]::GetFileName($outputFull)
    (Get-Content -LiteralPath $ddfPath) | ForEach-Object {
        $_.Replace('__OUTPUT__', $outName)
    } | Set-Content -LiteralPath $ddfPath -Encoding UTF8

    if (-not $PSCmdlet.ShouldProcess("package $($files.Count) file(s) into '$outputFull'")) {
        return
    }

    Write-Host "Packaging $($files.Count) file(s) into $outputFull"
    foreach ($f in $files) {
        Write-Host "  - $($f.Name)"
    }

    $result = & $makecab /F $ddfPath 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "makecab failed (exit code $LASTEXITCODE). Output: $result"
    }
}
finally {
    if (Test-Path -LiteralPath $ddfPath) {
        Remove-Item -LiteralPath $ddfPath -Force
    }
}

if (-not (Test-Path -LiteralPath $outputFull)) {
    throw "Expected output file not produced: $outputFull"
}

$item = Get-Item -LiteralPath $outputFull
Write-Host "Created $($item.FullName) ($([math]::Round($item.Length / 1KB, 1)) KB)." -ForegroundColor Green

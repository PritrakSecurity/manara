<#
.SYNOPSIS
    Generate a Pritrak DLP supplemental WDAC policy XML from the template.

.DESCRIPTION
    Reads installer\wdac\PritrakDLP-Supplemental-template.xml, fills in the
    base-policy GUID, a fresh supplemental-policy GUID, and the internal CA
    root certificate thumbprint, then optionally compiles the XML to a binary
    .p7b WDAC policy for deployment.

    The signer must be the ROOT certificate of the internal CA that signs the
    driver, so future driver builds signed by the same CA remain permitted
    without regenerating the policy.

.PARAMETER CertThumbprint
    SHA-1 thumbprint (40 hex chars) of the internal CA ROOT certificate.

.PARAMETER CertPath
    Alternative: path to a .cer/.crt of the internal CA ROOT certificate.
    Mutually exclusive with CertThumbprint.

.PARAMETER BasePolicyId
    GUID (with or without braces) of the deployed base WDAC policy this
    supplemental policy extends. Required.

.PARAMETER PolicyId
    GUID to assign to the new supplemental policy. If omitted, a new GUID is
    generated (use -ForceOutput to overwrite an existing OutputPath).

.PARAMETER OutputPath
    Destination .xml file. Default: <repo>\installer\wdac\out\PritrakDLP-Supplemental.xml

.PARAMETER Compile
    Also compile the XML to a .p7b binary policy next to OutputPath.

.PARAMETER ForceOutput
    Overwrite the output file if it already exists.

.EXAMPLE
    .\generate-wdac-policy.ps1 -CertThumbprint A1B2C3D4... -BasePolicyId "{8D5B4C..}" -Compile

.NOTES
    -Compile requires the ConfigCI WDAC cmdlets (Windows 10 1809+ / Server 2019+).
    A base WDAC policy must already be deployed on target machines.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(ParameterSetName = 'ByThumbprint', Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$CertThumbprint,

    [Parameter(ParameterSetName = 'ByCertPath', Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CertPath,

    [Parameter(Mandatory = $true)]
    [string]$BasePolicyId,

    [string]$PolicyId,

    [string]$OutputPath,

    [switch]$Compile,

    [switch]$ForceOutput
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$templatePath = Join-Path $PSScriptRoot 'PritrakDLP-Supplemental-template.xml'
if (-not (Test-Path -LiteralPath $templatePath)) {
    throw "Template not found: $templatePath"
}

function Get-RootThumbprint {
    param([string]$Thumbprint, [string]$CertFile)
    if ($CertFile) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertFile)
    }
    else {
        $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $Thumbprint } |
            Select-Object -First 1
        if (-not $cert) {
            throw "Certificate with thumbprint '$Thumbprint' not found in Cert:\LocalMachine\My."
        }
    }

    if ($cert.Subject -ne $cert.Issuer) {
        Write-Warning "Certificate '$($cert.Subject)' is not self-signed. WDAC CertRoot entries MUST be the root CA certificate; provide the internal CA ROOT thumbprint, not a leaf or intermediate."
    }
    return $cert.Thumbprint.ToUpper()
}

function Format-Guid {
    param([string]$Id)
    try {
        $parsed = [guid]$Id
    }
    catch {
        throw "Invalid GUID: '$Id'. Expected a GUID such as '{8D5B4C12-...}'."
    }
    return $parsed.ToString('B').ToUpper()
}

if (-not $PolicyId) {
    $PolicyId = [guid]::NewGuid().ToString('B').ToUpper()
    Write-Verbose "Generated supplemental policy GUID: $PolicyId"
}

$root = Get-RootThumbprint -Thumbprint $CertThumbprint -CertFile $CertPath
$baseGuid = Format-Guid -Id $BasePolicyId
$policyGuid = Format-Guid -Id $PolicyId

if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "out\PritrakDLP-Supplemental.xml"
}
if (-not (Test-Path -LiteralPath (Split-Path -Parent $OutputPath))) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
}
if ((Test-Path -LiteralPath $OutputPath) -and -not $ForceOutput -and -not $PSCmdlet.ShouldProcess('overwrite existing output file')) {
    return
}

$xml = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8
$xml = $xml.Replace('{BASE_POLICY_ID}', $baseGuid)
$xml = $xml.Replace('{POLICY_ID}', $policyGuid)
$xml = $xml.Replace('{SIGNER_ROOT_THUMBPRINT}', $root)

try {
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml($xml)
}
catch {
    throw "Generated policy XML is not well-formed: $($_.Exception.Message)"
}

Set-Content -LiteralPath $OutputPath -Value $xml -Encoding UTF8
Write-Host "Wrote supplemental policy to $OutputPath" -ForegroundColor Green
Write-Host "  PolicyID   : $policyGuid"
Write-Host "  BasePolicyID: $baseGuid"
Write-Host "  CertRoot   : $root"

if ($Compile) {
    if (-not (Get-Command ConvertTo-CIPolicy -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-CIPolicy not found. The ConfigCI WDAC cmdlets are required for -Compile (Windows 10 1809+ / Server 2019+).'
    }
    $p7bPath = [System.IO.Path]::ChangeExtension($OutputPath, '.p7b')
    if ($PSCmdlet.ShouldProcess("compile '$OutputPath' to '$p7bPath'")) {
        ConvertTo-CIPolicy -XmlFilePath $OutputPath -BinaryFilePath $p7bPath
        Write-Host "Compiled binary policy: $p7bPath" -ForegroundColor Green
        Write-Host 'Deploy the .p7b on target machines alongside the existing base policy (see README.md).'
    }
}

import { useMemo, useState } from 'react'
import { X, Copy, Download, CheckCircle, Terminal, Apple, Monitor, Code2 } from 'lucide-react'
import { getBackendUrl } from '../utils/getBackendUrl'

interface ManualRegisterModalProps {
  isOpen: boolean
  onClose: () => void
}

export default function ManualRegisterModal({ isOpen, onClose }: ManualRegisterModalProps) {
  const [copied, setCopied] = useState(false)
  const [activeTab, setActiveTab] = useState<'windows'|'mac'|'linux'>('windows')

  // Derive sensible defaults from backend URL
  const defaults = useMemo(() => {
    const backendUrl = getBackendUrl()
    const host = backendUrl.replace('http://', '').replace('https://','').split(':')[0]
    const port = backendUrl.split(':').pop() || '8080'
    return { host, port }
  }, [])

  const [serverHost, setServerHost] = useState<string>(defaults.host)
  const [serverPort, setServerPort] = useState<string>(defaults.port)
  const [enrollToken, setEnrollToken] = useState<string>('')

  const windowsScript = useMemo(() => {
    const serverIP = serverHost || defaults.host
    const port = serverPort || defaults.port
    return generateStandaloneScript(serverIP, port, enrollToken)
  }, [serverHost, serverPort, defaults, enrollToken])

  const oneLiner = useMemo(() => {
    const serverIP = serverHost || defaults.host
    const port = serverPort || defaults.port
    return `irm "http://${serverIP}:${port}/api/v1/install/bootstrap.ps1?server=http://${serverIP}:${port}" | iex`
  }, [serverHost, serverPort, defaults])

  const comingSoonBlock = (
    <div className="p-6">
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-start gap-3">
        <Code2 className="w-5 h-5 text-yellow-700 mt-0.5" />
        <div>
          <p className="text-yellow-800 font-semibold">Coming soon</p>
          <p className="text-yellow-800/90 text-sm mt-1">Agent installation for this platform will be available shortly. In the meantime, Windows deployment is fully supported.</p>
        </div>
      </div>
    </div>
  )

  const handleCopy = async () => {
    try {
      const script = oneLiner
      await navigator.clipboard.writeText(script)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy to clipboard:', err)
    }
  }

  const handleDownload = () => {
    try {
      const script = windowsScript
      const blob = new Blob([script], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'bootstrap-pritrak-agent.ps1'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Failed to download script:', err)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[120] p-4">
      <div className="bg-white rounded-xl border border-gray-200 w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col shadow-xl">
        {/* Header */}
        <div className="p-6 border-b border-gray-200 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-[#fd382f]/10 rounded-lg flex items-center justify-center">
              <Terminal className="h-6 w-6 text-[#fd382f]" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-gray-900">Manual Agent Installation</h2>
              <p className="text-gray-600 text-sm mt-1">
                Deploy the Pritrak DLP Agent on Windows devices
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="h-5 w-5 text-gray-400" />
          </button>
        </div>

        {/* Instructions + Dynamic server config */}
        <div className="p-6 border-b border-gray-200 bg-blue-50 flex-shrink-0">
          <div className="grid gap-6 md:grid-cols-2">
            <div className="space-y-3">
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Installation Instructions</h3>
              <ol className="space-y-3 list-decimal list-inside">
                <li className="text-gray-700">
                  <strong>Copy the script below</strong> - Use the "Copy to Clipboard" button
                </li>
                <li className="text-gray-700">
                  <strong>On the target Windows machine, open PowerShell as Administrator</strong> - Right-click PowerShell and select "Run as Administrator"
                </li>
                <li className="text-gray-700">
                  <strong>Paste and run the script</strong> - Press Enter to execute
                </li>
                <li className="text-gray-700">
                  <strong>The device will appear in the dashboard within ~60 seconds</strong> once the agent enrolls
                </li>
              </ol>
            </div>
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-gray-900">Server Configuration</h3>
              <div className="grid grid-cols-5 gap-2">
                <div className="col-span-3">
                  <label className="block text-xs text-gray-600 mb-1">Server Host/IP</label>
                  <input
                    value={serverHost}
                    onChange={(e)=>setServerHost(e.target.value)}
                    placeholder="e.g. 192.168.1.10 or dlp.example.com"
                    className="w-full px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f]"
                  />
                </div>
                <div className="col-span-2">
                  <label className="block text-xs text-gray-600 mb-1">Port</label>
                  <input
                    value={serverPort}
                    onChange={(e)=>setServerPort(e.target.value.replace(/[^0-9]/g,''))}
                    placeholder="8080"
                    className="w-full px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f]"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs text-gray-600 mb-1">Enrollment token (optional)</label>
                <input
                  value={enrollToken}
                  onChange={(e)=>setEnrollToken(e.target.value.trim())}
                  placeholder="pk_enr_..."
                  className="w-full px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 font-mono focus:outline-none focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f]"
                />
              </div>
              <p className="text-xs text-gray-600">These values are embedded into the script below and update in real-time. The enrollment token is consumed by the agent after it enrolls.</p>
            </div>
          </div>
        </div>

        {/* Tabs + Script Display */}
        <div className="flex-1 overflow-auto p-6">
          {/* Tabs */}
          <div className="flex items-center gap-2 mb-4">
            <button
              onClick={()=>setActiveTab('windows')}
              className={`px-3 py-1.5 rounded-lg border text-sm flex items-center gap-2 transition-colors ${activeTab==='windows' ? 'bg-[#fd382f] text-white border-[#fd382f]' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'}`}
            >
              <Monitor className="w-4 h-4" />
              Windows
            </button>
            <button
              onClick={()=>setActiveTab('mac')}
              className={`px-3 py-1.5 rounded-lg border text-sm flex items-center gap-2 transition-colors ${activeTab==='mac' ? 'bg-[#fd382f] text-white border-[#fd382f]' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'}`}
            >
              <Apple className="w-4 h-4" />
              macOS
            </button>
            <button
              onClick={()=>setActiveTab('linux')}
              className={`px-3 py-1.5 rounded-lg border text-sm flex items-center gap-2 transition-colors ${activeTab==='linux' ? 'bg-[#fd382f] text-white border-[#fd382f]' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'}`}
            >
              <Terminal className="w-4 h-4" />
              Linux
            </button>
          </div>

          {/* Panel */}
          {activeTab === 'windows' ? (
            <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
              <div className="bg-gray-800 px-4 py-2 flex justify-between items-center border-b border-gray-700">
                <span className="text-gray-400 text-xs font-semibold uppercase tracking-wide">PowerShell</span>
                <div className="flex gap-2">
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs transition-colors"
                  >
                    {copied ? (
                      <>
                        <CheckCircle className="h-3 w-3" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        Copy
                      </>
                    )}
                  </button>
                  <button
                    onClick={handleDownload}
                    className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs transition-colors"
                  >
                    <Download className="h-3 w-3" />
                    Download
                  </button>
                </div>
              </div>
              <div className="flex items-center gap-3 px-4 py-3">
                <input
                  readOnly
                  value={oneLiner}
                  onFocus={(e) => e.target.select()}
                  className="flex-1 bg-transparent text-sm text-green-400 font-mono focus:outline-none"
                />
              </div>
            </div>
          ) : (
            comingSoonBlock
          )}

          <div className="mt-4 bg-yellow-50 border-l-4 border-yellow-400 p-4 rounded">
            <strong className="text-yellow-800 block mb-2">Important Notes:</strong>
            <ul className="text-yellow-700 text-sm space-y-1 list-disc list-inside">
              <li>The script must be run with Administrator privileges</li>
              <li>Ensure the target machine can reach the server at {serverHost}:{serverPort}</li>
              <li>No kernel driver is installed or required - the agent runs MONITOR_ONLY (observes, never blocks)</li>
              <li>Agent heartbeats every 30 seconds; the enrollment token (if provided) is consumed after enrollment</li>
              <li>If the script reports "agent backend not available", this server does not yet serve /api/v1/install/*</li>
            </ul>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="p-6 border-t border-gray-200 flex gap-3 flex-shrink-0 bg-gray-50">
          <button
            onClick={onClose}
            className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
          >
            Close
          </button>
          {activeTab === 'windows' ? (
            <button
              onClick={handleDownload}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-[#fd382f] hover:bg-[#e02f26] text-white rounded-lg transition-colors font-medium"
            >
              <Download className="h-4 w-4" />
              Download Script
            </button>
          ) : (
            <button
              disabled
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-gray-200 text-gray-500 rounded-lg font-medium cursor-not-allowed"
            >
              Coming soon
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// Generate the Phase 1 bootstrap installer (service-based, MONITOR_ONLY, driver-free).
// Mirrors the backend-served installer/bootstrap.ps1 contract. Downloads and verifies the
// signed agent artifact from /api/v1/install/*, hardens the data dir ACL, stages the
// enrollment token in HKLM, and installs the PritrakDLP service.
function generateStandaloneScript(serverIP: string, serverPort: string, enrollToken: string = ''): string {
  const server = `http://${serverIP}:${serverPort}`

  return `# PRITRAK DLP Agent - Bootstrap Installer v1.0
# Install: C:\\Program Files\\PritrakDLP (binaries) / C:\\ProgramData\\PritrakDLP (state)
# Mode: MONITOR_ONLY - the agent observes, classifies, and reports. It NEVER blocks.
# No kernel driver is installed or required. Requires the backend /api/v1/install/* pipeline.
#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Server = '${server}'
$Token  = '${enrollToken}'
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

$sig = Get-AuthenticodeSignature $zip
if ($sig.Status -eq 'Valid') { Write-Step "Signed by: $($sig.SignerCertificate.Subject)" }
else { Write-Host '[Pritrak] WARNING: package is not code-signed (expected in pre-release).' -ForegroundColor Yellow }

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
New-Item -ItemType Directory -Force -Path $InstallDir,$DataDir,"$DataDir\\logs","$DataDir\\policy" | Out-Null
try {
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
} catch {
    # File may still be locked: remove or rename the existing exe, then retry
    Write-Host '[Pritrak] WARNING: extraction failed, removing locked binaries and retrying' -ForegroundColor Yellow
    $lockedExe = "$InstallDir\\PritrakDLP.exe"
    if (Test-Path $lockedExe) {
        try { Remove-Item -LiteralPath $lockedExe -Force -ErrorAction Stop }
        catch { Rename-Item -LiteralPath $lockedExe -NewName 'PritrakDLP.exe.old' -Force -ErrorAction SilentlyContinue }
    }
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
}
Remove-Item $zip -Force

# --- harden data dir (SYSTEM + Administrators only) ---
Write-Step 'Applying ACL to data directory'
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null

# --- config (non-secret) ---
@{
  schema_version = 1
  server_url = $Server
  agent_id = ''
  data_root = $DataDir
  log_level = 'info'
  enforcement_mode = 'MONITOR_ONLY'
  heartbeat_interval_sec = 30
} | ConvertTo-Json -Depth 4 | Set-Content "$DataDir\\config.json" -Encoding UTF8

# --- enrollment token: staged in registry, consumed + deleted by the agent after enroll ---
New-Item -Path 'HKLM:\\SOFTWARE\\PritrakDLP' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\PritrakDLP' -Name 'ServerUrl' -Value $Server
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\PritrakDLP' -Name 'DataPath'  -Value $DataDir
if ($Token) {
    Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\PritrakDLP' -Name 'EnrollmentToken' -Value $Token
    Write-Step "Enrollment token staged (redacted: $($Token.Substring(0, [Math]::Min(12, $Token.Length)))...)"
} else {
    Write-Host '[Pritrak] WARNING: no enrollment token provided. The agent will wait for a token before enrolling.' -ForegroundColor Yellow
}

# --- service ---
if (-not (Test-Path "$InstallDir\\PritrakDLP.exe")) { Fail "PritrakDLP.exe not found in $InstallDir. The downloaded package is empty or invalid." }

if (-not (Get-Service $Svc -ErrorAction SilentlyContinue)) {
    Write-Step 'Creating service'
    try {
        $binaryPath = "\`"$InstallDir\\PritrakDLP.exe\`" --service"
        New-Service -Name $Svc -BinaryPathName $binaryPath -DisplayName "Pritrak DLP Agent" -StartupType Automatic -ErrorAction Stop | Out-Null
    } catch {
        Fail "Failed to create service: $($_.Exception.Message)"
    }
    & sc.exe description $Svc "Pritrak DLP endpoint agent (monitor-only)" | Out-Null
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
if ($s.Status -ne 'Running') { Fail "Service failed to start. See $DataDir\\logs" }

Write-Host ''
Write-Host '  Pritrak DLP Agent installed.' -ForegroundColor Green
Write-Host "  Mode    : MONITOR_ONLY (no blocking)"
Write-Host "  Server  : $Server"
Write-Host "  Logs    : $DataDir\\logs"
Write-Host "  Enrolling in background; the device will appear in the console within ~60s."
Write-Host ''
Write-Host "Press Enter to exit..." -ForegroundColor Yellow
Read-Host
`}

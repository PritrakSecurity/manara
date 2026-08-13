<#
.SYNOPSIS
    Builds the Pritrak DLP user-mode agent (C++) and packages it as a ZIP the
    backend can serve to endpoints.

.DESCRIPTION
    1. Verifies CMake and Visual Studio 2022 (MSVC) are installed.
    2. Configures + builds the user-mode agent (common + usermode) for x64
       Release WITHOUT the kernel driver / WDK.
    3. Verifies PritrakDLP.exe was produced.
    4. Stages the exe and zips it (PritrakDLP.exe at the ZIP root, not in a
       subfolder).
    5. Ships the ZIP to backend/static/artifacts/PritrakDLP-Agent-1.0.0-x64.zip.
    6. Writes backend/static/artifacts/manifest.json (SHA-256 + size).

.NOTES
    Does NOT require the WDK. Kernel-mode components are intentionally excluded.
    Requires nlohmann/json to be discoverable by CMake (as the normal build does).
#>

[CmdletBinding()]
param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

$Root        = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$AgentDir    = Join-Path $Root "agent"
$BuildRoot   = Join-Path $AgentDir "build"
$WrapperDir  = Join-Path $BuildRoot "src"
$OutDir      = Join-Path $BuildRoot "out"
$ArtifactsDir = Join-Path $Root "backend\static\artifacts"
$ZipName     = "PritrakDLP-Agent-$Version-x64.zip"
$ZipPath     = Join-Path $ArtifactsDir $ZipName
$ManifestPath = Join-Path $ArtifactsDir "manifest.json"

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Pritrak DLP Agent - Build & Package" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- 1. Check CMake -------------------------------------------------------
$cmakeCmd = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmakeCmd) {
    Fail "CMake not found. Install CMake 3.20+ from https://cmake.org/download/ and add it to PATH."
}
Write-Host "[OK] CMake: $((cmake --version | Select-Object -First 1).Line)" -ForegroundColor Green

# --- 2. Check Visual Studio 2022 (MSVC) -----------------------------------
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Fail "vswhere.exe not found. The Visual Studio Installer is required to locate VS2022."
}
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    Fail "Visual Studio 2022 with the 'Desktop development with C++' workload was not found."
}
$vsVersion = & $vswhere -latest -products * -property installationVersion
$vsMajor = [int]($vsVersion -split '\.')[0]
if ($vsMajor -lt 17) {
    Fail "Visual Studio version '$vsVersion' detected. Visual Studio 2022 (17.x) or newer is required."
}
$msvcDir = Get-ChildItem (Join-Path $vsPath "VC\Tools\MSVC") -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $msvcDir) {
    Fail "MSVC toolchain not found under '$vsPath'. Install the 'Desktop development with C++' workload."
}
Write-Host "[OK] Visual Studio 2022: $vsPath (MSVC $($msvcDir.Name))" -ForegroundColor Green
Write-Host ""

# --- 3. Generate user-mode-only CMake wrapper (kernel / WDK excluded) -----
Write-Step "Writing user-mode-only CMake wrapper (kernel/WDK excluded)"
New-Item -ItemType Directory -Path $WrapperDir -Force | Out-Null

$commonDir    = (Join-Path $AgentDir "common").Replace('\', '/')
$userModeDir  = (Join-Path $AgentDir "usermode").Replace('\', '/')

$wrapper = @"
cmake_minimum_required(VERSION 3.20)
project(PritrakDLPAgentUsermode VERSION $Version LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# Download nlohmann_json
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# Download SQLite3
FetchContent_Declare(
    sqlite3
    URL https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip
)
FetchContent_MakeAvailable(sqlite3)
add_library(SQLite3 STATIC `${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(SQLite3 PUBLIC `${sqlite3_SOURCE_DIR})

if(WIN32)
    add_definitions(-D_UNICODE -DUNICODE -DWIN32 -D_WIN32 -D_WIN64 -DNOMINMAX -D_WIN32_WINNT=0x0600)
    set(CMAKE_CXX_FLAGS "`${CMAKE_CXX_FLAGS} /W4 /WX- /EHsc")
    set(CMAKE_CXX_FLAGS_RELEASE "`${CMAKE_CXX_FLAGS_RELEASE} /O2 /DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "`${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi /RTC1")
endif()

add_subdirectory("$commonDir" common)
add_subdirectory("$userModeDir" usermode)
"@
Set-Content -Path (Join-Path $WrapperDir "CMakeLists.txt") -Value $wrapper -Encoding UTF8
Write-Host "[OK] Wrapper written to $WrapperDir" -ForegroundColor Green

# --- 4. CMake configure (x64 Release, user-mode only) ---------------------
Write-Step "Configuring CMake (x64 Release, user-mode only)"
$cacheFile = Join-Path $OutDir "CMakeCache.txt"
if (Test-Path $cacheFile) {
    Remove-Item -Path $cacheFile -Force
}
$vcpkgToolchain = ""
if (-not [string]::IsNullOrEmpty($env:VCPKG_ROOT)) {
    $vcpkgToolchain = "-DCMAKE_TOOLCHAIN_FILE=$($env:VCPKG_ROOT)\scripts\buildsystems\vcpkg.cmake"
}

& cmake -S $WrapperDir -B $OutDir -A x64 $vcpkgToolchain
if ($LASTEXITCODE -ne 0) { Fail "CMake configure failed (exit $LASTEXITCODE)." }

# --- 5. CMake build -------------------------------------------------------
Write-Step "Building PritrakDLP (Release x64)"
& cmake --build $OutDir --config Release --target PritrakDLP
if ($LASTEXITCODE -ne 0) { Fail "CMake build failed (exit $LASTEXITCODE)." }

# --- 6. Verify the executable ---------------------------------------------
Write-Step "Verifying PritrakDLP.exe"
$exe = Get-ChildItem -Path $OutDir -Recurse -Filter "PritrakDLP.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -like "*\Release*" } |
    Select-Object -First 1
if (-not $exe) {
    $exe = Get-ChildItem -Path $OutDir -Recurse -Filter "PritrakDLP.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1
}
if (-not $exe) { Fail "PritrakDLP.exe was not produced in '$OutDir'." }
Write-Host "[OK] PritrakDLP.exe: $($exe.FullName)" -ForegroundColor Green

# --- 7-8. Stage + zip (exe at ZIP root) -----------------------------------
Write-Step "Packaging agent"
$staging = Join-Path $env:TEMP ("pritrak-agent-pkg-" + [Guid]::NewGuid().ToString("N"))
$tmpZip  = Join-Path $env:TEMP ("pritrak-agent-" + [Guid]::NewGuid().ToString("N") + ".zip")
New-Item -ItemType Directory -Path $staging -Force | Out-Null
try {
    Copy-Item -LiteralPath $exe.FullName -Destination $staging -Force
    # Use "$staging\*" so PritrakDLP.exe lands at the ROOT of the archive.
    Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $tmpZip -CompressionLevel Optimal -Force
    Write-Host "[OK] Staged and compressed (exe at archive root)" -ForegroundColor Green

    New-Item -ItemType Directory -Path $ArtifactsDir -Force | Out-Null
    Move-Item -LiteralPath $tmpZip -Destination $ZipPath -Force
    Write-Host "[OK] Artifact: $ZipPath" -ForegroundColor Green

    # --- 9. Generate manifest.json ----------------------------------------
    Write-Step "Generating manifest.json"
    $hash = (Get-FileHash -Algorithm SHA256 -Path $ZipPath).Hash
    $size = (Get-Item -LiteralPath $ZipPath).Length
    $manifest = @{
        artifacts = @(
            @{
                name       = $ZipName
                arch       = "x64"
                size_bytes = $size
                sha256     = $hash
            }
        )
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($ManifestPath, $manifestJson, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[OK] Manifest: $ManifestPath (SHA-256 $hash, $size bytes)" -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpZip -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Agent built and packaged successfully. The backend can now serve it to endpoints." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

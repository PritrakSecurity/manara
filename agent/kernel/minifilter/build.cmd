@echo off
setlocal enabledelayedexpansion
REM ============================================================================
REM Pritrak DLP Minifilter Driver - Build Script
REM Uses WDK command-line tools
REM ============================================================================

echo.
echo ============================================
echo   PRITRAK DLP MINIFILTER BUILD
echo   File System Minifilter (x64 Release)
echo ============================================
echo.

REM Set paths
set "WDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WDK_VERSION=10.0.26100.0"

REM Check for VS Developer Command Prompt (cl.exe should be in path)
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo [!] cl.exe not found in PATH
    echo [!] Please run from Developer Command Prompt
    exit /b 1
)

REM Verify WDK
if not exist "%WDK_ROOT%\Include\%WDK_VERSION%\km\fltKernel.h" (
    echo [!] WDK not found at expected location
    exit /b 1
)

echo [+] WDK found: %WDK_VERSION%
echo [+] Building minifilter driver...

REM Create output directory
if not exist "x64\Release" mkdir x64\Release

REM Set include paths
set INCLUDES=-I"%WDK_ROOT%\Include\%WDK_VERSION%\km"
set INCLUDES=%INCLUDES% -I"%WDK_ROOT%\Include\%WDK_VERSION%\shared"
set INCLUDES=%INCLUDES% -I"."

REM Set library paths  
set LIBS=/LIBPATH:"%WDK_ROOT%\Lib\%WDK_VERSION%\km\x64"

REM Compiler flags for kernel mode minifilter
set CFLAGS=/c /Zi /nologo /W4 /WX- /O2 /Oi
set CFLAGS=%CFLAGS% /D_AMD64_ /D_WIN64 /DNDEBUG
set CFLAGS=%CFLAGS% /D_UNICODE /DUNICODE /DPOOL_NX_OPTIN=1
set CFLAGS=%CFLAGS% /kernel /GS- /Gy /Gm-
set CFLAGS=%CFLAGS% /Zp8 /Zc:wchar_t /Zc:forScope /Zc:inline
set CFLAGS=%CFLAGS% /fp:precise /errorReport:prompt
set CFLAGS=%CFLAGS% /wd4100 /wd4201 /wd4214 /wd4152 /wd4706

REM Linker flags for minifilter driver
set LDFLAGS=/DRIVER /NOLOGO /DEBUG /INCREMENTAL:NO
set LDFLAGS=%LDFLAGS% /SUBSYSTEM:NATIVE /ENTRY:DriverEntry
set LDFLAGS=%LDFLAGS% /MERGE:_TEXT=.text /MERGE:_PAGE=PAGE
set LDFLAGS=%LDFLAGS% /NODEFAULTLIB /SECTION:INIT,d
set LDFLAGS=%LDFLAGS% /INTEGRITYCHECK /MACHINE:X64
set LDFLAGS=%LDFLAGS% %LIBS%

REM Required kernel libraries
set KERNEL_LIBS=ntoskrnl.lib hal.lib fltMgr.lib ntstrsafe.lib

echo.
echo [*] Compiling dlp_driver_core.c...
cl.exe %CFLAGS% %INCLUDES% /Fo"x64\Release\dlp_driver_core.obj" dlp_driver_core.c
if errorlevel 1 (
    echo [-] Compilation failed: dlp_driver_core.c
    exit /b 1
)

echo [*] Compiling dlp_policy_cache.c...
cl.exe %CFLAGS% %INCLUDES% /Fo"x64\Release\dlp_policy_cache.obj" dlp_policy_cache.c
if errorlevel 1 (
    echo [-] Compilation failed: dlp_policy_cache.c
    exit /b 1
)

echo [*] Compiling dlp_process_tracker.c...
cl.exe %CFLAGS% %INCLUDES% /Fo"x64\Release\dlp_process_tracker.obj" dlp_process_tracker.c
if errorlevel 1 (
    echo [-] Compilation failed: dlp_process_tracker.c
    exit /b 1
)

echo.
echo [*] Linking driver...
link.exe %LDFLAGS% /OUT:"x64\Release\PritrakDLPFilter.sys" ^
    x64\Release\dlp_driver_core.obj ^
    x64\Release\dlp_policy_cache.obj ^
    x64\Release\dlp_process_tracker.obj ^
    %KERNEL_LIBS%

if errorlevel 1 (
    echo [-] Link failed
    exit /b 1
)

echo.
echo [*] Signing driver (test certificate)...
"%WDK_ROOT%\bin\%WDK_VERSION%\x64\signtool.exe" sign /v /fd SHA256 /s PrivateCertStore /n "Pritrak Test" x64\Release\PritrakDLPFilter.sys 2>nul
if errorlevel 1 (
    echo [!] Signing skipped - test cert not available
    echo [!] Run with test signing enabled: bcdedit /set testsigning on
)

echo.
echo [*] Copying INF file...
copy /Y PritrakDLPFilter.inf x64\Release\ >nul

echo.
echo ============================================
echo   BUILD COMPLETE
echo ============================================
echo.
echo   Driver: x64\Release\PritrakDLPFilter.sys
echo   INF:    x64\Release\PritrakDLPFilter.inf
echo.
echo   To install (run as admin):
echo     1. Enable test signing: bcdedit /set testsigning on
echo     2. Reboot
echo     3. Run: fltmc load PritrakDLPFilter
echo.

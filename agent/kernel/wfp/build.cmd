@echo off
setlocal enabledelayedexpansion
REM ============================================================================
REM Pritrak DLP Network Driver (WFP) - Standalone Build Script
REM Uses WDK command-line tools without VS extension
REM ============================================================================

echo.
echo ============================================
echo   PRITRAK DLP NETWORK DRIVER BUILD
echo   WFP Callout Driver (x64 Release)
echo ============================================
echo.

REM Set paths (use short names to avoid space issues)
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
if not exist "%WDK_ROOT%\Include\%WDK_VERSION%\km\wdm.h" (
    echo [!] WDK not found at expected location
    exit /b 1
)

echo [+] WDK found: %WDK_VERSION%
echo [+] Building WFP driver...

REM Create output directory
if not exist "x64\Release" mkdir x64\Release

REM Set include paths
set INCLUDES=-I"%WDK_ROOT%\Include\%WDK_VERSION%\km"
set INCLUDES=%INCLUDES% -I"%WDK_ROOT%\Include\%WDK_VERSION%\shared"
set INCLUDES=%INCLUDES% -I"%WDK_ROOT%\Include\%WDK_VERSION%\um"
set INCLUDES=%INCLUDES% -I"..\..\..\common\shared"

REM Set library paths  
set LIBS=/LIBPATH:"%WDK_ROOT%\Lib\%WDK_VERSION%\km\x64"

REM Compiler flags for kernel mode
set CFLAGS=/c /Zi /nologo /W4 /WX- /O2 /Oi
set CFLAGS=%CFLAGS% /D_AMD64_ /D_WIN64 /DNDEBUG
set CFLAGS=%CFLAGS% /D_UNICODE /DUNICODE /DPOOL_NX_OPTIN=1
set CFLAGS=%CFLAGS% /DNDIS60=1 /DNDIS_SUPPORT_NDIS6=1 /DNDIS_WDM=1
set CFLAGS=%CFLAGS% /kernel /GS- /Gy /Gm-
set CFLAGS=%CFLAGS% /Zp8 /Zc:wchar_t /Zc:forScope /Zc:inline
set CFLAGS=%CFLAGS% /fp:precise /errorReport:prompt
set CFLAGS=%CFLAGS% /wd4100 /wd4201 /wd4214 /wd4152

REM Linker flags for kernel mode driver
set LDFLAGS=/DRIVER /NOLOGO /DEBUG /INCREMENTAL:NO
set LDFLAGS=%LDFLAGS% /SUBSYSTEM:NATIVE /ENTRY:DriverEntry
set LDFLAGS=%LDFLAGS% /MERGE:_TEXT=.text /MERGE:_PAGE=PAGE
set LDFLAGS=%LDFLAGS% /NODEFAULTLIB /SECTION:INIT,d
set LDFLAGS=%LDFLAGS% /INTEGRITYCHECK /MACHINE:X64
set LDFLAGS=%LDFLAGS% %LIBS%

REM Required kernel libraries
set KERNEL_LIBS=ntoskrnl.lib hal.lib wdm.lib wdmsec.lib fwpkclnt.lib ndis.lib netio.lib uuid.lib

echo.
echo [*] Compiling dlp_wfp_driver.c...
cl.exe %CFLAGS% %INCLUDES% /Fo"x64\Release\dlp_wfp_driver.obj" dlp_wfp_driver.c
if errorlevel 1 (
    echo [-] Compilation failed: dlp_wfp_driver.c
    exit /b 1
)

echo [*] Compiling dlp_email_monitor.c...
cl.exe %CFLAGS% %INCLUDES% /Fo"x64\Release\dlp_email_monitor.obj" dlp_email_monitor.c
if errorlevel 1 (
    echo [-] Compilation failed: dlp_email_monitor.c
    exit /b 1
)

echo.
echo [*] Linking driver...
link.exe %LDFLAGS% /OUT:"x64\Release\PritrakDLPNetwork.sys" ^
    x64\Release\dlp_wfp_driver.obj ^
    x64\Release\dlp_email_monitor.obj ^
    %KERNEL_LIBS%

if errorlevel 1 (
    echo [-] Link failed
    exit /b 1
)

echo.
echo [*] Signing driver (test certificate)...
"%WDK_ROOT%\bin\%WDK_VERSION%\x64\makecert.exe" -r -pe -ss PrivateCertStore -n "CN=Pritrak Test" PritrakTest.cer >nul 2>&1
"%WDK_ROOT%\bin\%WDK_VERSION%\x64\signtool.exe" sign /v /s PrivateCertStore /n "Pritrak Test" /t http://timestamp.digicert.com x64\Release\PritrakDLPNetwork.sys

echo.
echo [*] Copying INF file...
copy /Y PritrakDLPNetwork.inf x64\Release\ >nul

echo.
echo ============================================
echo   BUILD COMPLETE
echo ============================================
echo.
echo   Driver: x64\Release\PritrakDLPNetwork.sys
echo   INF:    x64\Release\PritrakDLPNetwork.inf
echo.
echo   To install (run as admin):
echo     1. Enable test signing: bcdedit /set testsigning on
echo     2. Reboot
echo     3. Run: pnputil /add-driver PritrakDLPNetwork.inf /install
echo.

@echo off
REM Test Minifilter Driver Script
REM Installs and starts the minifilter driver for testing

setlocal

set DRIVER_NAME=PritrakDLP
set DRIVER_PATH=%~dp0..\..\agent\build\Release\minifilter.sys
set SERVICE_NAME=%DRIVER_NAME%

echo Testing Minifilter Driver...
echo.

REM Check if driver file exists
if not exist "%DRIVER_PATH%" (
    echo ERROR: Driver file not found: %DRIVER_PATH%
    echo Please build the agent first using build-agent.ps1
    exit /b 1
)

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    exit /b 1
)

REM Stop and delete existing service if it exists
sc query %SERVICE_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo Stopping existing service...
    sc stop %SERVICE_NAME%
    timeout /t 2 /nobreak >nul
    sc delete %SERVICE_NAME%
    timeout /t 1 /nobreak >nul
)

REM Create service
echo Creating service...
sc create %SERVICE_NAME% type= kernel binPath= "%DRIVER_PATH%" start= demand

if %errorLevel% neq 0 (
    echo ERROR: Failed to create service
    exit /b 1
)

REM Start service
echo Starting service...
sc start %SERVICE_NAME%

if %errorLevel% neq 0 (
    echo ERROR: Failed to start service
    echo Check Event Viewer for details
    exit /b 1
)

echo.
echo Service started successfully!
echo Service Name: %SERVICE_NAME%
echo.
echo To stop the service, run:
echo   sc stop %SERVICE_NAME%
echo.
echo To remove the service, run:
echo   sc delete %SERVICE_NAME%
echo.

endlocal

@echo off
echo ================================================
echo Building Parental Control Complete System
echo ================================================

:: Check prerequisites
echo Checking prerequisites...
go version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Go is not installed or not in PATH
    pause
    exit /b 1
)

node --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Node.js is not installed or not in PATH
    pause
    exit /b 1
)

:: Build Core Service
echo.
echo Building Core Service...
cd core-service
set CGO_ENABLED=1
go mod tidy
go build -ldflags="-H windowsgui" -o core-service.exe
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to build core service
    pause
    exit /b 1
)
echo Core Service built successfully!
cd ..

:: Build UI Admin
echo.
echo Building UI Admin...
cd ui-admin
call npm install
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to install npm dependencies
    pause
    exit /b 1
)

call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to build UI
    pause
    exit /b 1
)
echo UI Admin built successfully!
cd ..

:: Create installer
echo.
echo Creating installer...
makensis auto_installer.nsi
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to create installer (Make sure NSIS is installed)
    pause
    exit /b 1
)

echo.
echo ================================================
echo BUILD COMPLETED SUCCESSFULLY!
echo ================================================
echo.
echo Files created:
echo - core-service\core-service.exe (DNS Service)
echo - ui-admin\dist\ (UI Application)
echo - ParentalControlAutoInstaller.exe (Complete Installer)
echo.
echo To install: Run ParentalControlAutoInstaller.exe as Administrator
echo.
pause

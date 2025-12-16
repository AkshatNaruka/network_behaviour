@echo off
REM Network Behaviour Tool - Desktop GUI Launcher (Windows)
REM This script launches the desktop GUI application

echo Starting Network Behaviour Tool - Desktop GUI...
echo.
echo Note: Some features require Administrator privileges.
echo If packet capture or other privileged operations fail,
echo please run this script as Administrator (right-click and
echo select "Run as Administrator").
echo.

net session >nul 2>&1
if %errorlevel% == 0 (
    echo Running with Administrator privileges
) else (
    echo Running as regular user (some features may be limited)
)

echo.
echo Launching GUI...
python gui.py
pause

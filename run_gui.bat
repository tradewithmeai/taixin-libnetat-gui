@echo off
REM Windows launcher for Taixin LibNetat GUI
REM A GUI wrapper for the Taixin LibNetat Tool by aliosa27
REM Original tool: https://github.com/aliosa27/taixin_tools

echo ===============================================
echo Taixin LibNetat GUI - Windows Launcher
echo ===============================================
echo Original Tool: github.com/aliosa27/taixin_tools
echo Original Author: aliosa27
echo ===============================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.6+ from https://python.org
    echo.
    pause
    exit /b 1
)

REM Check Python version (basic check)
python -c "import sys; exit(0 if sys.version_info >= (3,6) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python 3.6 or higher is required
    python --version
    echo.
    pause
    exit /b 1
)

echo Python version check: OK

REM Run the GUI launcher
echo Starting GUI launcher...
python "%~dp0run_gui.py"

REM Keep window open if there was an error
if %errorlevel% neq 0 (
    echo.
    echo GUI exited with an error
    echo Press any key to exit...
    pause >nul
)
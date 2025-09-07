#!/bin/bash
# Linux/macOS launcher for Taixin LibNetat GUI
# A GUI wrapper for the Taixin LibNetat Tool by aliosa27
# Original tool: https://github.com/aliosa27/taixin_tools

echo "==============================================="
echo "Taixin LibNetat GUI - Unix Launcher"
echo "==============================================="
echo "Original Tool: github.com/aliosa27/taixin_tools"
echo "Original Author: aliosa27 (aliosa27@aliosa27.me)"
echo "==============================================="
echo ""

# Get the directory where the script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in PATH"
    echo "Please install Python 3.6+ using your system's package manager"
    echo ""
    echo "Ubuntu/Debian: sudo apt install python3 python3-tk"
    echo "macOS:         brew install python-tk"
    echo "CentOS/RHEL:   sudo yum install python3 tkinter"
    echo "Arch Linux:    sudo pacman -S python tk"
    exit 1
fi

# Check Python version
python3 -c "import sys; exit(0 if sys.version_info >= (3,6) else 1)" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Python 3.6 or higher is required"
    python3 --version
    exit 1
fi

echo "Python version check: OK"

# Check for tkinter
python3 -c "import tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: tkinter is not available"
    echo "Please install tkinter:"
    echo ""
    echo "Ubuntu/Debian: sudo apt install python3-tk"
    echo "CentOS/RHEL:   sudo yum install tkinter"
    echo "macOS:         brew install python-tk"
    echo "Arch Linux:    sudo pacman -S tk"
    exit 1
fi

echo "tkinter available: OK"
echo ""

# Change to script directory
cd "$DIR"

# Run the GUI launcher
echo "Starting GUI launcher..."
python3 run_gui.py

exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo ""
    echo "GUI exited with error code: $exit_code"
    read -p "Press Enter to continue..."
fi
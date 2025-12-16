#!/bin/bash
# Network Behaviour Tool - Desktop GUI Launcher
# This script launches the desktop GUI application

echo "Starting Network Behaviour Tool - Desktop GUI..."
echo ""
echo "Note: Some features require administrator/root privileges."
echo "If packet capture, ARP scanning, or other privileged operations"
echo "fail, please run this script with sudo."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Running as regular user (some features may be limited)"
else
    echo "Running with administrator privileges"
fi

echo ""
echo "Launching GUI..."
python3 gui.py

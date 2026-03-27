#!/usr/bin/env bash
# PortHawk Dashboard launcher for macOS and Linux
# chmod +x start_dashboard.sh && ./start_dashboard.sh

set -e

echo ""
echo " PortHawk Dashboard"
echo " ------------------"
echo " Opening at http://localhost:8501"
echo ""

python3 start_dashboard.py || {
    echo ""
    echo "Something went wrong. Install dependencies first:"
    echo "  pip install porthawk[dashboard]"
    exit 1
}

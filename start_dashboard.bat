@echo off
title PortHawk Dashboard
echo.
echo  PortHawk Dashboard
echo  ------------------
echo  Opening at http://localhost:8501
echo.

python start_dashboard.py

if errorlevel 1 (
    echo.
    echo Something went wrong. Make sure you installed the dependencies:
    echo   pip install porthawk[dashboard]
    echo.
    pause
)

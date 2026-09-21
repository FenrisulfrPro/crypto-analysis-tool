@echo off
setlocal enableextensions
cd /d "%~dp0"
title CryptoAnalysisTool

rem ---- Check Python ----
python --version >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.9+ and add it to PATH.
    echo [Error] See: https://www.python.org/downloads/
    pause
    exit /b 1
)

rem ---- Check / install dependencies ----
python -c "import PySide6, gmssl, scapy, cryptography" >nul 2>nul
if errorlevel 1 (
    echo [INFO] First run: installing dependencies, please wait...
    python -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    if errorlevel 1 (
        echo [ERROR] Dependency install failed. Run this yourself:
        echo     python -m pip install -r requirements.txt
        pause
        exit /b 1
    )
)

echo [OK] Launching CryptoAnalysisTool...
python main.py

pause
endlocal

@echo off
title JOCKY Forensic Agent — Auto-Deploy
color 0A
echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║    JOCKY FORENSIC AGENT — DEPLOYMENT USB    ║
echo  ║    Smart India Hackathon 2026 Edition        ║
echo  ╚══════════════════════════════════════════════╝
echo.

:: Step 1: Check Python
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] Python not found. Please install Python 3.11+
    pause
    exit /b 1
)
echo   [OK] Python found.

:: Step 2: Install dependencies
echo [2/4] Installing JOCKY agent dependencies...
pip install -r "%~dp0requirements.txt" --quiet --disable-pip-version-check
if %errorlevel% neq 0 (
    echo   [!] Dependency installation failed.
    pause
    exit /b 1
)
echo   [OK] Dependencies installed.

:: Step 3: Allow through Windows Firewall (for incoming connections)
echo [3/4] Configuring Windows Firewall...
netsh advfirewall firewall add rule name="JOCKY Agent" dir=in action=allow protocol=TCP localport=5000 >nul 2>&1
echo   [OK] Firewall rule added.

:: Step 4: Launch JOCKY agent
echo [4/4] Starting JOCKY Agent on port 5000...
echo.
echo  ┌─────────────────────────────────────────────┐
echo  │  Agent URL: http://[THIS-IP]:5000           │
echo  │  Health:    http://[THIS-IP]:5000/ping      │
echo  │  Press Ctrl+C to stop the agent             │
echo  └─────────────────────────────────────────────┘
echo.
python "%~dp0agent.py"

pause

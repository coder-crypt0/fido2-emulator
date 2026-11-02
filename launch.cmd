@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
    echo Run PowerShell -ExecutionPolicy Bypass -File scripts\setup.ps1 first.
    pause
    exit /b 1
)
start "" ".venv\Scripts\pythonw.exe" -m fido2_emulator gui

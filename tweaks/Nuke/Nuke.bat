@echo off

cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0Nuke.ps1" -Force -SkipRestorePoint
pause

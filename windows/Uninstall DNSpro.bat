@echo off
rem Double-click to remove DNSpro and restore normal DNS.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"

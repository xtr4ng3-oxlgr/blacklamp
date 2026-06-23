@echo off
title BLACKLAMP
color 0C
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 src\blacklamp.py
    exit /b
)

where python >nul 2>nul
if %errorlevel%==0 (
    python src\blacklamp.py
    exit /b
)

echo No se encontro Python.
pause

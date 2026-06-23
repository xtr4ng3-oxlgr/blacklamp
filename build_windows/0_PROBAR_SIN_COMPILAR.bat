@echo off
title BLACKLAMP - Probar sin compilar
color 0C
cd /d "%~dp0\.."

echo ============================================================
echo BLACKLAMP - PROBAR SIN COMPILAR
echo xtr4ng3
echo ============================================================
echo.

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 src\blacklamp.py
    pause
    exit /b
)

where python >nul 2>nul
if %errorlevel%==0 (
    python src\blacklamp.py
    pause
    exit /b
)

echo No se encontro Python.
pause

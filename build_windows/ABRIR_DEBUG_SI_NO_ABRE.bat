@echo off
title BLACKLAMP - Debug
color 0C
cd /d "%~dp0"
if not exist logs mkdir logs

echo Inicio debug %date% %time% > logs\debug_inicio.log

if exist "BLACKLAMP\BLACKLAMP.exe" (
    "BLACKLAMP\BLACKLAMP.exe" >> logs\debug_inicio.log 2>&1
    echo.
    echo Codigo salida: %errorlevel%
    echo Revisar logs\debug_inicio.log
    pause
    exit /b
)

echo No se encontro BLACKLAMP\BLACKLAMP.exe
pause

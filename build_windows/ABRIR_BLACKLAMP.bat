@echo off
title BLACKLAMP
color 0C
cd /d "%~dp0"
if not exist logs mkdir logs
if not exist reports mkdir reports
if not exist data mkdir data
if not exist quarantine mkdir quarantine

echo Inicio BLACKLAMP %date% %time% > logs\ultimo_inicio.log

if exist "BLACKLAMP\BLACKLAMP.exe" (
    start "" "BLACKLAMP\BLACKLAMP.exe"
    exit /b
)

echo No se encontro BLACKLAMP\BLACKLAMP.exe
pause

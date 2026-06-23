@echo off
title BLACKLAMP - Compilar EXE portable
color 0C
cd /d "%~dp0\.."

echo ============================================================ > BUILD_LOG.txt
echo BLACKLAMP - BUILD LOG >> BUILD_LOG.txt
echo xtr4ng3 >> BUILD_LOG.txt
echo Fecha: %date% %time% >> BUILD_LOG.txt
echo ============================================================ >> BUILD_LOG.txt

echo.
echo ============================================================
echo BLACKLAMP
echo COMPILAR EXE PORTABLE
echo xtr4ng3
echo ============================================================
echo.
pause

set PYTHON_CMD=

where py >nul 2>nul
if %errorlevel%==0 set PYTHON_CMD=py -3

if "%PYTHON_CMD%"=="" (
    where python >nul 2>nul
    if %errorlevel%==0 set PYTHON_CMD=python
)

if "%PYTHON_CMD%"=="" (
    echo ERROR: No se encontro Python. >> BUILD_LOG.txt
    echo No se encontro Python.
    pause
    exit /b
)

echo Python usado: %PYTHON_CMD% >> BUILD_LOG.txt
%PYTHON_CMD% --version >> BUILD_LOG.txt 2>&1

echo Probando imports...
%PYTHON_CMD% -c "import tkinter, json, hashlib, urllib.parse, pathlib, shutil; print('IMPORTS OK')" >> BUILD_LOG.txt 2>&1

if %errorlevel% neq 0 (
    echo ERROR: Fallo prueba de imports. >> BUILD_LOG.txt
    echo Fallo prueba de imports. Revisar BUILD_LOG.txt
    pause
    exit /b
)

echo Instalando/verificando PyInstaller...
%PYTHON_CMD% -m pip install pyinstaller >> BUILD_LOG.txt 2>&1

if %errorlevel% neq 0 (
    echo ERROR: Fallo instalando PyInstaller. >> BUILD_LOG.txt
    echo Fallo PyInstaller. Revisar BUILD_LOG.txt
    pause
    exit /b
)

rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
rmdir /s /q CLIENTE_PORTABLE 2>nul
del /q BLACKLAMP.spec 2>nul

echo Compilando...
%PYTHON_CMD% -m PyInstaller ^
  --onedir ^
  --windowed ^
  --clean ^
  --noconfirm ^
  --name BLACKLAMP ^
  --hidden-import tkinter ^
  --hidden-import tkinter.ttk ^
  --hidden-import tkinter.filedialog ^
  --hidden-import tkinter.messagebox ^
  "src\blacklamp.py" >> BUILD_LOG.txt 2>&1

if %errorlevel% neq 0 (
    echo ERROR: Fallo PyInstaller. >> BUILD_LOG.txt
    echo Fallo compilacion. Revisar BUILD_LOG.txt
    pause
    exit /b
)

mkdir CLIENTE_PORTABLE
mkdir CLIENTE_PORTABLE\data
mkdir CLIENTE_PORTABLE\logs
mkdir CLIENTE_PORTABLE\reports
mkdir CLIENTE_PORTABLE\quarantine

xcopy /E /I /Y "dist\BLACKLAMP" "CLIENTE_PORTABLE\BLACKLAMP" >> BUILD_LOG.txt 2>&1
copy /Y "build_windows\ABRIR_BLACKLAMP.bat" "CLIENTE_PORTABLE\ABRIR_BLACKLAMP.bat" >> BUILD_LOG.txt 2>&1
copy /Y "build_windows\ABRIR_DEBUG_SI_NO_ABRE.bat" "CLIENTE_PORTABLE\ABRIR_DEBUG_SI_NO_ABRE.bat" >> BUILD_LOG.txt 2>&1
copy /Y "README.md" "CLIENTE_PORTABLE\README.txt" >> BUILD_LOG.txt 2>&1

echo OK: Build completado. >> BUILD_LOG.txt

echo.
echo ============================================================
echo BUILD LISTO
echo Abrir:
echo CLIENTE_PORTABLE\ABRIR_BLACKLAMP.bat
echo.
echo Entregar al usuario final:
echo CLIENTE_PORTABLE
echo ============================================================
pause

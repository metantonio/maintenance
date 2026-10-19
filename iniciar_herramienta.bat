@echo off
setlocal EnableDelayedExpansion
title NetShield y DiskCleaner Pro

cd /d "%~dp0"

echo ============================================================
echo      NETSHIELD Y DISKCLEANER PRO - SUITE DE MANTENIMIENTO
echo ============================================================
echo.

if exist "venv\Scripts\python.exe" (
    echo [INFO] Utilizando entorno virtual existente...
    set "PYTHON_EXE=venv\Scripts\python.exe"
    goto RUN_APP
)

echo [INFO] Creando entorno virtual (venv)...
set "PY_CMD=python"
where python >nul 2>nul
if %errorlevel% neq 0 (
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        set "PY_CMD=py"
    ) else (
        if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
            set "PY_CMD=%LOCALAPPDATA%\Python\bin\python.exe"
        )
    )
)

%PY_CMD% -m venv venv
if not exist "venv\Scripts\python.exe" (
    echo [ERROR] No se pudo crear el entorno virtual venv.
    echo Asegurate de que Python este instalado en el sistema.
    pause
    exit /b 1
)

set "PYTHON_EXE=venv\Scripts\python.exe"

:RUN_APP
echo [INFO] Verificando dependencias necesarias...
"%PYTHON_EXE%" -c "import customtkinter, psutil, requests" >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Instalando librerias requeridas...
    "%PYTHON_EXE%" -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Hubo un problema al instalar las dependencias.
        pause
        exit /b 1
    )
    echo [OK] Dependencias instaladas con exito.
)

"%PYTHON_EXE%" main.py
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] La aplicacion finalizo con codigo de error %errorlevel%.
    pause
)
exit /b 0

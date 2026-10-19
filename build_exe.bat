@echo off
setlocal EnableDelayedExpansion
title Compilador a .EXE - NetShield Pro

cd /d "%~dp0"

echo ============================================================
echo           COMPILADOR A EJECUTABLE INDEPENDIENTE (.EXE)
echo                    NetShield y DiskCleaner Pro
echo ============================================================
echo.

REM 1. Verificar o crear entorno virtual
if exist "venv\Scripts\python.exe" (
    echo [INFO] Utilizando entorno virtual existente...
    set "PYTHON_EXE=venv\Scripts\python.exe"
    goto CHECK_TOOLS
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

:CHECK_TOOLS
REM 2. Verificar dependencias y PyInstaller
echo [INFO] Verificando PyInstaller y librerias del proyecto...
"%PYTHON_EXE%" -c "import customtkinter, psutil, requests, PyInstaller" >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Instalando dependencias necesarias y PyInstaller...
    "%PYTHON_EXE%" -m pip install -r requirements.txt pyinstaller
    if %errorlevel% neq 0 (
        echo [ERROR] Hubo un problema al instalar las herramientas de compilacion.
        pause
        exit /b 1
    )
    echo [OK] Herramientas instaladas correctamente.
    echo.
)

REM 3. Compilar el archivo ejecutable con PyInstaller
echo [INFO] Compilando ejecutable standalone con PyInstaller...
echo [INFO] Esto puede demorar unos segundos...
echo.

venv\Scripts\pyinstaller.exe --noconsole --onefile --clean --collect-all customtkinter --name "NetShieldPro" main.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] La compilacion ha fallado. Revisa los mensajes anteriores.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo              COMPILACION COMPLETADA CON EXITO
echo ============================================================
echo.
echo Tu archivo ejecutable ha sido generado en:
echo   dist\NetShieldPro.exe
echo.
echo Ya puedes moverlo o ejecutarlo directamente sin necesidad
echo de tener Python ni ninguna libreria instalada.
echo ============================================================
echo.
pause
exit /b 0

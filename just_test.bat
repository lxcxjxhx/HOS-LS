@echo off
setlocal enabledelayedexpansion

set "PROJECT_DIR=c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS"
set "OUTPUT_DIR=c:\1AAA_PROJECT\HOS\HOS-LS\test_scan"
set "TARGET_PATH=c:\1AAA_PROJECT\HOS\HOS-LS\real-project\bizspring-open-main"
set "LOG_FILE=%OUTPUT_DIR%\scan_test_new.log"
set "CONDA_ROOT=C:\ProgramData\miniconda3"
set "ENV_NAME=hos-ls-test"

echo ========================================
echo HOS-LS Scan Test Script
echo ========================================
echo.

echo [1/5] Checking Conda environment...
if not exist "%CONDA_ROOT%" (
    echo ERROR: Miniconda3 not found at %CONDA_ROOT%
    echo Please install Miniconda3 first
    exit /b 1
)
echo Conda found at: %CONDA_ROOT%
echo.

echo [2/5] Checking Python environment...
"%CONDA_ROOT%\python.exe" --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python in Conda is not working
    exit /b 1
)
echo Python found:
"%CONDA_ROOT%\python.exe" --version
echo.

echo [3/5] Creating/Updating conda environment: %ENV_NAME%...
"%CONDA_ROOT%\Scripts\conda.exe" env list | findstr /i "%ENV_NAME%" >nul
if errorlevel 1 (
    echo Creating new environment: %ENV_NAME%
    "%CONDA_ROOT%\Scripts\conda.exe" create -n %ENV_NAME% python=3.11 -y
    if errorlevel 1 (
        echo ERROR: Failed to create conda environment
        exit /b 1
    )
) else (
    echo Environment %ENV_NAME% already exists
)
echo.

echo [4/5] Installing dependencies in environment %ENV_NAME%...
call "%CONDA_ROOT%\Scripts\activate.bat" %ENV_NAME%
if errorlevel 1 (
    echo ERROR: Failed to activate environment
    exit /b 1
)
echo Environment activated: %ENV_NAME%
pip install -r "%PROJECT_DIR%\requirements.txt"
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    exit /b 1
)
echo Dependencies installed successfully
echo.

echo [5/5] Running scan...
echo Command: python -m src.cli.main scan --pure-ai --test 100 "%TARGET_PATH%" -o %OUTPUT_DIR%\test_scan_new.html
echo.
echo Starting scan at %date% %time%
echo ----------------------------------------

cd /d "%PROJECT_DIR%"
echo Running scan command...

powershell.exe -NoProfile -Command "cd 'c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS'; python -m src.cli.main scan --pure-ai --test 100 'c:\1AAA_PROJECT\HOS\HOS-LS\real-project\bizspring-open-main' -o 'c:\1AAA_PROJECT\HOS\HOS-LS\test_scan\test_scan_new.html' 2>&1 | Tee-Object -FilePath 'c:\1AAA_PROJECT\HOS\HOS-LS\test_scan\scan_test_new.log'"

echo.
echo ----------------------------------------
echo Scan completed at %date% %time%
echo Log file: %LOG_FILE%
echo Report: %OUTPUT_DIR%\test_scan_new.html
echo ========================================

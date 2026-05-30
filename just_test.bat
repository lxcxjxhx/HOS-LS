@echo off
setlocal enabledelayedexpansion

REM ========================================
REM HOS-LS Scan Test Script (Enhanced)
REM ========================================
REM Usage:
REM   just_test.bat [file_count] [output_file]
REM
REM Examples:
REM   just_test.bat                - Scan 100 files, default output
REM   just_test.bat 50             - Scan 50 files, default output
REM   just_test.bat 50 my.html     - Scan 50 files, output to my.html
REM   just_test.bat help           - Show this help
REM ========================================

set "PROJECT_DIR=c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS"
set "OUTPUT_DIR=c:\1AAA_PROJECT\HOS\HOS-LS\test_scan"
set "TARGET_PATH=c:\1AAA_PROJECT\HOS\HOS-LS\real-project\bizspring-open-main"
set "CONDA_ROOT=C:\ProgramData\miniconda3"
set "ENV_NAME=hos-ls-test"

REM Default values
set "FILE_COUNT=100"
set "OUTPUT_FILE=test_scan_new.html"

REM Check for help request
if /i "%~1"=="help" goto :show_help
if /i "%~1"=="/?" goto :show_help
if /i "%~1"=="-h" goto :show_help

REM Parse file count (first parameter)
if not "%~1"=="" (
    set "FILE_COUNT=%~1"
    echo [INFO] Using custom file count: !FILE_COUNT!
)

REM Parse output filename (second parameter)
if not "%~2"=="" (
    set "OUTPUT_FILE=%~2"
    echo [INFO] Using custom output file: !OUTPUT_FILE!
)

set "LOG_FILE=%OUTPUT_DIR%\scan_!FILE_COUNT!files.log"
set "REPORT_PATH=%OUTPUT_DIR%\!OUTPUT_FILE!"

echo ========================================
echo HOS-LS Scan Test Script
echo ========================================
echo [CONFIG] Target: %TARGET_PATH%
echo [CONFIG] Files to scan: %FILE_COUNT%
echo [CONFIG] Output report: %REPORT_PATH%
echo [CONFIG] Log file: %LOG_FILE%
echo ========================================
echo.

REM ===== API Key Configuration =====
echo [API] Checking DEEPSEEK_API_KEY...

REM Check if environment variable already exists
if defined DEEPSEEK_API_KEY (
    echo [INFO] DEEPSEEK_API_KEY already set in environment
    set "API_KEY_SOURCE=environment variable"
    goto :api_key_verified
)

REM Check if key exists in project config file
if exist "%PROJECT_DIR%\hos-ls.yaml" (
    findstr /i "api_key" "%PROJECT_DIR%\hos-ls.yaml" >nul 2>&1
    if not errorlevel 1 (
        echo [INFO] Found api_key in hos-ls.yaml
        set "API_KEY_SOURCE=config file"
        goto :api_key_verified
    )
)

REM Prompt user for API key
echo.
echo [!] API Key not found. Please enter your DeepSeek API Key:
echo     (Key will be stored as temporary environment variable for this session only)
echo.
set /p "DEEPSEEK_API_KEY=Enter API Key: "

REM Validate key is not empty
if "!DEEPSEEK_API_KEY!"=="" (
    echo [ERROR] API Key cannot be empty!
    echo Please set DEEPSEEK_API_KEY environment variable or edit hos-ls.yaml
    exit /b 1
)

echo [OK] API Key received (!DEEPSEEK_API_KEY:~0,10!...)
set "API_KEY_SOURCE=user input (temporary)"
echo.

:api_key_verified
echo [VERIFY] Testing API Key connectivity...
echo.

REM Verify API key by making a test request
powershell.exe -NoProfile -Command ^
    "$headers = @{ 'Authorization' = 'Bearer $env:DEEPSEEK_API_KEY'; 'Content-Type' = 'application/json' }; ^
     $body = '{\"model\": \"deepseek-v4-flash\", \"messages\": [{\"role\": \"user\", \"content\": \"test\"}], \"max_tokens\": 10}'; ^
     try { ^
         $response = Invoke-RestMethod -Uri 'https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1/chat/completions' -Method Post -Headers $headers -Body $body -TimeoutSec 15; ^
         Write-Host '[OK] API Key verification successful!'; ^
         exit 0 ^
     } catch { ^
         Write-Host '[ERROR] API Key verification failed:'; ^
         Write-Host $_.Exception.Message; ^
         exit 1 ^
     }"

if errorlevel 1 (
    echo.
    echo [ERROR] API Key is invalid or network error!
    echo Please check:
    echo   1. API Key is correct
    echo   2. Network connection
    echo   3. Proxy settings if behind firewall
    echo.
    echo You can set the key permanently via:
    echo   setx DEEPSEEK_API_KEY "your-key-here"
    echo.
    echo Or edit: %PROJECT_DIR%\hos-ls.yaml
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo [READY] API Configuration Complete
echo ========================================
echo.

echo [1/6] Checking Conda environment...
if not exist "%CONDA_ROOT%" (
    echo ERROR: Miniconda3 not found at %CONDA_ROOT%
    echo Please install Miniconda3 first
    exit /b 1
)
echo Conda found at: %CONDA_ROOT%
echo.

echo [2/6] Checking Python environment...
"%CONDA_ROOT%\python.exe" --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python in Conda is not working
    exit /b 1
)
echo Python found:
"%CONDA_ROOT%\python.exe" --version
echo.

echo [3/6] Creating/Updating conda environment: %ENV_NAME%...
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

echo [4/6] Checking dependencies in environment %ENV_NAME%...
call "%CONDA_ROOT%\Scripts\activate.bat" %ENV_NAME%
if errorlevel 1 (
    echo ERROR: Failed to activate environment
    exit /b 1
)
echo Environment activated: %ENV_NAME%

REM Auto-install dependencies only if critical modules are missing
python -c "import click" >nul 2>&1
if errorlevel 1 (
    echo [INFO] click module not found, installing dependencies...
    pip install -r "%PROJECT_DIR%\requirements.txt"
    if errorlevel 1 (
        echo WARNING: Failed to install some dependencies
        echo Attempting to continue anyway...
    ) else (
        echo Dependencies installed successfully
    )
) else (
    echo Dependencies check passed
)
echo.

echo [5/6] Running scan...
echo Command: python -m src.cli.main scan --pure-ai --test %FILE_COUNT% "%TARGET_PATH%" -o "%REPORT_PATH%"
echo.

REM Create output directory if not exists
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo Starting scan at %date% %time%
echo ----------------------------------------

cd /d "%PROJECT_DIR%"
echo Running scan command...

powershell.exe -NoProfile -Command "cd '%PROJECT_DIR%'; python -m src.cli.main scan --pure-ai --test %FILE_COUNT% '%TARGET_PATH%' -o '%REPORT_PATH%' 2>&1 | Tee-Object -FilePath '%LOG_FILE%'"

if errorlevel 1 (
    echo.
    echo ----------------------------------------
    echo ERROR: Scan failed with exit code %errorlevel%
    echo Check log file for details: %LOG_FILE%
    echo ========================================
    exit /b 1
)

echo.
echo ----------------------------------------
echo Scan completed successfully at %date% %time%
echo Log file: %LOG_FILE%
echo Report: %REPORT_PATH%
echo ========================================

REM Check if report was generated
if exist "%REPORT_PATH%" (
    echo.
    echo [SUCCESS] Report generated: %REPORT_PATH%
    echo File size:
    for %%A in ("%REPORT_PATH%") do echo   %%~zA bytes
) else (
    echo.
    echo [WARNING] Report file not found at: %REPORT_PATH%
)

echo ========================================
exit /b 0

:show_help
echo ========================================
echo HOS-LS Scan Test Script - Usage
echo ========================================
echo.
echo Syntax:
echo   just_test.bat [file_count] [output_file]
echo.
echo Parameters:
echo   file_count    Number of files to scan (default: 100)
echo   output_file   Output HTML filename (default: test_scan_new.html)
echo.
echo Examples:
echo   just_test.bat                  - Scan 100 files with default output
echo   just_test.bat 50               - Scan 50 files with default output
echo   just_test.bat 50 report.html   - Scan 50 files, output to report.html
echo   just_test.bat 10 quick.html    - Scan 10 files, output to quick.html
echo   just_test.bat help             - Show this help message
echo.
echo Output Location:
echo   All reports and logs are saved to: %OUTPUT_DIR%
echo.
echo API Key Configuration:
echo   1. Set environment variable: setx DEEPSEEK_API_KEY "your-key"
echo   2. Edit hos-ls.yaml: ai.api_key: "your-key"
echo   3. Enter interactively when prompted (temporary, session only)
echo.
echo ========================================
exit /b 0

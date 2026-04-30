@echo off
REM HOS-LS Windows 安装脚本
REM 使用方法: install.bat

setlocal enabledelayedexpansion

set "INSTALL_DIR=%USERPROFILE%\.hos-ls"
set "SKIP_VENV=false"
set "DEVELOPMENT=false"

echo ========================================
echo   HOS-LS 安装脚本
echo   AI 生成代码安全扫描工具
echo ========================================
echo.

:check_python
echo 正在检查 Python 环境...

where python >nul 2>nul
if %errorlevel% neq 0 (
echo 错误: 未找到 Python。请先安装 Python 3.8+
pause
exit /b 1
)

python --version
echo 检测到 Python 环境
echo.
goto check_pip

:check_pip
echo 正在检查 pip...

python -m pip --version >nul 2>nul
if %errorlevel% neq 0 (
echo 正在安装 pip...
python -m ensurepip --upgrade
)

echo pip 已就绪
echo.
goto create_venv

:create_venv
if "%SKIP_VENV%" equ "true" (
echo 跳过虚拟环境创建
echo.
goto install_dependencies
)

echo 正在创建虚拟环境...

if exist "%INSTALL_DIR%\venv" (
echo 虚拟环境已存在: %INSTALL_DIR%\venv
echo.
goto install_dependencies
)

python -m venv "%INSTALL_DIR%\venv"
if %errorlevel% neq 0 (
echo 错误: 创建虚拟环境失败
pause
exit /b 1
)

echo 虚拟环境创建成功: %INSTALL_DIR%\venv
echo.
goto install_dependencies

:install_dependencies
echo 正在安装依赖...

if "%SKIP_VENV%" neq "true" (
set "VENV_ACTIVATE=%INSTALL_DIR%\venv\Scripts\activate.bat"
call "%VENV_ACTIVATE%"
)

python -m pip install --upgrade pip

if exist "requirements.txt" (
pip install -r requirements.txt
)

if exist "pyproject.toml" (
pip install poetry
poetry install
)

echo 依赖安装完成
echo.
goto create_config

:create_config
echo 正在创建配置文件...

mkdir "%INSTALL_DIR%\config" 2>nul

set "CONFIG_FILE=%INSTALL_DIR%\config\config.yaml"

if not exist "%CONFIG_FILE%" (
echo # HOS-LS 默认配置文件 > "%CONFIG_FILE%"
echo. >> "%CONFIG_FILE%"
echo # AI 配置 >> "%CONFIG_FILE%"
echo ai: >> "%CONFIG_FILE%"
echo   provider: deepseek >> "%CONFIG_FILE%"
echo   model: deepseek-chat >> "%CONFIG_FILE%"
echo   api_key: null >> "%CONFIG_FILE%"
echo   temperature: 0.0 >> "%CONFIG_FILE%"
echo   max_tokens: 4096 >> "%CONFIG_FILE%"
echo   base_url: "https://api.deepseek.com" >> "%CONFIG_FILE%"
echo. >> "%CONFIG_FILE%"
echo # 扫描配置 >> "%CONFIG_FILE%"
echo scan: >> "%CONFIG_FILE%"
echo   max_workers: 4 >> "%CONFIG_FILE%"
echo   cache_enabled: true >> "%CONFIG_FILE%"
echo   incremental: true >> "%CONFIG_FILE%"
echo. >> "%CONFIG_FILE%"
echo # 规则配置 >> "%CONFIG_FILE%"
echo rules: >> "%CONFIG_FILE%"
echo   ruleset: default >> "%CONFIG_FILE%"
echo   severity_threshold: low >> "%CONFIG_FILE%"
echo. >> "%CONFIG_FILE%"
echo # 报告配置 >> "%CONFIG_FILE%"
echo report: >> "%CONFIG_FILE%"
echo   format: html >> "%CONFIG_FILE%"
echo   output: .\security-report >> "%CONFIG_FILE%"

echo 配置文件已创建: %CONFIG_FILE%
echo.
) else (
echo 配置文件已存在: %CONFIG_FILE%
echo.
)
goto create_wrapper

:create_wrapper
echo 正在创建包装器脚本...

mkdir "%INSTALL_DIR%\bin" 2>nul

set "WRAPPER_FILE=%INSTALL_DIR%\bin\hos-ls.bat"

(echo @echo off
echo call "%INSTALL_DIR%\venv\Scripts\activate.bat"
echo python -m src.cli.main %%* ) > "%WRAPPER_FILE%"

:add_to_path
echo 正在添加到系统 PATH...

set "BIN_DIR=%INSTALL_DIR%\bin"
setx PATH "%PATH%;%BIN_DIR%" /M
if %errorlevel% neq 0 (
echo 警告: 添加 PATH 失败，请手动添加 %BIN_DIR% 到系统 PATH
echo.
) else (
echo 已添加 %BIN_DIR% 到系统 PATH
echo.
)
goto show_success

:show_success
echo ========================================
echo   安装完成!
echo ========================================
echo.
echo 使用方法:
echo   hos-ls scan .              # 扫描当前目录
echo   hos-ls scan .\src -f html  # 生成 HTML 报告
echo   hos-ls rules               # 列出可用规则
echo   hos-ls config              # 显示当前配置
echo.
echo 配置文件位置: %INSTALL_DIR%\config\config.yaml
echo.
echo 请重新打开命令提示符以使 PATH 更改生效
echo.
pause
goto end

:end
endlocal
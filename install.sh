#!/bin/bash
# HOS-LS Linux/macOS 安装脚本
# 使用方法: ./install.sh

set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/.hos-ls}"
SKIP_VENV="${SKIP_VENV:-false}"
DEVELOPMENT="${DEVELOPMENT:-false}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  HOS-LS 安装脚本${NC}"
echo -e "${CYAN}  AI 生成代码安全扫描工具${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

check_python() {
    echo -e "${YELLOW}正在检查 Python 环境...${NC}"
    
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}错误: 未找到 Python。请先安装 Python 3.8+${NC}"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}检测到 $PYTHON_VERSION${NC}"
}

check_pip() {
    echo -e "${YELLOW}正在检查 pip...${NC}"
    
    if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
        echo -e "${YELLOW}正在安装 pip...${NC}"
        python3 -m ensurepip --upgrade
    fi
    
    echo -e "${GREEN}pip 已就绪${NC}"
}

create_venv() {
    local venv_path="$1"
    
    if [ "$SKIP_VENV" = "true" ]; then
        echo -e "${YELLOW}跳过虚拟环境创建${NC}"
        return
    fi
    
    echo -e "${YELLOW}正在创建虚拟环境...${NC}"
    
    if [ -d "$venv_path" ]; then
        echo -e "${GREEN}虚拟环境已存在: $venv_path${NC}"
        return
    fi
    
    python3 -m venv "$venv_path"
    echo -e "${GREEN}虚拟环境创建成功: $venv_path${NC}"
}

install_dependencies() {
    local venv_path="$1"
    
    echo -e "${YELLOW}正在安装依赖...${NC}"
    
    if [ "$SKIP_VENV" != "true" ]; then
        source "$venv_path/bin/activate"
    fi
    
    python3 -m pip install --upgrade pip
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    fi
    
    if [ -f "pyproject.toml" ]; then
        if command -v poetry &> /dev/null; then
            poetry install
        else
            echo -e "${YELLOW}正在安装 poetry...${NC}"
            pip install poetry
            poetry install
        fi
    fi
    
    echo -e "${GREEN}依赖安装完成${NC}"
}

create_config() {
    local config_dir="$1"
    
    echo -e "${YELLOW}正在创建配置文件...${NC}"
    
    mkdir -p "$config_dir"
    
    local config_file="$config_dir/config.yaml"
    
    if [ ! -f "$config_file" ]; then
        cat > "$config_file" << 'EOF'
# HOS-LS 默认配置文件

# AI 配置
ai:
  provider: deepseek
  model: deepseek-chat
  base_url: "https://api.deepseek.com"
  api_key: null
  temperature: 0.0
  max_tokens: 4096

# 扫描配置
scan:
  max_workers: 4
  cache_enabled: true
  incremental: true

# 规则配置
rules:
  ruleset: default
  severity_threshold: low

# 报告配置
report:
  format: html
  output: ./security-report
EOF
        echo -e "${GREEN}配置文件已创建: $config_file${NC}"
    else
        echo -e "${YELLOW}配置文件已存在: $config_file${NC}"
    fi
}

create_wrapper() {
    local install_dir="$1"
    local bin_dir="$install_dir/bin"
    
    mkdir -p "$bin_dir"
    
    cat > "$bin_dir/hos-ls" << EOF
#!/bin/bash
source "$install_dir/venv/bin/activate"
python3 -m src.cli.main "\$@"
EOF
    
    chmod +x "$bin_dir/hos-ls"
    
    if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
        if [ -n "$ZSH_VERSION" ]; then
            echo "export PATH=\"\$PATH:$bin_dir\"" >> "$HOME/.zshrc"
        else
            echo "export PATH=\"\$PATH:$bin_dir\"" >> "$HOME/.bashrc"
        fi
        echo -e "${GREEN}已添加 $bin_dir 到 PATH${NC}"
    fi
}

show_success() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  安装完成!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${CYAN}使用方法:${NC}"
    echo "  hos-ls scan .              # 扫描当前目录"
    echo "  hos-ls scan ./src -f html  # 生成 HTML 报告"
    echo "  hos-ls rules               # 列出可用规则"
    echo "  hos-ls config              # 显示当前配置"
    echo ""
    echo -e "${YELLOW}配置文件位置: $INSTALL_DIR/config/config.yaml${NC}"
    echo ""
    echo -e "${YELLOW}请运行 'source ~/.bashrc' 或重新打开终端以使 PATH 更改生效${NC}"
}

main() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"
    
    check_python
    check_pip
    
    VENV_PATH="$INSTALL_DIR/venv"
    create_venv "$VENV_PATH"
    install_dependencies "$VENV_PATH"
    
    CONFIG_DIR="$INSTALL_DIR/config"
    create_config "$CONFIG_DIR"
    
    create_wrapper "$INSTALL_DIR"
    
    show_success
}

main "$@"

#!/bin/bash
#===============================================================================
# HOS-LS 安全检测工具 - Linux Shell脚本
# 
# 功能：与Python工具相同，检测AI工具的安全问题并生成报告
# 适用：Linux系统
# 
# 用法：
#   chmod +x hos-ls.sh
#   ./hos-ls.sh <目标路径> [选项]
#
# 选项：
#   -o, --output <format>    报告输出格式 (html/docx/md)，默认：html
#   -d, --output-dir <dir>   报告输出目录，默认：当前目录
#   -v, --verbose            显示详细输出
#   --version                显示版本信息
#   -h, --help               显示帮助信息
#===============================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 默认值
OUTPUT_FORMAT="html"
OUTPUT_DIR="reports"
VERBOSE=false

# 计数器
PASSED=0
FAILED=0
WARNINGS=0

# 风险统计
HIGH_RISK=0
MEDIUM_RISK=0
LOW_RISK=0

# 离线模式检测
OFFLINE_MODE=false

# 权限模式
ROOT_MODE=true
if [ "$EUID" -ne 0 ]; then
    ROOT_MODE=false
fi

# 检查结果数组（用于报告）
declare -a CHECK_RESULTS
CHECK_COUNT=0

# 当前章节名称
CURRENT_SECTION=""

# 加固建议数组
declare -a HARDENING_SUGGESTIONS
SUGGESTION_COUNT=0

# 系统信息
SYSTEM_HOSTNAME=""
SYSTEM_OS=""
SYSTEM_IP=""
SYSTEM_KERNEL=""
CHECK_TIME=""

# 显示帮助信息
show_help() {
    echo ""
    echo "HOS-LS 安全检测工具"
    echo ""
    echo "用法: $0 <目标路径> [选项]"
    echo ""
    echo "选项:"
    echo "  -o, --output <format>    报告输出格式 (html/docx/md)，默认：html"
    echo "  -d, --output-dir <dir>   报告输出目录，默认：reports"
    echo "  -v, --verbose            显示详细输出"
    echo "  --version                显示版本信息"
    echo "  -h, --help               显示帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 test-ai-tool -o html"
    echo "  $0 test-ai-tool -o docx"
    echo "  $0 test-ai-tool -o md"
    echo ""
}

# 显示版本信息
show_version() {
    echo "HOS-LS 安全检测工具 v1.0.0"
}

# 离线模式检测
detect_offline_mode() {
    echo -e "${CYAN}ℹ️  检测网络连接状态...${NC}"
    
    if ! curl -s --connect-timeout 2 https://api.github.com &>/dev/null; then
        OFFLINE_MODE=true
        echo -e "${YELLOW}⚠️  检测到离线环境，跳过联网检查项${NC}"
    else
        echo -e "${GREEN}✅ 网络连接正常${NC}"
    fi
}

# 权限模式检测
detect_permission_mode() {
    if [ "$ROOT_MODE" = false ]; then
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}  ⚠️  检测到非root用户运行，部分检查项将受限${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${CYAN}受限检查项：${NC}"
        echo -e "${CYAN}  • SSH暴力破解检测（无法读取系统日志）${NC}"
        echo -e "${CYAN}  • 防火墙规则详情（无法执行iptables -L）${NC}"
        echo -e "${CYAN}  • 反向Shell进程检测（无法查看进程名）${NC}"
        echo -e "${CYAN}  • SUID文件全盘扫描（仅扫描用户可访问目录）${NC}"
        echo -e "${CYAN}  • 浏览器进程沙箱状态（无法读取/proc/<pid>/status）${NC}"
        echo ""
        echo -e "${GREEN}💡 建议使用sudo运行以获得完整检查结果：${NC}"
        echo -e "${GREEN}   sudo ./ai-security-check.sh${NC}"
        echo ""
    fi
}

# 打印标题函数
print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 记录章节名称
    CURRENT_SECTION="$1"
}

# 打印信息函数
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# 检查信息函数
check_info() {
    local message="$1"
    local detail="${2:-}"
    
    echo -e "${BLUE}ℹ️  $message${NC}"
    
    if [ -n "$detail" ]; then
        echo -e "${BLUE}   详情: $detail${NC}"
    fi
}

# 添加加固建议
add_suggestion() {
    local risk_level="$1"  # HIGH/MEDIUM/LOW
    local suggestion="$2"
    local icon=""
    
    case "$risk_level" in
        HIGH)
            icon="🔴高风险"
            ((HIGH_RISK++))
            ;;
        MEDIUM)
            icon="🟡中风险"
            ((MEDIUM_RISK++))
            ;;
        LOW)
            icon="🟢低风险"
            ((LOW_RISK++))
            ;;
    esac
    
    HARDENING_SUGGESTIONS[$SUGGESTION_COUNT]="$icon | $suggestion"
    ((SUGGESTION_COUNT++))
}

# 检查通过函数
check_pass() {
    local message="$1"
    local detail="${2:-}"
    local suggestion="${3:-该项配置安全}"
    
    echo -e "${GREEN}✅ $message${NC}"
    ((PASSED++))
    
    if [ -n "$detail" ]; then
        echo -e "${BLUE}   详情: $detail${NC}"
    fi
    
    # 记录到数组
    CHECK_RESULTS[$CHECK_COUNT]="PASS|$CURRENT_SECTION|$message|$detail|$suggestion|LOW"
    ((CHECK_COUNT++))
}

# 检查失败函数
check_fail() {
    local message="$1"
    local detail="${2:-}"
    local suggestion="${3:-请执行脚本输出的加固建议进行整改}"
    local risk_level="${4:-HIGH}"
    
    echo -e "${RED}❌ $message${NC}"
    ((FAILED++))
    
    if [ -n "$detail" ]; then
        echo -e "${BLUE}   详情: $detail${NC}"
    fi
    
    if [ -n "$suggestion" ]; then
        echo -e "${YELLOW}   建议: $suggestion${NC}"
    fi
    
    # 记录到数组（包含风险等级）
    CHECK_RESULTS[$CHECK_COUNT]="FAIL|$CURRENT_SECTION|$message|$detail|$suggestion|$risk_level"
    ((CHECK_COUNT++))
    
    # 添加到加固建议列表
    add_suggestion "$risk_level" "$suggestion"
}

# 检查警告函数
check_warn() {
    local message="$1"
    local detail="${2:-}"
    local suggestion="${3:-建议优化该项配置}"
    local risk_level="${4:-MEDIUM}"
    
    echo -e "${YELLOW}⚠️  $message${NC}"
    ((WARNINGS++))
    
    if [ -n "$detail" ]; then
        echo -e "${BLUE}   详情: $detail${NC}"
    fi
    
    if [ -n "$suggestion" ]; then
        echo -e "${YELLOW}   建议: $suggestion${NC}"
    fi
    
    # 记录到数组（包含风险等级）
    CHECK_RESULTS[$CHECK_COUNT]="WARN|$CURRENT_SECTION|$message|$detail|$suggestion|$risk_level"
    ((CHECK_COUNT++))
    
    # 添加到加固建议列表
    add_suggestion "$risk_level" "$suggestion"
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -d|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --version)
                show_version
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                if [[ -z "$TARGET" ]]; then
                    TARGET="$1"
                else
                    echo -e "${RED}错误: 未知参数: $1${NC}"
                    show_help
                    exit 1
                fi
                shift
                ;;
        esac
    done
}

# 检查Python是否安装
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}错误: Python 3 未安装${NC}"
        echo -e "${YELLOW}请安装Python 3.8+后再运行此工具${NC}"
        exit 1
    fi
}

# 检查目标路径是否存在
check_target() {
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}错误: 缺少目标路径${NC}"
        show_help
        exit 1
    fi
    
    if [[ ! -e "$TARGET" ]]; then
        echo -e "${RED}错误: 目标路径不存在: $TARGET${NC}"
        exit 1
    fi
}

# 确保输出目录存在
ensure_output_dir() {
    mkdir -p "$OUTPUT_DIR" 2>/dev/null
}

# 执行基本安全检查
execute_security_check() {
    echo -e "${BLUE}开始安全扫描...${NC}"
    
    # 检测项目类型并选择规则集
    if [[ -f "rules/rule_manager.py" ]]; then
        echo -e "${CYAN}检测项目类型...${NC}"
        PROJECT_TYPE=$(python3 -c "from rules.rule_manager import RuleManager; manager = RuleManager(); print(manager.detect_project_type('$TARGET'))")
        RULE_SET=$(python3 -c "from rules.rule_manager import RuleManager; manager = RuleManager(); print(manager.get_project_rule_set('$TARGET'))")
        echo -e "${GREEN}项目类型: $PROJECT_TYPE${NC}"
        echo -e "${GREEN}使用规则集: $RULE_SET${NC}"
    else
        echo -e "${YELLOW}规则管理器未找到，使用默认规则集${NC}"
        RULE_SET="default"
    fi
    
    # 创建临时结果文件
    TEMP_RESULT=$(mktemp "${TMPDIR:-/tmp}/ai-security-check-XXXXXX.json")
    
    # 初始化结果结构
    cat > "$TEMP_RESULT" << EOF
{
    "code_security": [],
    "permission_security": [],
    "network_security": [],
    "dependency_security": [],
    "config_security": [],
    "project_type": "$PROJECT_TYPE",
    "rule_set": "$RULE_SET"
}
EOF
    
    # 扫描代码安全
    echo -e "${CYAN}扫描代码安全...${NC}"
    scan_code_security
    
    # 扫描权限安全
    echo -e "${CYAN}扫描权限安全...${NC}"
    scan_permission_security
    
    # 扫描网络安全
    echo -e "${CYAN}扫描网络安全...${NC}"
    scan_network_security
    
    # 扫描依赖安全
    echo -e "${CYAN}扫描依赖安全...${NC}"
    scan_dependency_security
    
    # 扫描配置安全
    echo -e "${CYAN}扫描配置安全...${NC}"
    scan_config_security
    
    # 扫描数据安全
    echo -e "${CYAN}扫描数据安全...${NC}"
    scan_data_security
    
    echo -e "${GREEN}扫描完成!${NC}"
    echo -e "${RED}高风险: $HIGH_RISK${NC}"
    echo -e "${YELLOW}中风险: $MEDIUM_RISK${NC}"
    echo -e "${GREEN}低风险: $LOW_RISK${NC}"
    
    # 返回临时结果文件路径
    echo "$TEMP_RESULT"
}

# 扫描代码安全
scan_code_security() {
    print_header "【一】代码安全检查"
    
    # 遍历文件
    find "$TARGET" -type f -name "*.py" -o -name "*.js" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name ".env" | while read file; do
        # 检查硬编码的敏感信息
        if grep -q -i "api[_-]?key\|api[_-]?token\|password\|passwd\|pwd\|secret\|private[_-]?key\|token\|auth[_-]?token" "$file"; then
            check_fail "发现硬编码的敏感信息" "文件: $file" "移除硬编码的敏感信息，使用环境变量或配置文件存储" "HIGH"
        fi
        
        # 检查潜在的后门代码
        if grep -q -i "exec(\|eval(\|system(\|os\.system(" "$file"; then
            check_fail "发现潜在的后门代码" "文件: $file" "审查代码，确保这些函数的使用是安全的" "HIGH"
        fi
        
        # 检查网络访问代码
        if grep -q -i "requests\.\|urllib\.\|socket\." "$file"; then
            check_warn "发现网络访问代码" "文件: $file" "确保网络访问代码有适当的错误处理和安全验证" "MEDIUM"
        fi
        
        # AI 相关代码检查
        # 检查 AI 模型加载代码
        if grep -q -i "torch\.load\|torch\.jit\.load\|tf\.keras\.models\.load_model\|onnxruntime\.InferenceSession\|transformers\.AutoModel\|transformers\.AutoTokenizer" "$file"; then
            check_warn "发现 AI 模型加载代码" "文件: $file" "确保模型加载路径安全，避免加载恶意模型" "MEDIUM"
        fi
        
        # 检查 AI 输入验证代码
        if grep -q -i "input\|prompt\|query" "$file" && ! grep -q -i "validate\|sanitize\|check" "$file"; then
            check_warn "发现 AI 输入处理代码，可能缺少输入验证" "文件: $file" "添加输入验证和 sanitization 代码" "MEDIUM"
        fi
        
        # 检查 AI 输出处理代码
        if grep -q -i "output\|response\|result" "$file" && ! grep -q -i "filter\|sanitize\|validate" "$file"; then
            check_warn "发现 AI 输出处理代码，可能缺少输出过滤" "文件: $file" "添加输出过滤和验证代码" "MEDIUM"
        fi
        
        # 检查 AI 推理代码
        if grep -q -i "model\.predict\|model\.forward\|model(" "$file"; then
            check_warn "发现 AI 推理代码" "文件: $file" "确保推理代码有适当的错误处理和安全检查" "MEDIUM"
        fi
        
        # 检查 AI 数据处理代码
        if grep -q -i "data\.load\|dataset\|dataloader" "$file"; then
            check_warn "发现 AI 数据处理代码" "文件: $file" "确保数据处理代码有适当的安全检查和验证" "MEDIUM"
        fi
        
        # Cursor/TRAE/Kiro 特有安全检查
        # 检查由这些工具生成的代码特征
        if grep -q -i "cursor\|trae\|kiro" "$file"; then
            check_info "发现 Cursor/TRAE/Kiro 生成的代码" "文件: $file"
        fi
        
        # 检查硬编码的 API 调用
        if grep -q -i "openai\|anthropic\|gemini\|cohere" "$file" && grep -q -E "['"]api[_-]?key['"]" "$file"; then
            check_fail "发现硬编码的 AI API 密钥" "文件: $file" "使用环境变量存储 API 密钥" "HIGH"
        fi
        
        # 检查不安全的 AI 提示模板
        if grep -q -i "prompt\|template" "$file" && grep -q -E "['"]system['"]|['"]user['"]|['"]assistant['"]" "$file"; then
            check_warn "发现 AI 提示模板" "文件: $file" "确保提示模板不包含敏感信息，并且经过安全审查" "MEDIUM"
        fi
    done
}

# 扫描权限安全
scan_permission_security() {
    print_header "【二】权限安全检查"
    
    # 检查运行用户
    print_info "检查运行用户..."
    if [ "$EUID" -eq 0 ]; then
        check_warn "使用root用户运行" "当前用户: root" "创建专用用户运行AI工具，遵循最小权限原则" "MEDIUM"
    else
        check_pass "使用非root用户运行" "当前用户: $(whoami)"
    fi
    
    # 检查文件执行权限
    print_info "检查文件执行权限..."
    EXECUTABLE_FILES=$(find "$TARGET" -type f -executable 2>/dev/null | wc -l)
    if [ "$EXECUTABLE_FILES" -gt 0 ]; then
        check_warn "发现可执行文件" "数量: $EXECUTABLE_FILES" "仅对必要的脚本设置执行权限" "MEDIUM"
        find "$TARGET" -type f -executable 2>/dev/null | head -5 | while read file; do
            echo "  - $file"
        done
    else
        check_pass "无可执行文件"
    fi
    
    # 检查 AI 模型文件权限
    print_info "检查 AI 模型文件权限..."
    MODEL_FILES=$(find "$TARGET" -type f -name "*.pt" -o -name "*.pth" -o -name "*.onnx" -o -name "*.h5" -o -name "*.pb" -o -name "*.tflite" 2>/dev/null)
    if [ -n "$MODEL_FILES" ]; then
        while read file; do
            # 检查权限是否过于宽松
            if [[ $(stat -c "%a" "$file" 2>/dev/null || echo "777") == *7* ]]; then
                check_fail "AI 模型文件权限过于宽松" "文件: $file" "执行 'chmod 640 $file' 限制模型文件访问" "HIGH"
            else
                check_pass "AI 模型文件权限正常" "文件: $file"
            fi
        done <<< "$MODEL_FILES"
    else
        check_pass "未发现 AI 模型文件"
    fi
    
    # 检查用户敏感目录权限
    print_info "检查用户敏感目录权限..."
    SENSITIVE_DIRS="$HOME/.ssh $HOME/.gnupg $HOME/.config"
    for dir in $SENSITIVE_DIRS; do
        if [ -d "$dir" ]; then
            PERM=$(stat -c "%a" "$dir" 2>/dev/null)
            if [ "$PERM" -gt 700 ]; then
                check_warn "用户敏感目录权限过宽" "目录: $dir, 权限: $PERM" "执行 'chmod 700 $dir' 限制目录访问" "LOW"
            else
                check_pass "用户敏感目录权限正常" "目录: $dir"
            fi
        fi
    done
    
    # 检查SSH密钥文件权限
    print_info "检查SSH密钥文件权限..."
    if [ -d "$HOME/.ssh" ]; then
        # 检查私钥文件
        PRIVATE_KEYS=$(find "$HOME/.ssh" -type f -name "id_*" ! -name "*.pub" 2>/dev/null)
        while read key; do
            PERM=$(stat -c "%a" "$key" 2>/dev/null)
            if [ "$PERM" != "600" ]; then
                check_fail "SSH私钥权限不安全" "文件: $key, 权限: $PERM" "执行 'chmod 600 $key' 限制私钥访问" "HIGH"
            else
                check_pass "SSH私钥权限安全" "文件: $key"
            fi
        done <<< "$PRIVATE_KEYS"
        
        # 检查authorized_keys文件
        if [ -f "$HOME/.ssh/authorized_keys" ]; then
            PERM=$(stat -c "%a" "$HOME/.ssh/authorized_keys" 2>/dev/null)
            if [ "$PERM" -gt 644 ]; then
                check_warn "authorized_keys权限过宽" "权限: $PERM" "执行 'chmod 644 $HOME/.ssh/authorized_keys' 限制访问" "LOW"
            else
                check_pass "authorized_keys权限正常"
            fi
        fi
    fi
    
    # 检查SUID/SGID特权文件
    print_info "检查SUID/SGID特权文件..."
    if [ "$ROOT_MODE" = true ]; then
        # 检查当前目录下的SUID文件
        SUID_FILES=$(find "$TARGET" -type f -perm -4000 2>/dev/null)
        if [ -n "$SUID_FILES" ]; then
            check_fail "发现SUID文件" "在AI工具目录中发现特权文件" "移除不必要的SUID权限: chmod -s <文件>" "HIGH"
            echo "SUID文件:"
            echo "$SUID_FILES"
        else
            check_pass "未发现SUID文件"
        fi
    else
        check_warn "SUID文件检查需要root权限" "非root用户无法进行完整检查" "使用sudo运行以获得完整检查结果" "LOW"
    fi
}

# 扫描网络安全
scan_network_security() {
    print_header "【三】网络安全检查"
    
    # 检查硬编码的IP和端口
    print_info "检查硬编码的IP和端口..."
    find "$TARGET" -type f -name "*.py" -o -name "*.js" | while read file; do
        # 检查IP地址
        if grep -q "\b\(\(25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?\)\.\)\{3\}\(25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?\)\b" "$file"; then
            check_warn "发现硬编码的IP地址" "文件: $file" "避免硬编码IP地址，使用配置文件或环境变量" "MEDIUM"
        fi
        
        # 检查端口号
        if grep -q ":\d\{1,5\}\b" "$file"; then
            check_warn "发现硬编码的端口号" "文件: $file" "避免硬编码端口号，使用配置文件或环境变量" "MEDIUM"
        fi
    done
    
    # 检查端口监听状态
    print_info "检查端口监听状态..."
    if [ "$ROOT_MODE" = true ]; then
        # 检查是否有端口暴露到公网
        PUBLIC_PORTS=$(netstat -tlnp 2>/dev/null | grep "0\.0\.0\.0:\|:::")
        if [ -n "$PUBLIC_PORTS" ]; then
            check_warn "发现端口暴露到公网" "存在公网监听的端口" "修改配置，将监听地址改为 127.0.0.1 或配置防火墙限制访问" "MEDIUM"
            echo "暴露的端口:"
            echo "$PUBLIC_PORTS" | head -5
        else
            check_pass "无端口暴露到公网" "所有端口仅本地监听"
        fi
    else
        check_warn "端口监听检查需要root权限" "非root用户无法查看端口监听状态" "使用sudo运行以获得完整检查结果" "LOW"
    fi
    
    # 检查防火墙状态
    print_info "检查防火墙状态..."
    FIREWALL_ENABLED=false
    
    # 检查 UFW
    if command -v ufw &> /dev/null; then
        UFW_STATUS=$(ufw status 2>/dev/null | head -1)
        if echo "$UFW_STATUS" | grep -q "active"; then
            check_pass "UFW防火墙已启用" "状态: $UFW_STATUS" "LOW"
            FIREWALL_ENABLED=true
        fi
    fi
    
    # 检查 Firewalld
    if [ "$FIREWALL_ENABLED" = false ]; then
        if command -v firewall-cmd &> /dev/null; then
            if firewall-cmd --state 2>/dev/null | grep -q "running"; then
                check_pass "Firewalld防火墙已启用" "状态: running" "LOW"
                FIREWALL_ENABLED=true
            fi
        fi
    fi
    
    # 检查 iptables
    if [ "$FIREWALL_ENABLED" = false ]; then
        if command -v iptables &> /dev/null; then
            if [ "$ROOT_MODE" = true ]; then
                IPTABLES_RULES=$(iptables -L -n 2>/dev/null | grep -c "DROP\|REJECT")
                if [ "$IPTABLES_RULES" -gt 0 ]; then
                    check_pass "iptables防火墙已配置" "存在 DROP/REJECT 规则" "LOW"
                    FIREWALL_ENABLED=true
                fi
            else
                check_warn "iptables检查需要root权限" "非root用户无法查看iptables规则" "使用sudo运行以获得完整检查结果" "LOW"
            fi
        fi
    fi
    
    if [ "$FIREWALL_ENABLED" = false ]; then
        check_fail "未检测到防火墙" "系统未安装或启用防火墙" "安装并启用防火墙，如 ufw、firewalld 或 iptables" "HIGH"
    fi
    
    # 检测反向Shell
    print_info "检测反向Shell..."
    if [ "$ROOT_MODE" = true ]; then
        # 检查Shell进程的外网连接
        SHELL_CONN=$(ss -antp 2>/dev/null | grep ESTAB | grep -E "bash|python|perl|ruby|php|node" | grep -v "127.0.0.1")
        if [ -n "$SHELL_CONN" ]; then
            check_fail "发现Shell进程有外网连接" "可能是反向Shell" "立即检查进程详情并终止可疑进程" "HIGH"
            echo "可疑连接:"
            echo "$SHELL_CONN"
        else
            check_pass "未检测到Shell进程的外网连接"
        fi
    else
        check_warn "反向Shell检测需要root权限" "非root用户无法查看进程详情" "使用sudo运行以获得完整检查结果" "LOW"
    fi
    
    # 检查SSH配置
    print_info "检查SSH配置..."
    if [ -f "/etc/ssh/sshd_config" ]; then
        # 检查是否允许root登录
        if grep -qE "^PermitRootLogin.*no" /etc/ssh/sshd_config 2>/dev/null; then
            check_pass "SSH禁止root登录" "配置: PermitRootLogin no" "LOW"
        elif grep -qE "^PermitRootLogin.*yes" /etc/ssh/sshd_config 2>/dev/null; then
            check_fail "SSH允许root登录" "配置: PermitRootLogin yes" "修改 /etc/ssh/sshd_config，设置 'PermitRootLogin no'" "HIGH"
        else
            check_warn "SSH root登录配置未明确限制" "未找到PermitRootLogin配置项" "在 /etc/ssh/sshd_config 中添加 'PermitRootLogin no'" "MEDIUM"
        fi
        
        # 检查是否禁用密码登录
        if grep -qE "^PasswordAuthentication.*no" /etc/ssh/sshd_config 2>/dev/null; then
            check_pass "SSH已禁用密码登录" "配置: PasswordAuthentication no" "LOW"
        else
            check_warn "SSH允许密码登录" "PasswordAuthentication 未设置为 no" "建议禁用密码登录，仅使用密钥认证" "MEDIUM"
        fi
    else
        check_warn "未找到SSH配置文件" "/etc/ssh/sshd_config 不存在" "SSH可能未安装或配置" "LOW"
    fi
}

# 扫描依赖安全
scan_dependency_security() {
    print_header "【四】依赖安全检查"
    
    # 检查依赖文件
    dependency_files=("$TARGET/requirements.txt" "$TARGET/package.json" "$TARGET/pyproject.toml")
    for dep_file in "${dependency_files[@]}"; do
        if [[ -f "$dep_file" ]]; then
            check_pass "发现依赖文件" "文件: $dep_file" "LOW"
            
            # 检查 AI 相关依赖库
            if grep -q -i "tensorflow\|keras\|pytorch\|torch\|transformers\|onnx\|onnxruntime\|scikit-learn\|numpy\|pandas" "$dep_file"; then
                check_warn "发现 AI 相关依赖库" "文件: $dep_file" "确保依赖库版本安全，定期更新" "MEDIUM"
            fi
            
            # 检查依赖库版本
            if grep -q "==" "$dep_file"; then
                check_pass "依赖库版本已固定" "文件: $dep_file" "LOW"
            else
                check_warn "依赖库版本未固定" "文件: $dep_file" "固定依赖库版本，避免自动更新引入安全问题" "MEDIUM"
            fi
        fi
    done
}

# 扫描配置安全
scan_config_security() {
    print_header "【五】配置安全检查"
    
    # 检查配置文件
    config_files=("$TARGET/config.json" "$TARGET/config.yaml" "$TARGET/config.yml" "$TARGET/.env" "$TARGET/model_config.json" "$TARGET/model_config.yaml" "$TARGET/model_config.yml")
    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            # 检查敏感配置
            if grep -q -i "api[_-]?key\|password\|secret\|token\|database[_-]?url" "$config_file"; then
                check_fail "配置文件中可能包含敏感信息" "文件: $config_file" "移除敏感信息，使用环境变量存储" "HIGH"
            else
                check_pass "配置文件未发现敏感信息" "文件: $config_file"
            fi
            
            # 检查 AI 特定配置
            if grep -q -i "model_path\|model_name\|model_dir\|api_key\|api_token\|endpoint\|url" "$config_file"; then
                check_warn "发现 AI 特定配置" "文件: $config_file" "确保配置安全，避免硬编码敏感信息" "MEDIUM"
            fi
        fi
    done
    
    # 检查 AI 相关的环境变量文件
    find "$TARGET" -name ".env*" -type f | while read env_file; do
        if grep -q -i "model\|api\|token\|key" "$env_file"; then
            check_warn "发现 AI 相关环境变量" "文件: $env_file" "确保环境变量文件权限安全，避免泄露" "MEDIUM"
        else
            check_pass "环境变量文件未发现敏感信息" "文件: $env_file"
        fi
    done
}

# 扫描数据安全
scan_data_security() {
    print_header "【六】AI特定安全检查"
    
    # 检查 AI 模型文件
    print_info "检查 AI 模型文件..."
    MODEL_FORMATS="*.pt *.pth *.onnx *.h5 *.pb *.tflite *.safetensors *.bin"
    for format in $MODEL_FORMATS; do
        MODEL_FILES=$(find "$TARGET" -type f -name "$format" 2>/dev/null)
        if [ -n "$MODEL_FILES" ]; then
            while read file; do
                # 检查文件大小
                file_size=$(stat -c "%s" "$file" 2>/dev/null || echo "0")
                if [[ $file_size -gt 104857600 ]]; then  # 100MB
                    check_warn "发现大型 AI 模型文件" "文件: $file, 大小: $((file_size / 1048576))MB" "考虑使用模型量化或分布式存储" "MEDIUM"
                else
                    check_pass "AI 模型文件大小合理" "文件: $file, 大小: $((file_size / 1048576))MB"
                fi
                
                # 检查文件权限
                if [[ $(stat -c "%a" "$file" 2>/dev/null || echo "777") == *7* ]]; then
                    check_fail "AI 模型文件权限过于宽松" "文件: $file" "执行 'chmod 640 $file' 限制模型文件访问" "HIGH"
                else
                    check_pass "AI 模型文件权限正常" "文件: $file"
                fi
                
                # 增强：检查模型文件完整性
                if [ -f "${file}.md5" ] || [ -f "${file}.sha256" ]; then
                    check_pass "发现模型文件校验和" "文件: $file" "使用校验和验证模型文件完整性" "LOW"
                else
                    check_warn "未发现模型文件校验和" "文件: $file" "添加校验和文件以验证模型完整性" "LOW"
                fi
                
                # 增强：检查模型文件来源
                if grep -q -i "model_source\|model_origin\|model_url" "$file" 2>/dev/null; then
                    check_info "发现模型文件来源信息" "文件: $file"
                else
                    check_warn "未发现模型文件来源信息" "文件: $file" "添加模型来源信息，确保模型来自可信来源" "LOW"
                fi
            done <<< "$MODEL_FILES"
        fi
    done
    
    # 检查 AI 训练数据文件
    print_info "检查 AI 训练数据文件..."
    DATA_FORMATS="*.csv *.json *.npy *.hdf5 *.txt *.parquet *.arrow"
    for format in $DATA_FORMATS; do
        DATA_FILES=$(find "$TARGET" -type f -name "$format" 2>/dev/null)
        if [ -n "$DATA_FILES" ]; then
            while read data_file; do
                # 检查文件大小
                file_size=$(stat -c "%s" "$data_file" 2>/dev/null || echo "0")
                if [[ $file_size -gt 10485760 ]]; then  # 10MB
                    check_warn "发现大型 AI 训练数据文件" "文件: $data_file, 大小: $((file_size / 1048576))MB" "考虑使用数据压缩或分布式存储" "MEDIUM"
                else
                    check_pass "AI 训练数据文件大小合理" "文件: $data_file, 大小: $((file_size / 1048576))MB"
                fi
                
                # 检查文件权限
                if [[ $(stat -c "%a" "$data_file" 2>/dev/null || echo "777") == *7* ]]; then
                    check_fail "AI 训练数据文件权限过于宽松" "文件: $data_file" "执行 'chmod 640 $data_file' 限制数据文件访问" "HIGH"
                else
                    check_pass "AI 训练数据文件权限正常" "文件: $data_file"
                fi
                
                # 检查文件内容是否包含敏感信息
                if grep -q -i "password\|secret\|token\|api[_-]?key\|email\|phone\|address\|ssn\|credit_card" "$data_file" 2>/dev/null; then
                    check_fail "AI 训练数据文件可能包含敏感信息" "文件: $data_file" "移除敏感信息或使用数据脱敏技术" "HIGH"
                else
                    check_pass "AI 训练数据文件未发现敏感信息" "文件: $data_file"
                fi
                
                # 增强：检查数据脱敏
                if grep -q -i "脱敏\|mask\|anonymize\|encrypt" "$data_file" 2>/dev/null; then
                    check_pass "发现数据脱敏处理" "文件: $data_file" "数据已进行脱敏处理，增强数据安全性" "LOW"
                else
                    check_warn "未发现数据脱敏处理" "文件: $data_file" "考虑对敏感数据进行脱敏处理" "LOW"
                fi
                
                # 增强：检查数据来源
                if grep -q -i "data_source\|data_origin\|data_url" "$data_file" 2>/dev/null; then
                    check_pass "发现数据来源信息" "文件: $data_file" "数据来源已记录，便于追溯" "LOW"
                else
                    check_warn "未发现数据来源信息" "文件: $data_file" "添加数据来源信息，确保数据来自可信来源" "LOW"
                fi
                
                # 增强：检查数据质量
                if grep -q -i "data_quality\|data_validation\|data_cleaning" "$data_file" 2>/dev/null; then
                    check_pass "发现数据质量处理" "文件: $data_file" "数据已进行质量处理，提高模型安全性" "LOW"
                else
                    check_warn "未发现数据质量处理" "文件: $data_file" "考虑对数据进行质量检查和清洗" "LOW"
                fi
            done <<< "$DATA_FILES"
        fi
    done
    
    # 检查数据目录
    print_info "检查 AI 数据目录..."
    DATA_DIRS=$(find "$TARGET" -type d -name "data" -o -name "dataset" -o -name "train" -o -name "test" -o -name "models" 2>/dev/null)
    if [ -n "$DATA_DIRS" ]; then
        while read data_dir; do
            check_warn "发现 AI 数据目录" "目录: $data_dir" "确保目录权限正确，仅授权用户访问" "MEDIUM"
        done <<< "$DATA_DIRS"
    else
        check_pass "未发现 AI 数据目录"
    fi
    
    # 检查 AI API 安全
    print_info "检查 AI API 安全..."
    API_FILES=$(find "$TARGET" -type f -name "*.py" -o -name "*.js" | xargs grep -l "api_key\|api_token\|endpoint\|url" 2>/dev/null)
    if [ -n "$API_FILES" ]; then
        while read file; do
            # 检查硬编码的API密钥
            if grep -q -i "api[_-]?key\|api[_-]?token" "$file" && grep -q -E "['"]\w+['"]" "$file"; then
                check_fail "发现硬编码的 API 密钥" "文件: $file" "使用环境变量或配置文件存储API密钥" "HIGH"
            else
                check_pass "未发现硬编码的 API 密钥" "文件: $file"
            fi
            
            # 增强：检查 API 密钥管理
            if grep -q -i "environment\|env\|config" "$file" && grep -q -i "api[_-]?key\|api[_-]?token" "$file"; then
                check_pass "发现 API 密钥管理" "文件: $file" "API 密钥使用环境变量或配置文件管理" "LOW"
            else
                check_warn "未发现 API 密钥管理" "文件: $file" "使用环境变量或配置文件管理 API 密钥" "LOW"
            fi
            
            # 增强：检查 API 调用频率限制
            if grep -q -i "rate\|limit\|throttle" "$file" && grep -q -i "api\|request" "$file"; then
                check_pass "发现 API 调用频率限制" "文件: $file" "API 调用有频率限制，防止滥用" "LOW"
            else
                check_warn "未发现 API 调用频率限制" "文件: $file" "添加 API 调用频率限制，防止 API 滥用" "LOW"
            fi
            
            # 增强：检查 API 响应验证
            if grep -q -i "validate\|verify\|check" "$file" && grep -q -i "response\|api" "$file"; then
                check_pass "发现 API 响应验证" "文件: $file" "API 响应有验证，提高安全性" "LOW"
            else
                check_warn "未发现 API 响应验证" "文件: $file" "添加 API 响应验证，防止恶意响应" "LOW"
            fi
            
            # 增强：检查 API 错误处理
            if grep -q -i "try\|except\|error\|exception" "$file" && grep -q -i "api\|request" "$file"; then
                check_pass "发现 API 错误处理" "文件: $file" "API 调用有错误处理，提高稳定性" "LOW"
            else
                check_warn "未发现 API 错误处理" "文件: $file" "添加 API 错误处理，提高系统稳定性" "LOW"
            fi
        done <<< "$API_FILES"
    else
        check_pass "未发现 AI API 相关代码"
    fi
    
    # 检查 AI 技能包安全
    print_info "检查 AI 技能包安全..."
    SKILL_FILES=$(find "$TARGET" -type f -name "*.py" -o -name "*.js" -o -name "*.json" | xargs grep -l "skill\|plugin\|extension" 2>/dev/null)
    if [ -n "$SKILL_FILES" ]; then
        while read file; do
            # 检查技能包是否来自可信来源
            if grep -q -i "github\|official\|trusted" "$file"; then
                check_pass "技能包来源可信" "文件: $file"
            else
                check_warn "技能包来源未验证" "文件: $file" "仅使用来自可信来源的技能包" "MEDIUM"
            fi
            
            # 检查技能包是否包含恶意代码
            if grep -q -i "exec(\|eval(\|system(\|os\.system(" "$file";
            then
                check_fail "技能包可能包含恶意代码" "文件: $file" "审查技能包代码，确保不包含恶意代码" "HIGH"
            else
                check_pass "技能包未发现恶意代码" "文件: $file"
            fi
        done <<< "$SKILL_FILES"
    else
        check_pass "未发现 AI 技能包"
    fi
    
    # Cursor/TRAE/Kiro 特有安全检查
    print_info "检查 Cursor/TRAE/Kiro 特有安全问题..."
    
    # 检查由这些工具生成的配置文件
    CONFIG_FILES=$(find "$TARGET" -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name ".env" | xargs grep -l -i "cursor\|trae\|kiro" 2>/dev/null)
    if [ -n "$CONFIG_FILES" ]; then
        while read config_file; do
            check_info "发现 Cursor/TRAE/Kiro 配置文件" "文件: $config_file"
            
            # 检查配置文件中的敏感信息
            if grep -q -i "api[_-]?key\|password\|secret\|token" "$config_file"; then
                check_fail "Cursor/TRAE/Kiro 配置文件中可能包含敏感信息" "文件: $config_file" "移除敏感信息，使用环境变量存储" "HIGH"
            fi
        done <<< "$CONFIG_FILES"
    fi
    
    # 检查 AI 提示工程文件
    PROMPT_FILES=$(find "$TARGET" -name "*.py" -o -name "*.json" -o -name "*.txt" | xargs grep -l -i "prompt\|template\|system\|user\|assistant" 2>/dev/null)
    if [ -n "$PROMPT_FILES" ]; then
        while read prompt_file; do
            check_info "发现 AI 提示工程文件" "文件: $prompt_file"
            
            # 检查提示文件中的敏感信息
            if grep -q -i "password\|secret\|token\|api[_-]?key" "$prompt_file"; then
                check_fail "AI 提示文件中可能包含敏感信息" "文件: $prompt_file" "移除敏感信息，确保提示安全" "HIGH"
            fi
        done <<< "$PROMPT_FILES"
    fi
    
    # OpenClaw 特化安全检查
    scan_openclaw_security
}

# OpenClaw 特化安全检查
scan_openclaw_security() {
    print_header "【七】OpenClaw特化安全检查"
    
    # 检查 OpenClaw 是否安装
    print_info "检查 OpenClaw 安装状态..."
    
    OPENCLAW_INSTALLED=false
    if command -v openclaw &> /dev/null; then
        OPENCLAW_INSTALLED=true
        CURRENT_VER=$(openclaw --version 2>/dev/null | grep -oP 'v?\d{4}\.\d+\.\d+(?:-\d+)?' | head -1 || echo "未知")
        CURRENT_VER=${CURRENT_VER#v}
        print_info "当前 OpenClaw 版本: $CURRENT_VER"
        
        # 检查版本是否最新（离线模式跳过）
        if [ "$OFFLINE_MODE" = false ]; then
            print_info "检查官方最新版本..."
            LATEST_VER=$(curl -s --connect-timeout 5 --max-time 10 \
                https://api.github.com/repos/openclaw/openclaw/releases/latest 2>/dev/null \
                | grep '"tag_name"' | sed -E 's/.*"v?([0-9.]+(-[0-9]+)?)"$/\1/' || echo "无法获取")
            
            if [ "$LATEST_VER" != "无法获取" ] && [ "$CURRENT_VER" != "未知" ]; then
                # 版本比较
                if [ "$(echo "$CURRENT_VER $LATEST_VER" | awk '{if ($1 < $2) print 1; else print 0}')" -eq 1 ]; then
                    check_fail "OpenClaw 版本过旧" "当前版本: $CURRENT_VER, 最新版本: $LATEST_VER" "立即执行 'openclaw update' 升级到最新版本" "HIGH"
                else
                    check_pass "OpenClaw 版本为最新" "版本: $CURRENT_VER"
                fi
            else
                check_warn "无法验证 OpenClaw 版本" "网络或 API 不可用" "手动访问 https://github.com/openclaw/openclaw/releases 检查版本" "LOW"
            fi
        else
            check_warn "离线模式，跳过版本检查" "无法连接到 GitHub API" "手动检查版本: openclaw --version" "LOW"
        fi
    else
        check_warn "未检测到 OpenClaw 安装" "openclaw 命令未找到" "如需安装 OpenClaw，请访问: https://openclaw.ai" "LOW"
    fi
    
    # 检查安装来源
    if [ "$OPENCLAW_INSTALLED" = true ]; then
        print_info "验证 OpenClaw 安装来源..."
        
        if [ -f "$HOME/.openclaw/config.json" ]; then
            INSTALL_SOURCE=$(grep -oP '"source"\s*:\s*"\K[^"]+' "$HOME/.openclaw/config.json" 2>/dev/null || echo "unknown")
            
            case "$INSTALL_SOURCE" in
                "official"|"github")
                    check_pass "安装来源：官方渠道 ($INSTALL_SOURCE)" "从官方渠道安装，可信度高" "保持使用官方渠道获取更新" "LOW"
                    ;;
                "unknown"|"")
                    check_warn "安装来源未标记" "无法确认安装来源是否可信" "建议从官方渠道重新安装：https://openclaw.ai" "LOW"
                    ;;
                *)
                    check_warn "安装来源：$INSTALL_SOURCE（非官方）" "非官方安装来源，可能存在安全风险" "建议从官方渠道安装：https://openclaw.ai 或 https://github.com/openclaw/openclaw" "MEDIUM"
                    ;;
            esac
        fi
        
        # 检查 GPG 签名
        if [ -f "$HOME/.openclaw/openclaw.sig" ] && [ -f "$HOME/.openclaw/openclaw" ]; then
            if command -v gpg &> /dev/null; then
                if gpg --verify "$HOME/.openclaw/openclaw.sig" "$HOME/.openclaw/openclaw" 2>/dev/null; then
                    check_pass "二进制 GPG 签名验证通过" "文件签名有效，未被篡改" "保持文件完整性验证机制" "LOW"
                else
                    check_fail "二进制 GPG 签名验证失败！" "二进制文件可能被篡改" "立即停止使用，从官方渠道重新下载安装：https://openclaw.ai" "HIGH"
                fi
            fi
        fi
    fi
    
    # 检查 OpenClaw 端口安全
    print_info "检查 OpenClaw 端口安全..."
    OPENCLAW_PORTS="18789 18790 18791 18792"
    PUBLIC_EXPOSED=0
    
    for port in $OPENCLAW_PORTS; do
        if netstat -tlnp 2>/dev/null | grep -q "0\.0\.0\.0:$port\|:::$port"; then
            check_fail "OpenClaw 端口 $port 暴露到公网" "端口监听在所有网络接口" "修改 ~/.openclaw/config.json 中的 'host' 配置，将 '0.0.0.0' 改为 '127.0.0.1'，或在防火墙中限制访问" "HIGH"
            ((PUBLIC_EXPOSED++))
        elif netstat -tlnp 2>/dev/null | grep -q "127\.0\.0\.1:$port"; then
            check_pass "OpenClaw 端口 $port 仅本地监听" "端口安全配置正确"
        else
            print_info "OpenClaw 端口 $port 未监听"
        fi
    done
    
    if [ $PUBLIC_EXPOSED -eq 0 ]; then
        check_pass "OpenClaw 无端口暴露到公网" "所有端口配置安全"
    fi
    
    # 检查 OpenClaw 技能包安全
    print_info "检查 OpenClaw 技能包安全..."
    SKILL_DIRS=$(find "$TARGET" -type d -name "skills" -o -name "skill" 2>/dev/null)
    if [ -n "$SKILL_DIRS" ]; then
        while read skill_dir; do
            check_info "发现 OpenClaw 技能包目录" "目录: $skill_dir"
            
            # 检查技能包文件
            SKILL_FILES=$(find "$skill_dir" -type f -name "*.py" -o -name "*.js" -o -name "*.json" 2>/dev/null)
            if [ -n "$SKILL_FILES" ]; then
                while read skill_file; do
                    # 检查技能包是否包含恶意代码
                    if grep -q -i "exec(\|eval(\|system(\|os\.system(" "$skill_file";
                    then
                        check_fail "OpenClaw 技能包可能包含恶意代码" "文件: $skill_file" "审查技能包代码，确保不包含恶意代码" "HIGH"
                    else
                        check_pass "OpenClaw 技能包未发现恶意代码" "文件: $skill_file"
                    fi
                    
                    # 检查技能包配置
                    if [ "$(basename "$skill_file")" = "config.json" ]; then
                        if grep -q -i "api[_-]?key\|password\|secret\|token" "$skill_file"; then
                            check_fail "OpenClaw 技能包配置文件中可能包含敏感信息" "文件: $skill_file" "移除敏感信息，使用环境变量存储" "HIGH"
                        else
                            check_pass "OpenClaw 技能包配置文件安全" "文件: $skill_file"
                        fi
                    fi
                done <<< "$SKILL_FILES"
            fi
        done <<< "$SKILL_DIRS"
    else
        check_pass "未发现 OpenClaw 技能包目录"
    fi
    
    # 检查 OpenClaw 配置文件
    print_info "检查 OpenClaw 配置文件安全..."
    CONFIG_FILES=$(find "$TARGET" -name "config.json" | xargs grep -l "openclaw" 2>/dev/null)
    if [ -n "$CONFIG_FILES" ]; then
        while read config_file; do
            check_info "发现 OpenClaw 配置文件" "文件: $config_file"
            
            # 检查配置文件中的敏感信息
            if grep -q -i "api[_-]?key\|password\|secret\|token" "$config_file"; then
                check_fail "OpenClaw 配置文件中可能包含敏感信息" "文件: $config_file" "移除敏感信息，使用环境变量存储" "HIGH"
            else
                check_pass "OpenClaw 配置文件安全" "文件: $config_file"
            fi
            
            # 检查自动更新配置
            if grep -q '"autoUpdate".*:.*true' "$config_file" 2>/dev/null; then
                check_pass "OpenClaw 自动更新已启用" "配置安全，确保及时获取安全更新"
            else
                check_warn "OpenClaw 自动更新未启用" "可能错过重要安全更新" "在 config.json 中设置 'autoUpdate: true'" "LOW"
            fi
        done <<< "$CONFIG_FILES"
    fi
}

# 调用Python执行检测
execute_scan() {
    echo -e "${BLUE}开始检测: $TARGET${NC}"
    echo -e "${BLUE}输出格式: $OUTPUT_FORMAT${NC}"
    echo -e "${BLUE}输出目录: $OUTPUT_DIR${NC}"
    
    # 执行安全检查
    TEMP_RESULT=$(execute_security_check)
    
    # 检查是否存在Python脚本
    if [[ -f "src/main.py" ]]; then
        # 直接运行Python脚本，传递扫描结果
        python3 src/main.py "$TARGET" -o "$OUTPUT_FORMAT" -d "$OUTPUT_DIR" --scan-result "$TEMP_RESULT"
    elif [[ -f "ai_tool_security_check/src/main.py" ]]; then
        # 从安装目录运行
        python3 ai_tool_security_check/src/main.py "$TARGET" -o "$OUTPUT_FORMAT" -d "$OUTPUT_DIR" --scan-result "$TEMP_RESULT"
    else
        # 尝试通过pip安装的包运行
        if command -v hos-ls &> /dev/null; then
            hos-ls "$TARGET" -o "$OUTPUT_FORMAT" -d "$OUTPUT_DIR" --scan-result "$TEMP_RESULT"
        else
            echo -e "${RED}错误: 找不到Python脚本${NC}"
            echo -e "${YELLOW}请确保Python脚本在正确的位置${NC}"
            # 清理临时文件
            rm -f "$TEMP_RESULT"
            exit 1
        fi
    fi
    
    # 清理临时文件
    rm -f "$TEMP_RESULT"
}

# 生成工具特定的安全提示词
generate_tool_prompts() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  生成工具特定安全提示词${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 检查规则管理器是否存在
    if [[ -f "rules/rule_manager.py" ]]; then
        # 生成Cursor格式的安全提示词
        echo -e "${GREEN}🔧 Cursor 安全提示词:${NC}"
        python3 rules/rule_manager.py | grep -A 20 "=== Cursor格式规则 ==="
        echo ""
        
        # 生成Trae格式的安全提示词
        echo -e "${GREEN}🔧 Trae 安全提示词:${NC}"
        python3 rules/rule_manager.py | grep -A 20 "=== Trae格式规则 ==="
        echo ""
        
        # 生成Kiro格式的安全提示词
        echo -e "${GREEN}🔧 Kiro 安全提示词:${NC}"
        python3 rules/rule_manager.py | grep -A 20 "=== Kiro格式规则 ===" || echo "Kiro格式规则未生成"
        echo ""
    else
        echo -e "${YELLOW}⚠️  规则管理器未找到，跳过工具特定提示词生成${NC}"
    fi
}

# 主函数
main() {
    # 解析命令行参数
    parse_args "$@"
    
    # 检查Python是否安装
    check_python
    
    # 检查目标路径
    check_target
    
    # 确保输出目录存在
    ensure_output_dir
    
    # 显示标题
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       HOS-LS 安全检测工具 v1.0                              ║"
    echo "║          基于工信部'六要六不要'安全建议                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "检查时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "目标路径: $TARGET"
    echo "操作系统: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo '未知')"
    
    # 保存系统信息
    SYSTEM_HOSTNAME=$(hostname 2>/dev/null || echo "未知")
    SYSTEM_OS=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo "未知")
    SYSTEM_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "未知")
    SYSTEM_KERNEL=$(uname -r 2>/dev/null || echo "未知")
    CHECK_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 检测离线模式
    detect_offline_mode
    
    # 检测权限模式
    detect_permission_mode
    
    # 执行扫描
    execute_scan
    
    # 生成工具特定的安全提示词
    generate_tool_prompts
    
    # 显示总结
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  检测总结${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${GREEN}✅ 通过: $PASSED${NC}"
    echo -e "${RED}❌ 失败: $FAILED${NC}"
    echo -e "${YELLOW}⚠️  警告: $WARNINGS${NC}"
    echo ""
    echo -e "${RED}高风险: $HIGH_RISK${NC}"
    echo -e "${YELLOW}中风险: $MEDIUM_RISK${NC}"
    echo -e "${GREEN}低风险: $LOW_RISK${NC}"
    echo ""
    
    # 计算总体风险等级
    if [ "$HIGH_RISK" -gt 0 ]; then
        echo -e "${RED}总体风险等级: 高风险${NC}"
        echo -e "${YELLOW}建议: 立即处理高风险问题，确保系统安全${NC}"
    elif [ "$MEDIUM_RISK" -gt 3 ]; then
        echo -e "${YELLOW}总体风险等级: 中风险${NC}"
        echo -e "${YELLOW}建议: 尽快处理中风险问题，提高系统安全性${NC}"
    else
        echo -e "${GREEN}总体风险等级: 低风险${NC}"
        echo -e "${GREEN}建议: 定期进行安全检查，保持系统安全状态${NC}"
    fi
    echo ""
    
    # 显示加固建议
    if [ "$SUGGESTION_COUNT" -gt 0 ]; then
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BLUE}  加固建议${NC}"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        for ((i=0; i<SUGGESTION_COUNT; i++)); do
            echo -e "${YELLOW}${HARDENING_SUGGESTIONS[$i]}${NC}"
        done
        echo ""
    fi
    
    # 显示报告位置
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  报告信息${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${GREEN}报告输出目录: $OUTPUT_DIR${NC}"
    echo -e "${GREEN}报告格式: $OUTPUT_FORMAT${NC}"
    echo -e "${GREEN}检查时间: $CHECK_TIME${NC}"
    echo -e "${GREEN}目标路径: $TARGET${NC}"
    echo ""
    echo -e "${BLUE}💡 提示: 详细报告已生成，请查看 $OUTPUT_DIR 目录下的报告文件${NC}"
    echo ""
}

# 运行主函数
main "$@"

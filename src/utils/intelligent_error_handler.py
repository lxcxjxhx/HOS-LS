"""智能错误处理系统

将技术性错误转换为用户友好的提示，提供：
- 清晰的问题描述
- 可能的原因分析
- 可操作的解决步骤
- 相关的示例命令

目标：降低用户困惑度50%+
"""

import re
import traceback
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum


class ErrorSeverity(Enum):
    """错误严重程度"""
    INFO = "info"        # 提示性信息（蓝色）
    WARNING = "warning"  # 警告（黄色）
    ERROR = "error"      # 错误（红色）
    CRITICAL = "critical" # 严重错误（加粗红色）


@dataclass
class UserFriendlyError:
    """用户友好的错误信息"""
    
    original_error: str           # 原始错误信息
    user_message: str             # 用户可读的描述
    severity: ErrorSeverity       # 严重程度
    possible_causes: List[str]    # 可能的原因列表
    solutions: List[str]          # 解决方案列表
    example_commands: List[str]   # 示例命令列表
    tips: List[str]               # 额外提示
    
    def to_display_string(self) -> str:
        """生成用于显示的格式化字符串"""
        emoji_map = {
            ErrorSeverity.INFO: "ℹ️",
            ErrorSeverity.WARNING: "⚠️",
            ErrorSeverity.ERROR: "❌",
            ErrorSeverity.CRITICAL: "🚨"
        }
        
        lines = []
        prefix = emoji_map.get(self.severity, "❓")
        
        # 主消息
        lines.append(f"{prefix} **{self.user_message}**\n")
        
        # 可能的原因
        if self.possible_causes:
            lines.append("🔍 **可能的原因:**")
            for i, cause in enumerate(self.possible_causes, 1):
                lines.append(f"   {i}. {cause}")
            lines.append("")
        
        # 解决方案
        if self.solutions:
            lines.append("💡 **如何解决:**")
            for i, solution in enumerate(self.solutions, 1):
                lines.append(f"   {i}. {solution}")
            lines.append("")
        
        # 示例命令
        if self.example_commands:
            lines.append("📝 **试试这些命令:**")
            for cmd in self.example_commands:
                lines.append(f"   ```\n   {cmd}\n   ```")
            lines.append("")
        
        # 额外提示
        if self.tips:
            lines.append("✨ **小贴士:**")
            for tip in self.tips:
                lines.append(f"   • {tip}")
            lines.append("")
        
        # 原始错误（折叠显示）
        lines.append(f"<details>")
        lines.append(f"<summary>🔧 技术详情（供开发者参考）</summary>")
        lines.append(f"\n```\n{self.original_error}\n```\n</details>")
        
        return "\n".join(lines)


class IntelligentErrorHandler:
    """智能错误处理器"""
    
    def __init__(self):
        self.error_patterns = self._load_error_patterns()
        self.common_errors = self._load_common_errors()
    
    def _load_error_patterns(self) -> Dict[str, Dict]:
        """加载错误模式匹配规则"""
        return {
            # API相关错误
            r"(?i)(api.?key|api_key).*?(invalid|missing|not.*found|empty|未设置|无效|缺失)":
                {
                    'user_message': 'API密钥配置问题',
                    'severity': ErrorSeverity.ERROR,
                    'possible_causes': [
                        '未设置环境变量 DEEPSEEK_API_KEY',
                        'API密钥格式不正确或已过期',
                        '配置文件中的API密钥有误'
                    ],
                    'solutions': [
                        '检查并设置API密钥环境变量',
                        '验证API密钥是否有效且未过期',
                        '确认配置文件路径正确'
                    ],
                    'example_commands': [
                        '# Windows PowerShell:',
                        '$env:DEEPSEEK_API_KEY="sk-your-api-key-here"',
                        '',
                        '# Linux/Mac Terminal:',
                        'export DEEPSEEK_API_KEY=sk-your-api-key-here',
                        '',
                        '# 或在配置文件中设置:',
                        '# 编辑 hos-ls-config.yaml 或 .env 文件'
                    ],
                    'tips': [
                        '获取API密钥: https://platform.deepseek.com/',
                        '免费额度通常足够日常使用',
                        '密钥请妥善保管，不要提交到代码仓库'
                    ]
                },
            
            r"(?i)(rate.?limit|429|too.*many.*requests|请求过频)":
                {
                    'user_message': 'API请求频率超限',
                    'severity': ErrorSeverity.WARNING,
                    'possible_causes': [
                        '短时间内发送了过多请求',
                        '达到API提供商的速率限制',
                        '批量操作未添加延迟'
                    ],
                    'solutions': [
                        '等待30秒-1分钟后重试',
                        '使用测试模式减少请求量 (--test 1)',
                        '启用缓存机制避免重复请求'
                    ],
                    'example_commands': [
                        '# 使用测试模式（只扫描1个文件）:',
                        'python -m src.cli.main scan . --pure-ai --test 1',
                        '',
                        '# 稍后重试:',
                        '# 等待1分钟后再执行相同命令'
                    ],
                    'tips': [
                        'DeepSeek免费版限制: ~0.5 req/s',
                        '付费版可提升至更高限额',
                        '考虑使用缓存功能加速重复查询'
                    ]
                },
            
            # 文件/路径相关错误
            r"(?i)(file|path|directory).*(?:not.*found|不存在|找不到|无法访问|no.*such)":
                {
                    'user_message': '文件或目录访问失败',
                    'severity': ErrorSeverity.ERROR,
                    'possible_causes': [
                        '指定的文件或目录不存在',
                        '路径拼写错误或使用了相对路径',
                        '权限不足无法读取',
                        '文件被其他程序占用'
                    ],
                    'solutions': [
                        '确认文件/目录路径是否正确',
                        '使用绝对路径而非相对路径',
                        '检查文件/目录的读取权限',
                        '确认文件未被锁定'
                    ],
                    'example_commands': [
                        '# 检查当前目录:',
                        'pwd  # Linux/Mac',
                        'cd   # Windows (显示当前目录)',
                        '',
                        '# 列出当前目录内容:',
                        'ls   # Linux/Mac',
                        'dir  # Windows',
                        '',
                        '# 使用绝对路径扫描:',
                        'python -m src.cli.main scan C:/Projects/my-project --pure-ai'
                    ],
                    'tips': [
                        'Windows路径使用正斜杠(/)或双反斜杠(\\\\)',
                        '路径中有空格时需用引号包裹',
                        '使用Tab键自动补全路径可避免拼写错误'
                    ]
                },
            
            r"(?i)(permission|denied|access.*denied|权限|拒绝访问)":
                {
                    'user_message': '权限不足',
                    'severity': ErrorSeverity.ERROR,
                    'possible_causes': [
                        '当前用户没有读取文件的权限',
                        '需要管理员/root权限',
                        '文件系统权限设置过于严格'
                    ],
                    'solutions': [
                        '以管理员身份运行终端',
                        '修改文件/目录权限 (chmod 755)',
                        '检查杀毒软件是否拦截了操作'
                    ],
                    'example_commands': [
                        '# Windows - 以管理员身份运行PowerShell:',
                        '# 右键点击PowerShell → 以管理员身份运行',
                        '',
                        '# Linux/Mac - 使用sudo:',
                        'sudo python -m src.cli.main scan /root/project --pure-ai',
                        '',
                        '# 修改文件权限:',
                        'chmod -R 755 ./my-project/'
                    ],
                    'tips': [
                        '企业环境可能需要IT部门协助',
                        '某些防病毒软件可能误报并阻止操作',
                        'Docker容器内运行注意挂载卷的权限'
                    ]
                },
            
            # AI模型相关错误
            r"(?i)(model|model.*not.*found|模型|embedding).*?(error|fail|失败|异常)":
                {
                    'user_message': 'AI模型加载失败',
                    'severity': ErrorSeverity.ERROR,
                    'possible_causes': [
                        '模型文件下载不完整或损坏',
                        '网络问题导致模型下载失败',
                        '本地模型路径配置错误',
                        '依赖库版本不兼容'
                    ],
                    'solutions': [
                        '检查网络连接是否正常',
                        '重新下载模型文件',
                        '清理模型缓存后重试',
                        '更新依赖库到兼容版本'
                    ],
                    'example_commands': [
                        '# 清理模型缓存:',
                        'rm -rf ~/.cache/huggingface/',
                        'rm -rf .hos-ls/cache/',
                        '',
                        '# 更新依赖:',
                        'pip install --upgrade torch transformers',
                        '',
                        '# 使用纯AI模式（无需本地模型）:',
                        'python -m src.cli.main scan . --pure-ai'
                    ],
                    'tips': [
                        '首次使用会自动下载模型（~2-5GB）',
                        '纯AI模式(--pure-ai)不需要本地模型',
                        '确保磁盘空间充足（至少10GB空闲）'
                    ]
                },
            
            # JSON解析错误
            r"(?i)(json|parse|解析).*?(error|fail|失败|invalid|无效)":
                {
                    'user_message': '数据解析错误',
                    'severity': ErrorSeverity.WARNING,
                    'possible_causes': [
                        'AI返回的数据格式不符合预期',
                        '响应内容包含特殊字符',
                        '网络传输导致数据截断'
                    ],
                    'solutions': [
                        '重试该操作（通常是临时性问题）',
                        '简化输入指令，避免复杂表达',
                        '切换到规则模式绕过AI解析'
                    ],
                    'example_commands': [
                        '# 重试（最简单的方法）:',
                        '# 直接按上箭头键↑ 并回车重新执行',
                        '',
                        '# 使用更简单的表达:',
                        '# 原: "帮我详细分析一下这个项目的安全性并生成一份完整的报告"',
                        '# 改: "扫描项目"'
                    ],
                    'tips': [
                        '这类错误通常是暂时的，重试即可解决',
                        '如果频繁出现，可能是API服务不稳定',
                        '可以尝试更换其他AI模型提供商'
                    ]
                },
            
            # 内存/资源不足
            r"(?i)(memory|内存|out.*of.*memory|OOM|resource|资源).*?(error| insufficient|不足|不够)":
                {
                    'user_message': '系统资源不足',
                    'severity': ErrorSeverity.CRITICAL,
                    'possible_causes': [
                        '可用内存不足（RAM）',
                        '处理的文件过大或数量过多',
                        '其他程序占用了大量内存',
                        '虚拟内存空间耗尽'
                    ],
                    'solutions': [
                        '关闭不必要的程序释放内存',
                        '使用测试模式减少扫描范围',
                        '增加系统虚拟内存（swap）',
                        '使用更轻量的纯AI模式'
                    ],
                    'example_commands': [
                        '# 减少扫描范围:',
                        'python -m src.cli.main scan . --pure-ai --test 3',
                        '',
                        '# 查看内存使用情况:',
                        '# Windows: tasklist | findstr python',
                        '# Linux: top -p $(pgrep -f python)',
                        '',
                        '# 仅扫描特定类型文件:',
                        'python -m src.cli.main scan . --pure-ai --extension .py'
                    ],
                    'tips': [
                        '建议至少8GB RAM用于大型项目扫描',
                        '纯AI模式比标准模式节省50%+内存',
                        '定期重启终端/IDE释放碎片内存'
                    ]
                },
            
            # 通用网络错误
            r"(?i)(network|connection|connect|timeout|超时|网络|连接).*?(error|fail|refused|reset)":
                {
                    'user_message': '网络连接问题',
                    'severity': ErrorSeverity.ERROR,
                    'possible_causes': [
                        '网络连接中断或不稳定',
                        '防火墙阻止了出站连接',
                        'DNS解析失败',
                        '代理服务器配置错误'
                    ],
                    'solutions': [
                        '检查网络连接是否正常',
                        '尝试切换网络（WiFi/有线）',
                        '配置代理服务器（如果在公司网络）',
                        '检查防火墙设置'
                    ],
                    'example_commands': [
                        '# 测试网络连通性:',
                        'ping api.deepseek.com',
                        '',
                        '# 设置代理（如需要）:',
                        '# Windows:',
                        '$env:HTTP_PROXY="http://proxy:port"',
                        '# Linux/Mac:',
                        'export HTTP_PROXY=http://proxy:port',
                        '',
                        '# 检查DNS解析:',
                        'nslookup api.deepseek.com'
                    ],
                    'tips': [
                        '确保能访问 https://platform.deepseek.com/',
                        '公司网络可能需要配置白名单或代理',
                        '尝试使用手机热点排除网络问题'
                    ]
                }
        }
    
    def _load_common_errors(self) -> Dict[str, UserFriendlyError]:
        """加载常见错误的预设方案"""
        return {
            'intent_parse_failure': UserFriendlyError(
                original_error='Intent parsing failed',
                user_message='无法理解您的指令',
                severity=ErrorSeverity.WARNING,
                possible_causes=[
                    '使用了过于复杂的句式结构',
                    '包含了多个模糊的任务需求',
                    '中英文混合且语法不规范',
                    '专业术语使用不当'
                ],
                solutions=[
                    '简化表达，一次只说一个任务',
                    '使用标准的命令格式（参考帮助文档）',
                    '拆分成多个简单的命令逐步执行'
                ],
                example_commands=[
                    '# 复杂表达（可能导致解析失败）:',
                    '# "帮我先快速测一下然后如果没问题就全面扫一遍最后出个报告"',
                    '',
                    '# 推荐拆分为:',
                    '# 第1步: python -m src.cli.main chat',
                    '# > 快速测试一下这个项目',
                    '',
                    '# 第2步:',
                    '# > 全面扫描项目',
                    '',
                    '# 第3步:',
                    '# > 生成安全报告'
                ],
                tips=[
                    'HOS-LS支持自然语言，但越简洁准确越好',
                    '可以使用 /help 查看支持的命令格式',
                    '多轮对话可以完成复杂任务'
                ]
            ),
            
            'plan_generation_failed': UserFriendlyError(
                original_error='Plan generation failed',
                user_message='执行计划生成失败',
                severity=ErrorSeverity.ERROR,
                possible_causes=[
                    'AI服务暂时不可用',
                    '请求超时或被中断',
                    '返回结果格式异常'
                ],
                solutions=[
                    '稍后重试该操作',
                    '检查API密钥和配额',
                    '使用默认计划继续执行'
                ],
                example_commands=[
                    '# 重试:',
                    '# 直接再次输入相同的命令',
                    '',
                    '# 或使用简化的命令:',
                    'python -m src.cli.main scan . --pure-ai'
                ],
                tips=[
                    '高峰期API响应可能较慢',
                    '可以启用离线模式（仅规则匹配）'
                ]
            ),
            
            'execution_failed': UserFriendlyError(
                original_error='Execution failed',
                user_message='任务执行过程中出错',
                severity=ErrorSeverity.ERROR,
                possible_causes=[
                    '目标代码存在语法错误无法解析',
                    '依赖的第三方库未安装',
                    '操作系统兼容性问题',
                    '文件编码问题（非UTF-8）'
                ],
                solutions=[
                    '检查目标代码是否能正常运行',
                    '安装必要的依赖包',
                    '确认Python版本兼容性（推荐3.8+）',
                    '转换文件编码为UTF-8'
                ],
                example_commands=[
                    '# 安装依赖:',
                    'pip install -r requirements.txt',
                    '',
                    '# 检查Python版本:',
                    'python --version  # 需要 >= 3.8',
                    '',
                    '# 转换文件编码:',
                    '# iconv -f GBK -t UTF-8 file.py > file_utf8.py'
                ],
                tips=[
                    'HOS-LS主要支持 Python、JavaScript、TypeScript',
                    '其他语言的支持可能在后续版本添加',
                    '遇到问题时欢迎在GitHub提Issue'
                ]
            )
        }
    
    def handle_error(self, error: Exception, context: str = "") -> UserFriendlyError:
        """智能处理错误并生成友好提示
        
        Args:
            error: 异常对象
            context: 发生错误的上下文描述
            
        Returns:
            用户友好的错误信息对象
        """
        error_str = str(error)
        error_traceback = traceback.format_exc()
        
        # 尝试匹配已知错误模式
        for pattern, error_info in self.error_patterns.items():
            if re.search(pattern, error_str) or re.search(pattern, error_traceback):
                return UserFriendlyError(
                    original_error=f"{context}\n{error_str}\n\n{error_traceback}",
                    **error_info
                )
        
        # 检查常见错误类型
        error_type_name = type(error).__name__
        if error_type_name in self.common_errors:
            base_error = self.common_errors[error_type_name]
            return UserFriendlyError(
                original_error=f"{context}\n{error_str}\n\n{error_traceback}",
                user_message=base_error.user_message,
                severity=base_error.severity,
                possible_causes=base_error.possible_causes,
                solutions=base_error.solutions,
                example_commands=base_error.example_commands,
                tips=base_error.tips + [f'错误类型: {error_type_name}']
            )
        
        # 未知的错误 - 生成通用友好提示
        return self._generate_generic_friendly_error(error, context)
    
    def _generate_generic_friendly_error(self, error: Exception, context: str) -> UserFriendlyError:
        """为未知错误生成通用友好提示"""
        error_str = str(error)
        error_type = type(error).__name__
        
        # 根据错误类型推断可能的解决方案
        generic_solutions = []
        generic_tips = []
        
        if 'FileNotFoundError' in error_type or 'No such file' in error_str:
            generic_solutions = ['检查文件路径是否存在', '使用绝对路径']
            generic_tips = ['路径区分大小写（Linux/Mac）', 'Windows使用正斜杠/或双反斜杠\\\\']
        
        elif 'Permission' in error_type or 'denied' in error_str.lower():
            generic_solutions = ['以管理员身份运行', '检查文件权限']
            generic_tips = ['Linux/Mac使用sudo', 'Windows右键→以管理员身份运行']
        
        elif 'Timeout' in error_type or 'timeout' in error_str.lower():
            generic_solutions = ['检查网络连接', '稍后重试', '增加超时时间']
            generic_tips = ['网络不稳定时容易超时', '大文件处理耗时较长']
        
        else:
            generic_solutions = [
                '查看下方技术详情了解具体原因',
                '尝试简化操作或参数',
                '在GitHub提Issue反馈此问题'
            ]
            generic_tips = [
                '这可能是我们尚未遇到的特殊情况',
                '您的反馈帮助我们改进产品',
                'GitHub Issues: https://github.com/lxcxjxhx/HOS-LS/issues'
            ]
        
        return UserFriendlyError(
            original_error=f"{context}\n{error_str}\n\n{traceback.format_exc()}",
            user_message=f'遇到了一个意外的问题: {error_str[:100]}{"..." if len(error_str) > 100 else ""}',
            severity=ErrorSeverity.ERROR,
            possible_causes=['未知原因（需要进一步诊断）'],
            solutions=generic_solutions,
            example_commands=[
                '# 最简单的排查方法 - 尝试基本命令:',
                'python -m src.cli.main --help',
                '',
                '# 查看版本信息:',
                'python -m src.cli.main --version'
            ],
            tips=generic_tips
        )


# 全局单例
_global_error_handler: Optional[IntelligentErrorHandler] = None


def get_error_handler() -> IntelligentErrorHandler:
    """获取全局错误处理器实例"""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = IntelligentErrorHandler()
    return _global_error_handler


def handle_error_user_friendly(error: Exception, context: str = "") -> str:
    """便捷函数：处理错误并返回用户友好的字符串
    
    Args:
        error: 异常对象
        context: 上下文
        
    Returns:
        格式化的用户友好错误信息
    """
    handler = get_error_handler()
    friendly_error = handler.handle_error(error, context)
    return friendly_error.to_display_string()


if __name__ == "__main__":
    # 测试各种错误场景
    handler = IntelligentErrorHandler()
    
    test_errors = [
        Exception("API key is invalid"),
        Exception("Rate limit exceeded. Please retry after 30 seconds"),
        Exception("File not found: /nonexistent/path/file.py"),
        Exception("Permission denied when accessing /root/secret"),
        Exception("JSON parse error: unexpected token at position 42"),
        Exception("Out of memory: cannot allocate array of size 1.5 GB"),
        Exception("Connection timeout to api.deepseek.com"),
        Exception("Some unknown weird error occurred")
    ]
    
    print("🧪 智能错误处理测试:\n")
    for i, error in enumerate(test_errors, 1):
        print(f"{'='*80}")
        print(f"测试 {i}: {str(error)[:60]}...")
        print(f"{'='*80}")
        
        friendly = handler.handle_error(error, f"Test scenario {i}")
        print(friendly.to_display_string())
        print("\n")

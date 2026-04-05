"""提示词管理模块

提供结构化的提示词管理，支持自定义提示词和优化的系统提示词。
"""

from pathlib import Path
from typing import Dict, Optional, Union

from src.core.config import Config, get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PromptManager:
    """提示词管理器"""

    def __init__(self, config: Optional[Config] = None):
        """初始化提示词管理器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._prompts: Dict[str, str] = {}
        self._load_default_prompts()

    def _load_default_prompts(self) -> None:
        """加载默认提示词"""
        # 安全分析系统提示词
        self._prompts["security_analysis"] = """你是专业代码安全分析师，专注识别安全漏洞和风险。

目标：执行全面的代码安全审查，发现所有可能的安全问题，包括但不限于高影响漏洞。

核心要求：
- 平衡误报和漏报（>70%信心）
- 关注实际安全风险，同时不忽略潜在问题
- 全面检查所有安全类别

检查范围：
- 输入验证：SQL注入、命令注入、XXE、模板注入、NoSQL注入、路径遍历、LDAP注入、SMTP注入
- 认证授权：认证绕过、权限提升、会话管理缺陷、JWT漏洞、OAuth漏洞、OpenID漏洞
- 加密密钥：硬编码凭证/密钥、弱加密、不当密钥管理、不安全的随机数生成
- 代码执行：反序列化RCE、Pickle注入、YAML反序列化、Eval注入、XSS、CSRF、SSRF
- 数据暴露：敏感数据日志/存储、PII违规、API数据泄露、调试信息暴露、配置文件泄露
- 配置安全：不安全的配置选项、默认凭证、过度权限、CORS配置错误
- 脚本安全：Shell脚本注入、PowerShell注入、命令注入
- 网络安全：明文传输、证书验证缺失、不安全的HTTP方法
- 依赖安全：过时依赖、已知漏洞的依赖库
- 日志安全：敏感信息日志、日志注入
- 容器安全：不安全的容器配置、特权容器、敏感挂载

分析方法：
1. 代码上下文分析（安全框架、编码模式、验证机制）
2. 数据流分析（用户输入到敏感操作、权限边界、注入点）
3. 漏洞评估（影响、严重程度、可利用性、修复建议）

输出JSON格式，包含：rule_id、rule_name、description、severity、confidence、location、code_snippet、fix_suggestion、explanation、references、exploit_scenario。

即使你认为问题可能是误报，也要将其包含在结果中，让后续的过滤机制处理。

无问题返回空findings数组。"""

        # 快速分析提示词
        self._prompts["fast_analysis"] = """你是专业代码安全分析师，请快速分析代码识别安全漏洞。

输出JSON格式，包含：rule_id、rule_name、description、severity、confidence、location、code_snippet、fix_suggestion、exploit_scenario。

无问题返回空findings数组。"""

        # 误报过滤提示词
        self._prompts["false_positive_filter"] = """你是安全专家，负责过滤误报，减少警报疲劳，保持高召回率。

判断标准：
1. 存在具体可利用漏洞和明确攻击路径
2. 代表真实安全风险（非理论最佳实践）
3. 有具体代码位置和复现步骤
4. 对安全团队可操作

输出JSON：{"keep_finding": false, "confidence": 0.8, "justification": "", "exclusion_reason": null}"""

        # 安全分析摘要提示词
        self._prompts["security_summary"] = """你是专业代码安全分析师，根据分析结果生成详细安全摘要报告，包含：
1. 总体安全状况评估
2. 主要安全问题概述
3. 风险等级分布
4. 建议的修复优先级
5. 安全最佳实践建议

结构化输出，清晰易懂。"""

        # 漏洞分类提示词
        self._prompts["vulnerability_classification"] = """你是漏洞分类专家，对漏洞进行准确分类。

严重程度：
- critical: 系统完全控制、敏感数据泄露、严重业务中断
- high: 重要功能受损、数据泄露、权限提升
- medium: 有限功能受损、信息泄露
- low: 轻微功能问题
- info: 仅信息，无直接威胁

漏洞类型：
sql_injection、xss、command_injection、hardcoded_credentials、hardcoded_keys、insecure_random、weak_crypto、sensitive_data_exposure、authentication_bypass、authorization_issue、csrf、ssrf、rce、lfi、rfi、xxe、dos、info_disclosure、ldap_injection、smtp_injection、oauth_vulnerability、openid_vulnerability、yaml_deserialization、pickle_injection、eval_injection、cors_misconfiguration、shell_injection、powershell_injection、plaintext_transmission、certificate_validation_missing、unsafe_http_methods、outdated_dependency、log_injection、container_security_issue、configuration_security、script_injection、dependency_vulnerability

输出JSON：{"severity": "", "vulnerability_type": "", "description": "", "confidence": 0.0}"""

        # AI学习提示词
        self._prompts["ai_learning"] = """你是安全漏洞学习专家，从扫描结果和用户反馈中学习，识别模式，提取知识，提供改进建议。

分析重点：
- 常见漏洞模式和趋势
- 误报和漏报模式
- 有价值的安全知识和规则
- 检测能力改进方法
- 潜在新型漏洞预测

输出详细分析结果，包含模式及置信度、提取的知识及来源、具体改进建议、分析结果置信度。

返回JSON格式。"""

        # 攻击链路分析提示词
        self._prompts["attack_chain_analysis"] = """你是攻击链路分析系统，识别漏洞间关联关系，构建攻击路径，评估风险。

分析要求：
- 识别因果关系和依赖关系
- 评估攻击路径可能性
- 提供概率评分(0-1)
- 描述关系类型和攻击场景
- 考虑严重程度、置信度和位置信息

返回JSON格式，包含关系列表（源漏洞索引、目标漏洞索引、关系类型、概率评分、关系描述）。"""

        # 优先级评估提示词
        self._prompts["priority_evaluation"] = """你是漏洞优先级评估专家，基于上下文和潜在影响评估优先级。

评估因素：严重程度、可利用性、影响范围、上下文、资产价值
优先级等级：1-5（1最高）
优先级得分：0-1（1最高）

返回JSON格式，包含优先级、得分、各因素得分和评估理由。"""

    def load_from_file(self, file_path: Union[str, Path]) -> bool:
        """从文件加载提示词

        Args:
            file_path: 提示词文件路径

        Returns:
            bool: 是否加载成功
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logger.error(f"Prompt file not found: {file_path}")
                return False

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 简单的格式解析：每行以 "key: " 开头，后面是提示词内容
            lines = content.strip().split('\n')
            current_key = None
            current_content = []

            for line in lines:
                line = line.strip()
                if line.endswith(':'):
                    # 保存之前的提示词
                    if current_key:
                        self._prompts[current_key] = '\n'.join(current_content)
                    # 开始新的提示词
                    current_key = line[:-1].strip()
                    current_content = []
                elif current_key:
                    current_content.append(line)

            # 保存最后一个提示词
            if current_key:
                self._prompts[current_key] = '\n'.join(current_content)

            logger.info(f"Loaded prompts from file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load prompts from file: {e}")
            return False

    def get_prompt(self, key: str, default: Optional[str] = None) -> str:
        """获取提示词

        Args:
            key: 提示词键
            default: 默认值

        Returns:
            str: 提示词内容
        """
        return self._prompts.get(key, default or "")

    def set_prompt(self, key: str, value: str) -> None:
        """设置提示词

        Args:
            key: 提示词键
            value: 提示词内容
        """
        self._prompts[key] = value
        logger.info(f"Set prompt: {key}")

    def list_prompts(self) -> list:
        """列出所有可用的提示词键

        Returns:
            list: 提示词键列表
        """
        return list(self._prompts.keys())


# 全局提示词管理器实例
_prompt_manager: Optional[PromptManager] = None


def get_prompt_manager(config: Optional[Config] = None) -> PromptManager:
    """获取提示词管理器实例

    Args:
        config: 配置对象

    Returns:
        PromptManager: 提示词管理器实例
    """
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager(config)
    return _prompt_manager

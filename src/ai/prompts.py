"""提示词管理模块

提供结构化的提示词管理，支持自定义提示词和优化的系统提示词。
"""

from pathlib import Path
from typing import Dict, List, Optional, Union, Any

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
        # ========== v3 规则驱动的安全分析 Prompt ==========
        self._prompts["security_analysis_v3"] = """[任务]：检测代码中的安全漏洞

[上下文]
语言：{{language}}
文件路径：{{file_path}}
代码片段：
{{code}}

[检测规则]
按以下规则逐一检查：

1. SQL注入检测
   - 是否存在字符串拼接 SQL
   - 是否使用未过滤的用户输入
   - 是否使用 ORM 安全方式
   - 检查关键词：execute、cursor、sql、query

2. 命令注入检测
   - 是否存在 subprocess、os.system、eval、exec
   - 是否使用未过滤的用户输入
   - 是否使用 shlex.quote 或安全执行方式

3. XSS 检测
   - 是否存在 innerHTML、outerHTML、document.write
   - 是否直接输出用户输入到 HTML
   - 是否有适当的转义

4. 硬编码凭证检测
   - 是否存在 password、api_key、secret、token、key
   - 值是否为硬编码字符串（非测试值）
   - 检查是否从环境变量读取

5. 弱加密检测
   - 是否使用 md5、sha1、des、rc4、3des
   - 是否使用不安全的随机数（random 而非 secrets）

6. 路径遍历检测
   - 是否存在 ../ 或路径拼接
   - 是否使用 os.path.join 且未验证输入
   - 是否有适当的路径规范化

7. CSRF 检测
   - 是否存在表单提交
   - 是否缺少 CSRF token
   - 是否有 Referer 验证

8. SSRF 检测
   - 是否存在 requests、urlopen、fetch、curl
   - URL 是否由用户输入控制
   - 是否有 SSRF 保护机制

9. 反序列化检测
   - 是否存在 pickle.load、yaml.load、jsonpickle
   - 是否反序列化不受信任的数据

10. 敏感数据暴露
    - 是否在日志中输出密码、密钥、PII
    - 是否在调试信息中暴露敏感数据

[输出格式 - 严格 JSON]
{
  "findings": [
    {
      "rule_id": "SQL_INJECTION",
      "rule_name": "SQL 注入漏洞",
      "description": "存在 SQL 注入风险，代码中直接拼接用户输入到 SQL 查询",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.95,
      "location": {
        "file": "{{file_path}}",
        "line": 123,
        "column": 45
      },
      "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
      "fix_suggestion": "使用参数化查询：cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
      "explanation": "用户输入 user_id 直接拼接到 SQL 查询中，攻击者可以注入恶意 SQL",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection"
      ],
      "exploit_scenario": "攻击者输入 '1 OR 1=1--' 可以获取所有用户数据"
    }
  ],
  "summary": "发现 N 个潜在安全问题",
  "risk_score": 7.5
}

[要求]
- 只输出 JSON，不要有任何其他文本
- 无问题时返回 {"findings": [], "summary": "未发现安全问题", "risk_score": 0.0}
- 置信度范围 0.0-1.0，越接近 1.0 越确定
- 严重性必须是：critical、high、medium、low、info 之一
- 严格遵循 JSON 格式，确保可以被解析"""

        # ========== 第一阶段：轻量定位 Prompt ==========
        self._prompts["phase1_locate"] = """[任务]：快速定位代码中的可疑点（低 token）

[上下文]
语言：{{language}}
代码片段：
{{code}}

[目标]
只找出可能存在安全问题的代码位置，不要做深度分析

[输出格式 - JSON]
{
  "suspicious_points": [
    {
      "line": 123,
      "type": "sql_injection|xss|command_injection|hardcoded_credentials|...",
      "snippet": "cursor.execute(f\"...\")"
    }
  ]
}

[可疑类型列表]
sql_injection, xss, command_injection, hardcoded_credentials, weak_crypto,
path_traversal, csrf, ssrf, deserialization, sensitive_data_exposure

[要求]
- 只输出 JSON
- 无问题时返回 {"suspicious_points": []}"""

        # ========== 第二阶段：精扫 Prompt ==========
        self._prompts["phase2_deep_scan"] = """[任务]：深度分析可疑代码区域

[上下文]
语言：{{language}}
文件路径：{{file_path}}
可疑类型：{{vuln_type}}
可疑行：{{line_num}}
代码区域（±50行）：
{{code}}

[检测规则 - {{vuln_type}}]
{{specific_rules}}

[输出格式 - 严格 JSON]
{
  "vuln": true|false,
  "rule_id": "{{vuln_type.upper()}}",
  "rule_name": "{{vuln_type}} 漏洞",
  "description": "...",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.95,
  "location": {
    "file": "{{file_path}}",
    "line": {{line_num}},
    "column": 0
  },
  "code_snippet": "...",
  "fix_suggestion": "...",
  "explanation": "...",
  "references": [],
  "exploit_scenario": "..."
}

[要求]
- 只输出 JSON
- vuln 为 true 时才包含完整信息
- vuln 为 false 时只返回 {"vuln": false}"""

        # ========== SQL 注入专项规则 ==========
        self._prompts["rules_sql_injection"] = """1. 检查是否存在字符串拼接 SQL 查询
2. 检查是否使用未过滤的用户输入
3. 检查是否使用参数化查询（安全）
4. 检查 ORM 使用是否安全"""

        # ========== 命令注入专项规则 ==========
        self._prompts["rules_command_injection"] = """1. 检查 subprocess、os.system、eval、exec 的使用
2. 检查参数是否由用户输入控制
3. 检查是否使用 shell=True（危险）
4. 检查是否使用 shlex.quote 或安全列表参数"""

        # ========== XSS 专项规则 ==========
        self._prompts["rules_xss"] = """1. 检查 innerHTML、outerHTML、document.write
2. 检查用户输入是否直接输出到 HTML
3. 检查是否有适当的转义（escape、sanitize）
4. 检查框架是否自动转义（React、Vue 等）"""

        # ========== 安全分析系统提示词（旧版保留兼容） ==========
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

    def render_template(self, key: str, variables: Dict[str, str]) -> str:
        """渲染带变量的提示词模板

        Args:
            key: 提示词键
            variables: 变量字典

        Returns:
            str: 渲染后的提示词
        """
        prompt = self.get_prompt(key)
        if not prompt:
            return ""
        
        # 替换 {{variable}} 格式的变量
        for var_name, var_value in variables.items():
            prompt = prompt.replace(f"{{{{{var_name}}}}}", str(var_value))
        
        return prompt

    def get_rule_based_prompt(
        self,
        language: str,
        file_path: str,
        code: str,
        rules: Optional[List[str]] = None
    ) -> str:
        """获取规则驱动的安全分析 Prompt

        Args:
            language: 编程语言
            file_path: 文件路径
            code: 代码片段
            rules: 要启用的规则列表，None 表示使用所有规则

        Returns:
            str: 渲染后的 Prompt
        """
        variables = {
            "language": language,
            "file_path": file_path,
            "code": code
        }
        return self.render_template("security_analysis_v3", variables)

    def get_phase1_prompt(self, language: str, code: str) -> str:
        """获取第一阶段：轻量定位 Prompt

        Args:
            language: 编程语言
            code: 代码片段

        Returns:
            str: 渲染后的 Prompt
        """
        variables = {
            "language": language,
            "code": code
        }
        return self.render_template("phase1_locate", variables)

    def get_phase2_prompt(
        self,
        language: str,
        file_path: str,
        vuln_type: str,
        line_num: int,
        code: str
    ) -> str:
        """获取第二阶段：精扫 Prompt

        Args:
            language: 编程语言
            file_path: 文件路径
            vuln_type: 漏洞类型
            line_num: 可疑行号
            code: 代码片段（±50行）

        Returns:
            str: 渲染后的 Prompt
        """
        # 获取专项规则
        rule_key = f"rules_{vuln_type}"
        specific_rules = self.get_prompt(rule_key, "请按常规安全分析方法检查")
        
        variables = {
            "language": language,
            "file_path": file_path,
            "vuln_type": vuln_type,
            "line_num": str(line_num),
            "code": code,
            "specific_rules": specific_rules
        }
        return self.render_template("phase2_deep_scan", variables)


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


def get_semantic_analysis_prompt(analysis_input: Dict[str, Any]) -> str:
    """获取语义分析提示词

    Args:
        analysis_input: 分析输入，包含代码、证据、污点路径和CVE模式

    Returns:
        str: 语义分析提示词
    """
    prompt = """你是专业的语义安全分析专家，负责基于代码和现有证据进行深入的语义理解和漏洞分析。

[分析任务]
基于提供的代码、证据、污点路径和CVE模式，进行全面的语义分析，识别潜在的安全漏洞。

[分析输入]
代码:
{code}

现有证据:
{evidence}

污点路径:
{taint_paths}

CVE模式:
{cve_patterns}

[分析要求]
1. 深入理解代码的语义结构和逻辑流程
2. 结合现有证据和污点路径进行综合分析
3. 识别潜在的安全漏洞，包括但不限于：
   - 代码注入
   - 命令注入
   - SQL注入
   - XSS
   - 路径遍历
   - 认证绕过
   - 授权绕过
   - 信息泄露
   - 拒绝服务
   - 缓冲区溢出
4. 对每个发现的漏洞提供详细的分析和评估
5. 生成标准化的输出格式

[输出格式]
请以JSON格式输出分析结果，包含以下字段：
{
  "vulnerabilities": [
    {
      "rule_id": "SEMANTIC-001",
      "message": "语义分析发现的漏洞描述",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.95,
      "location": {
        "file": "unknown",
        "line": 123
      },
      "vulnerability_type": "代码注入",
      "exploitability": "High",
      "reasoning": "详细的分析推理过程"
    }
  ]
}

[注意事项]
- 输出必须是有效的JSON格式
- 分析要基于代码的实际语义，避免误报
- 提供充分的推理过程，说明漏洞的成因和潜在影响
- 置信度要基于分析的确定性，范围0.0-1.0
"""
    
    # 格式化输入
    code = analysis_input.get('code', '')
    evidence = analysis_input.get('evidence', [])
    taint_paths = analysis_input.get('taint_paths', [])
    cve_patterns = analysis_input.get('cve_patterns', [])
    
    # 转换列表为字符串
    evidence_str = '\n'.join([str(item) for item in evidence])
    taint_paths_str = '\n'.join([str(item) for item in taint_paths])
    cve_patterns_str = '\n'.join([str(item) for item in cve_patterns])
    
    # 替换占位符
    prompt = prompt.format(
        code=code,
        evidence=evidence_str,
        taint_paths=taint_paths_str,
        cve_patterns=cve_patterns_str
    )
    
    return prompt

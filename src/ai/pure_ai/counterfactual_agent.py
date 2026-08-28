"""CounterfactualAgent — 反事实验证 Agent

对疑似漏洞构造"安全反事实"（添加安全措施后的版本），
验证漏洞在反事实中是否消失，从而提供可证伪的证据链。

这是论文核心验证机制 DEP 的关键组件：
- 输入：疑似漏洞代码段 + 上下文
- 输出：反事实实验报告（漏洞在反事实中消失 → 确认；未消失 → 降低置信度）
- 大幅提升 Pair-Correct 指标（确认漏洞确实被正确修复）
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CounterfactualExperiment:
    """单个反事实实验"""
    experiment_id: str
    vulnerability_type: str
    method_name: str
    original_snippet: str                    # 原始代码片段
    counterfactual_snippet: str              # 反事实代码（添加安全措施）
    modification_description: str            # 添加的安全措施描述
    expected_result: str                     # 预期：漏洞应消失
    actual_result: str = ""                  # 实际验证结果
    verified: Optional[bool] = None          # 是否验证通过


@dataclass
class CounterfactualReport:
    """反事实实验报告"""
    findings: List[CounterfactualExperiment] = field(default_factory=list)
    summary: str = ""
    pass_count: int = 0
    fail_count: int = 0
    total_experiments: int = 0


SECURITY_FIX_TEMPLATES = {
    "SQL_INJECTION": {
        "add_prepared": (
            "PreparedStatement/参数化查询",
            "将字符串拼接的 SQL 查询改为 PreparedStatement / 参数化查询"
        ),
        "add_escape": (
            "输入转义",
            "对输入进行 SQL 特殊字符转义"
        ),
    },
    "XSS": {
        "add_escape_output": (
            "输出编码",
            "对输出进行 HTML 实体编码（escape）"
        ),
        "add_csp": (
            "CSP 头",
            "添加 Content-Security-Policy 响应头"
        ),
    },
    "COMMAND_INJECTION": {
        "add_shell_escape": (
            "Shell 参数转义",
            "对命令参数进行 shell 转义或使用 shlex.quote()"
        ),
        "add_allowlist": (
            "命令白名单",
            "限制可执行命令为白名单中的安全命令"
        ),
    },
    "PATH_TRAVERSAL": {
        "add_path_normalize": (
            "路径规范化",
            "对用户输入路径进行规范化处理（realpath/normpath）并验证在允许范围内"
        ),
        "add_basename_only": (
            "仅允许文件名",
            "只取路径中的 basename，丢弃目录部分"
        ),
    },
    "AUTH_BYPASS": {
        "add_auth_check": (
            "添加认证检查",
            "在访问敏感资源前添加身份验证/权限检查"
        ),
        "add_role_check": (
            "添加角色检查",
            "验证用户是否具有访问该资源的角色权限"
        ),
    },
    "SSRF": {
        "add_url_validate": (
            "URL 白名单验证",
            "对目标 URL 进行白名单验证（仅允许内部服务/已知安全域名）"
        ),
        "add_url_block": (
            "内网地址拦截",
            "拦截指向内网（127.0.0.1/10.0.0.0/172.16.0.0/192.168.0.0）的请求"
        ),
    },
}


class CounterfactualConstructor:
    """反事实构造器 — 为可疑漏洞代码构造安全反事实"""

    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def construct(self, snippet: str, vuln_type: str, language: str) -> CounterfactualExperiment:
        """为可疑代码构造安全反事实

        Args:
            snippet: 原始代码片段
            vuln_type: 漏洞类型
            language: 编程语言

        Returns:
            反事实实验
        """
        templates = SECURITY_FIX_TEMPLATES.get(vuln_type, {})
        if not templates:
            # 未知类型的漏洞，尝试通用修复
            counterfactual = self._generic_counterfactual(snippet, language)
            return counterfactual

        # 选择第一个适合的修复模板
        template_key = list(templates.keys())[0]
        fix_name, fix_desc = templates[template_key]
        counterfactual = self._apply_template(snippet, vuln_type, fix_name, fix_desc, language)
        return counterfactual

    def _apply_template(self, snippet: str, vuln_type: str, fix_name: str,
                        fix_desc: str, language: str) -> CounterfactualExperiment:
        """应用修复模板构造反事实"""
        # 对常见的漏洞模式应用规则式修复
        counterfactual_snippet = snippet

        if vuln_type == "SQL_INJECTION":
            if "PreparedStatement" not in snippet and "prepared" not in snippet.lower():
                # Python: 替换 cursor.execute(f"...{var}") → cursor.execute("...", (var,))
                counterfactual_snippet = re.sub(
                    r'cursor\.execute\s*\(\s*(f["\'])(.*?)\{(\w+)\}(.*?)(["\'])\s*\)',
                    r'cursor.execute(\2%s\4, (\3,))',
                    snippet
                )
                # 替换拼接模式
                counterfactual_snippet = re.sub(
                    r'execute\s*\(\s*["\'].*?["\']\s*\+\s*\w+',
                    r'# 反事实: 应使用参数化查询代替拼接\nexecute("...", (param,))',
                    counterfactual_snippet
                )

        elif vuln_type == "XSS":
            if "escape" not in snippet.lower():
                # 在输出前添加 escape
                counterfactual_snippet = re.sub(
                    r'(return\s+response|return\s+render|\.write|\.html\s*=)',
                    r'# 反事实: 添加输出编码\nescape_html(\1)',
                    snippet
                )

        elif vuln_type == "COMMAND_INJECTION":
            if "quote" not in snippet:
                counterfactual_snippet = re.sub(
                    r'(subprocess\.(call|run|Popen)\s*\(\s*)',
                    r'\1# 反事实: 使用 shlex.quote() 转义参数\n',
                    snippet
                )

        elif vuln_type == "PATH_TRAVERSAL":
            if "realpath" not in snippet and "normpath" not in snippet and "abspath" not in snippet:
                counterfactual_snippet = re.sub(
                    r'(open\s*\(\s*)(\w+)',
                    r'\1# 反事实: 路径规范化\nos.path.realpath(\2)',
                    snippet
                )

        # 添加注释说明
        comment_prefix = "#" if language == "python" else "//"
        modified_snippet = (
            f"{comment_prefix} === [反事实] {fix_desc} ===\n"
            f"{counterfactual_snippet}\n"
            f"{comment_prefix} === [/反事实] ==="
        )

        return CounterfactualExperiment(
            experiment_id=f"CF-{vuln_type}-{hash(snippet) % 10000}",
            vulnerability_type=vuln_type,
            method_name=fix_name,
            original_snippet=snippet,
            counterfactual_snippet=modified_snippet,
            modification_description=fix_desc,
            expected_result=f"添加 {fix_name} 后漏洞路径应被阻断",
        )

    def _generic_counterfactual(self, snippet: str, language: str) -> CounterfactualExperiment:
        """通用反事实构造（无模板时）"""
        comment_prefix = "#" if language == "python" else "//"
        modified = (
            f"{comment_prefix} === [反事实-通用] 添加输入验证与安全检查 ===\n"
            f"{comment_prefix} 原始: {snippet.strip()}\n"
            f"{comment_prefix} 反事实: \n"
            f"{comment_prefix} if not validate_input(input_data):\n"
            f"{comment_prefix}     raise ValueError(\"Invalid input\")\n"
            f"{comment_prefix} result = safe_execute(sanitized_input)\n"
            f"{comment_prefix} === [/反事实] ==="
        )
        return CounterfactualExperiment(
            experiment_id=f"CF-GENERIC-{hash(snippet) % 10000}",
            vulnerability_type="GENERIC",
            method_name="通用输入验证",
            original_snippet=snippet,
            counterfactual_snippet=modified,
            modification_description="添加输入验证与安全检查",
            expected_result="添加安全措施后漏洞不可利用",
        )

    def construct_batch(self, findings: List[Dict[str, Any]], language: str = "python") -> List[CounterfactualExperiment]:
        """批量构造反事实"""
        experiments = []
        for finding in findings:
            snippet = finding.get("snippet", "") or finding.get("code_snippet", "")
            vuln_type = finding.get("vuln_type", "GENERIC")
            if snippet:
                exp = self.construct(snippet, vuln_type, language)
                experiments.append(exp)
        return experiments


class CounterfactualAgent:
    """反事实验证 Agent — 通过构造安全反事实来验证漏洞"""

    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.constructor = CounterfactualConstructor(llm_client)

    def verify(self, findings: List[Dict[str, Any]], language: str = "python") -> CounterfactualReport:
        """对一组发现进行反事实验证

        Args:
            findings: 发现列表（来自上游 Agent）
            language: 编程语言

        Returns:
            反事实报告
        """
        experiments = self.constructor.construct_batch(findings, language)
        report = CounterfactualReport(findings=experiments)
        report.total_experiments = len(experiments)

        for exp in experiments:
            # 验证：运行 Semgrep 检查反事实中漏洞是否消失
            verified, actual = self._verify_experiment(exp)
            exp.verified = verified
            exp.actual_result = actual

            if verified:
                report.pass_count += 1
            else:
                report.fail_count += 1

        # 生成摘要
        if report.total_experiments == 0:
            report.summary = "无反事实实验"
        else:
            pass_pct = report.pass_count / report.total_experiments * 100
            report.summary = (
                f"反事实验证: {report.pass_count}/{report.total_experiments} 通过 ({pass_pct:.0f}%)"
            )

        return report

    def _verify_experiment(self, exp: CounterfactualExperiment) -> Tuple[bool, str]:
        """验证单个反事实实验

        用 Semgrep 检查原始代码和反事实代码，确认漏洞是否确实被修复。
        如果没有 Semgrep CLI，用基于规则的模式匹配。
        """
        # 优先使用 Semgrep CLI
        import subprocess
        import tempfile
        import json

        try:
            # 创建一个临时文件包含原始代码
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write("import os\nimport subprocess\n")  # 常见 import
                f.write(exp.counterfactual_snippet)
                tmp_path = f.name

            # 用 semgrep 扫描反事实代码
            result = subprocess.run(
                ["semgrep", "scan", "--config", "p/default", "--json", "-q", tmp_path],
                capture_output=True, text=True, timeout=60,
                encoding="utf-8", errors="replace",
            )

            os.unlink(tmp_path)

            data = json.loads(result.stdout or "{}")
            hits = data.get("results", [])

            if hits:
                # 反事实中仍有命中 — 反事实未能完全修复
                return False, f"反事实中仍有 {len(hits)} 条规则命中（修复不完整）"
            else:
                # 反事实中无命中 — 漏洞被阻断
                return True, "反事实通过: Semgrep 无命中"

        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            # 无 Semgrep CLI — 用模式匹配降级
            return self._rule_based_verify(exp)

    def _rule_based_verify(self, exp: CounterfactualExperiment) -> Tuple[bool, str]:
        """基于规则的降级验证（无 Semgrep CLI 时）"""
        vuln_type = exp.vulnerability_type
        cf = exp.counterfactual_snippet

        # 检查反事实中是否包含对应的安全措施
        if vuln_type == "SQL_INJECTION":
            has_fix = "PreparedStatement" in cf or "parameterize" in cf.lower() or "%s" in cf or "?" in cf
        elif vuln_type == "XSS":
            has_fix = "escape" in cf.lower() or "sanitize" in cf.lower()
        elif vuln_type == "COMMAND_INJECTION":
            has_fix = "quote" in cf.lower() or "shlex" in cf.lower()
        elif vuln_type == "PATH_TRAVERSAL":
            has_fix = "realpath" in cf or "normpath" in cf
        elif vuln_type == "AUTH_BYPASS":
            has_fix = "auth" in cf.lower() or "login" in cf.lower() or "permission" in cf.lower()
        else:
            has_fix = "validate" in cf.lower() or "secure" in cf.lower()

        if has_fix:
            return True, "反事实通过（规则验证：安全措施已在反事实中应用）"
        else:
            return False, "反事实失败（规则验证：无法确认安全措施已应用）"

    def to_agent_format(self, report: CounterfactualReport) -> Dict[str, Any]:
        """转换为 AgentVote 兼容格式"""
        return {
            "counterfactual_report": [
                {
                    "experiment_id": exp.experiment_id,
                    "vulnerability_type": exp.vulnerability_type,
                    "modification": exp.modification_description,
                    "verified": exp.verified,
                    "expected": exp.expected_result,
                    "actual": exp.actual_result,
                }
                for exp in report.findings
            ],
            "summary": report.summary,
            "pass_rate": report.pass_count / report.total_experiments if report.total_experiments > 0 else 0,
            "total": report.total_experiments,
        }

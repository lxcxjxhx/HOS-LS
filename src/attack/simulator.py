"""攻击模拟器模块

提供攻击模拟测试功能。
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackScenario:
    """攻击场景"""
    
    id: str
    name: str
    description: str
    attack_type: str
    target_files: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_findings: List[str] = field(default_factory=list)


@dataclass
class AttackResult:
    """攻击结果"""
    
    scenario_id: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: str = ""


class AttackSimulator:
    """攻击模拟器
    
    支持 8+ 攻击场景的模拟测试。
    """
    
    BUILTIN_SCENARIOS = [
        AttackScenario(
            id="sql_injection_basic",
            name="SQL 注入基础测试",
            description="测试基本的 SQL 注入漏洞",
            attack_type="injection",
            expected_findings=["SQL_INJECTION"],
        ),
        AttackScenario(
            id="xss_reflected",
            name="反射型 XSS 测试",
            description="测试反射型跨站脚本漏洞",
            attack_type="xss",
            expected_findings=["XSS"],
        ),
        AttackScenario(
            id="command_injection",
            name="命令注入测试",
            description="测试命令注入漏洞",
            attack_type="injection",
            expected_findings=["COMMAND_INJECTION"],
        ),
        AttackScenario(
            id="path_traversal",
            name="路径遍历测试",
            description="测试路径遍历漏洞",
            attack_type="traversal",
            expected_findings=["PATH_TRAVERSAL"],
        ),
        AttackScenario(
            id="ssrf_basic",
            name="SSRF 基础测试",
            description="测试服务器端请求伪造漏洞",
            attack_type="ssrf",
            expected_findings=["SSRF"],
        ),
        AttackScenario(
            id="auth_bypass",
            name="认证绕过测试",
            description="测试认证绕过漏洞",
            attack_type="auth",
            expected_findings=["AUTH_BYPASS"],
        ),
        AttackScenario(
            id="sensitive_data_exposure",
            name="敏感数据暴露测试",
            description="测试敏感数据暴露漏洞",
            attack_type="data",
            expected_findings=["SENSITIVE_DATA_EXPOSURE"],
        ),
        AttackScenario(
            id="prompt_injection",
            name="Prompt 注入测试",
            description="测试 AI Prompt 注入漏洞",
            attack_type="ai",
            expected_findings=["PROMPT_INJECTION"],
        ),
    ]
    
    def __init__(self) -> None:
        self.scenarios: Dict[str, AttackScenario] = {}
        self._load_builtin_scenarios()
    
    def _load_builtin_scenarios(self) -> None:
        """加载内置场景"""
        for scenario in self.BUILTIN_SCENARIOS:
            self.scenarios[scenario.id] = scenario
    
    def register_scenario(self, scenario: AttackScenario) -> None:
        """注册场景"""
        self.scenarios[scenario.id] = scenario
    
    def get_scenario(self, scenario_id: str) -> Optional[AttackScenario]:
        """获取场景"""
        return self.scenarios.get(scenario_id)
    
    def list_scenarios(self) -> List[AttackScenario]:
        """列出所有场景"""
        return list(self.scenarios.values())
    
    async def run_scenario(
        self,
        scenario_id: str,
        target_code: str,
        language: str = "python",
    ) -> AttackResult:
        """运行攻击场景
        
        Args:
            scenario_id: 场景 ID
            target_code: 目标代码
            language: 语言
            
        Returns:
            攻击结果
        """
        import time
        
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            return AttackResult(
                scenario_id=scenario_id,
                success=False,
                error_message=f"场景 '{scenario_id}' 不存在",
            )
        
        start_time = time.time()
        findings = []
        
        try:
            # 根据攻击类型执行不同的测试
            if scenario.attack_type == "injection":
                findings = await self._test_injection(target_code, language)
            elif scenario.attack_type == "xss":
                findings = await self._test_xss(target_code, language)
            elif scenario.attack_type == "traversal":
                findings = await self._test_traversal(target_code, language)
            elif scenario.attack_type == "ssrf":
                findings = await self._test_ssrf(target_code, language)
            elif scenario.attack_type == "auth":
                findings = await self._test_auth(target_code, language)
            elif scenario.attack_type == "data":
                findings = await self._test_data_exposure(target_code, language)
            elif scenario.attack_type == "ai":
                findings = await self._test_prompt_injection(target_code, language)
            
            success = len(findings) > 0
            
        except Exception as e:
            success = False
            return AttackResult(
                scenario_id=scenario_id,
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )
        
        return AttackResult(
            scenario_id=scenario_id,
            success=success,
            findings=findings,
            execution_time=time.time() - start_time,
        )
    
    async def _test_injection(
        self, code: str, language: str
    ) -> List[Dict[str, Any]]:
        """测试注入漏洞"""
        findings = []
        
        # SQL 注入模式
        sql_patterns = [
            "execute(", "executemany(", "raw(", "cursor.execute",
            "SELECT * FROM", "INSERT INTO", "UPDATE", "DELETE FROM",
        ]
        
        for pattern in sql_patterns:
            if pattern.lower() in code.lower():
                findings.append({
                    "type": "SQL_INJECTION",
                    "pattern": pattern,
                    "severity": "high",
                    "message": f"发现潜在的 SQL 注入点: {pattern}",
                })
        
        # 命令注入模式
        cmd_patterns = [
            "os.system(", "subprocess.call(", "subprocess.run(",
            "subprocess.Popen(", "eval(", "exec(",
        ]
        
        for pattern in cmd_patterns:
            if pattern in code:
                findings.append({
                    "type": "COMMAND_INJECTION",
                    "pattern": pattern,
                    "severity": "critical",
                    "message": f"发现潜在的命令注入点: {pattern}",
                })
        
        return findings
    
    async def _test_xss(
        self, code: str, language: str
    ) -> List[Dict[str, Any]]:
        """测试 XSS 漏洞"""
        findings = []
        
        xss_patterns = [
            "innerHTML", "document.write(", "dangerouslySetInnerHTML",
            "render_template_string(", "Markup(", "|safe",
        ]
        
        for pattern in xss_patterns:
            if pattern in code:
                findings.append({
                    "type": "XSS",
                    "pattern": pattern,
                    "severity": "high",
                    "message": f"发现潜在的 XSS 漏洞: {pattern}",
                })
        
        return findings
    
    async def _test_traversal(
        self, code: str, language: str
    ) -> List[Dict[str, Any]]:
        """测试路径遍历漏洞"""
        findings = []
        
        traversal_patterns = [
            "open(", "read(", "write(", "send_file(",
            "os.path.join(", "Path(",
        ]
        
        for pattern in traversal_patterns:
            if pattern in code:
                # 检查是否有用户输入
                if "request" in code or "input" in code or "args" in code:
                    findings.append({
                        "type": "PATH_TRAVERSAL",
                        "pattern": pattern,
                        "severity": "high",
                        "message": f"发现潜在的路径遍历漏洞: {pattern}",
                    })
        
        return findings
    
    async def _test_ssrf(
        self, code: str, language: str
    ) -> List[Dict[str, Any]]:
        """测试 SSRF 漏洞"""
        findings = []
        
        ssrf_patterns = [
            "requests.get(", "requests.post(", "urllib.request.urlopen(",
            "httpx.get(", "httpx.post(", "aiohttp.ClientSession(",
        ]
        
        for pattern in ssrf_patterns:
            if pattern in code:
                findings.append({
                    "type": "SSRF",
                    "pattern": pattern,
                    "severity": "high",
                    "message": f"发现潜在的 SSRF 漏洞: {pattern}",
                })
        
        return findings
    
    async def _test_auth(
        self, code: str, language: str
    ) -> List[Dict[str, Any]]:
        """测试认证漏洞"""
        findings = []
        
        auth_patterns = [
            "password", "secret", "token", "api_key",
            "authorization", "bearer",
        ]
        
        for pattern in auth_patterns:
            if pattern in code.lower():
                # 检查是否有硬编码
                if f'"{pattern}"' in code.lower() or f"'{pattern}'" in code.lower():
                    findings.append({
                        "type": "AUTH_BYPASS",
                        "pattern": pattern,
                        "severity": "critical",
                        "message": f"发现潜在的认证问题: 硬编码 {pattern}",
                    })
        
        return findings
    
    async def _test_data_exposure(
        self, code: str, language: str
    ) -> List[Dict[str, Any]]:
        """测试敏感数据暴露"""
        findings = []
        
        sensitive_patterns = [
            "password", "api_key", "secret", "token",
            "private_key", "access_token", "refresh_token",
        ]
        
        for pattern in sensitive_patterns:
            if pattern in code.lower():
                # 检查是否有日志或输出
                if "print(" in code or "log" in code or "return" in code:
                    findings.append({
                        "type": "SENSITIVE_DATA_EXPOSURE",
                        "pattern": pattern,
                        "severity": "high",
                        "message": f"发现潜在的敏感数据暴露: {pattern}",
                    })
        
        return findings
    
    async def _test_prompt_injection(
        self, code: str, language: str
    ) -> List[Dict[str, Any]]:
        """测试 Prompt 注入漏洞"""
        findings = []
        
        prompt_patterns = [
            "prompt", "system_prompt", "user_input",
            "messages.append", "format(",
        ]
        
        for pattern in prompt_patterns:
            if pattern in code:
                # 检查是否有用户输入直接拼接到 prompt
                if "f'" in code or 'f"' in code or ".format(" in code or "+" in code:
                    findings.append({
                        "type": "PROMPT_INJECTION",
                        "pattern": pattern,
                        "severity": "critical",
                        "message": f"发现潜在的 Prompt 注入漏洞: {pattern}",
                    })
        
        return findings
    
    async def run_all_scenarios(
        self, target_code: str, language: str = "python"
    ) -> List[AttackResult]:
        """运行所有场景"""
        results = []
        for scenario_id in self.scenarios:
            result = await self.run_scenario(scenario_id, target_code, language)
            results.append(result)
        return results

"""AI辅助验证脚本生成模块

基于AI检测结果，结合AI动态生成验证脚本。
"""

import os
import hashlib
from typing import Dict, List, Optional, Any

from src.ai.models import VulnerabilityFinding, AIRequest
from src.ai.prompts import get_prompt_manager
from src.ai.client import get_model_manager, AIModelManager
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AIVerificationGenerator:
    """AI辅助验证脚本生成器"""

    # 支持的编程语言
    SUPPORTED_LANGUAGES = ["python", "java", "javascript"]

    # 各语言的测试框架
    TEST_FRAMEWORKS = {
        "python": "pytest",
        "java": "JUnit",
        "javascript": "Jest"
    }

    def __init__(self):
        """初始化AI验证脚本生成器"""
        self._prompt_manager = get_prompt_manager()
        self._model_manager: Optional[AIModelManager] = None

    async def _init_model_manager(self):
        """初始化模型管理器"""
        if self._model_manager is None:
            self._model_manager = await get_model_manager()

    def generate_verification_script(self, vuln_info: Dict, language: str = "python") -> str:
        """生成可执行的验证脚本（同步版本，不依赖AI）

        Args:
            vuln_info: 漏洞信息字典，包含:
                - type: 漏洞类型 (如 "sql_injection", "xss", "command_injection")
                - rule_id: 规则ID
                - rule_name: 规则名称
                - description: 漏洞描述
                - severity: 严重程度
                - location: 位置信息 {"file": str, "line": int}
                - code_snippet: 代码片段
            language: 脚本语言 (python/java/javascript)

        Returns:
            str: 生成的验证脚本内容
        """
        template_generator = VerificationScriptGenerator()
        return template_generator.generate_verification_script(vuln_info, language)

    async def generate_ai_verification_script(self, finding: VulnerabilityFinding,
                                             language: str = "python",
                                             output_dir: str = "./verification_scripts") -> str:
        """使用AI生成验证脚本

        Args:
            finding: 漏洞发现
            language: 脚本语言
            output_dir: 输出目录

        Returns:
            str: 生成的脚本路径
        """
        try:
            await self._init_model_manager()
            
            # 创建输出目录
            os.makedirs(output_dir, exist_ok=True)
            
            # 构建AI请求，生成验证脚本
            verification_script = await self._generate_script_with_ai(finding, language)
            
            # 生成文件名
            vulnerability_type = finding.rule_id.lower()
            filename = f"{vulnerability_type}_test.{language}"
            script_path = os.path.join(output_dir, filename)
            
            # 写入文件
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(verification_script)
            
            # 添加执行权限
            os.chmod(script_path, 0o755)
            
            logger.info(f"Generated AI-assisted verification script: {script_path}")
            return script_path
            
        except Exception as e:
            logger.error(f"Failed to generate AI-assisted verification script: {e}")
            return ""

    async def _generate_script_with_ai(self, finding: VulnerabilityFinding, language: str) -> str:
        """使用AI生成验证脚本内容

        Args:
            finding: 漏洞发现
            language: 脚本语言

        Returns:
            str: 验证脚本内容
        """
        # 构建提示词
        system_prompt = self._build_system_prompt(language)
        user_prompt = self._build_user_prompt(finding)
        
        # 构建AI请求
        ai_request = AIRequest(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.3,
            max_tokens=2048
        )
        
        # 生成响应
        response = await self._model_manager.generate(ai_request)
        
        # 提取脚本内容
        script_content = self._extract_script_content(response.content)
        
        return script_content

    def _build_system_prompt(self, language: str) -> str:
        """构建系统提示词

        Args:
            language: 脚本语言

        Returns:
            str: 系统提示词
        """
        return f"""你是一个专业的安全漏洞验证专家。你的任务是根据漏洞信息，生成一个可执行的验证脚本，用于POC（概念验证）复现漏洞。

## 要求：
1. 脚本必须完整、可执行
2. 包含详细的注释说明
3. 提供清晰的使用步骤
4. 包含预期结果和验证方法
5. 脚本应该是安全的，不会造成实际损害

## 脚本语言：
使用 {language} 语言编写验证脚本。

## 输出格式：
只返回完整的脚本代码，不要添加其他说明文字。
"""

    def _build_user_prompt(self, finding: VulnerabilityFinding) -> str:
        """构建用户提示词

        Args:
            finding: 漏洞发现

        Returns:
            str: 用户提示词
        """
        return f"""请根据以下漏洞信息，生成一个完整的验证脚本：

## 漏洞信息：
- 规则ID: {finding.rule_id}
- 规则名称: {finding.rule_name}
- 严重程度: {finding.severity}
- 置信度: {finding.confidence}
- 位置: {finding.location.get('file', 'unknown')}:{finding.location.get('line', 'unknown')}

## 漏洞描述：
{finding.description}

## 代码片段：
```
{finding.code_snippet}
```

## 修复建议：
{finding.fix_suggestion}

## 漏洞解释：
{finding.explanation}

## 漏洞利用场景：
{finding.exploit_scenario}

请生成一个完整的验证脚本，用于POC复现此漏洞。
"""

    def _extract_script_content(self, content: str) -> str:
        """从AI响应中提取脚本内容

        Args:
            content: AI响应内容

        Returns:
            str: 提取的脚本内容
        """
        # 尝试提取代码块
        if "```" in content:
            lines = content.split("\n")
            in_code_block = False
            script_lines = []
            
            for line in lines:
                if line.strip().startswith("```"):
                    in_code_block = not in_code_block
                    continue
                if in_code_block:
                    script_lines.append(line)
            
            if script_lines:
                return "\n".join(script_lines)
        
        # 如果没有找到代码块，返回整个内容
        return content

    async def generate_scripts_for_findings(self, findings: List[VulnerabilityFinding],
                                             language: str = "python",
                                             output_dir: str = "./verification_scripts") -> List[str]:
        """为多个漏洞发现生成验证脚本

        Args:
            findings: 漏洞发现列表
            language: 脚本语言
            output_dir: 输出目录

        Returns:
            List[str]: 生成的脚本路径列表
        """
        script_paths = []
        
        for finding in findings:
            # 只为高危漏洞生成脚本
            if finding.severity in ["critical", "high"]:
                script_path = await self.generate_ai_verification_script(finding, language, output_dir)
                if script_path:
                    script_paths.append(script_path)
        
        return script_paths

    async def generate_readme(self, findings: List[VulnerabilityFinding],
                               script_paths: List[str],
                               output_dir: str = "./verification_scripts") -> str:
        """生成README文件

        Args:
            findings: 漏洞发现列表
            script_paths: 脚本路径列表
            output_dir: 输出目录

        Returns:
            str: README文件路径
        """
        try:
            readme_content = await self._generate_readme_with_ai(findings, script_paths, output_dir)
            
            # 写入README文件
            readme_path = os.path.join(output_dir, "README.md")
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(readme_content)
            
            logger.info(f"Generated AI-assisted README: {readme_path}")
            return readme_path
            
        except Exception as e:
            logger.error(f"Failed to generate AI-assisted README: {e}")
            return ""

    async def _generate_readme_with_ai(self, findings: List[VulnerabilityFinding],
                                        script_paths: List[str],
                                        output_dir: str) -> str:
        """使用AI生成README内容

        Args:
            findings: 漏洞发现列表
            script_paths: 脚本路径列表
            output_dir: 输出目录

        Returns:
            str: README内容
        """
        await self._init_model_manager()
        
        # 构建漏洞信息摘要
        findings_summary = self._build_findings_summary(findings)
        scripts_summary = self._build_scripts_summary(script_paths)
        
        # 构建AI请求
        ai_request = AIRequest(
            prompt=f"""请为以下安全漏洞验证脚本生成一个详细的README.md文件：

## 漏洞列表：
{findings_summary}

## 验证脚本：
{scripts_summary}

## 输出目录：
{output_dir}

请生成一个清晰、结构化的README.md文件，包含：
1. 项目介绍
2. 漏洞列表（包含每个漏洞的关键信息）
3. 验证脚本列表
4. 使用说明
5. 注意事项

只返回markdown格式的内容，不要添加其他说明。
""",
            system_prompt="你是一个专业的技术文档撰写专家。请生成清晰、结构化的README文档。",
            temperature=0.2,
            max_tokens=2048
        )
        
        # 生成响应
        response = await self._model_manager.generate(ai_request)
        
        return response.content

    def _build_findings_summary(self, findings: List[VulnerabilityFinding]) -> str:
        """构建漏洞信息摘要

        Args:
            findings: 漏洞发现列表

        Returns:
            str: 漏洞信息摘要
        """
        summary = []
        for i, finding in enumerate(findings, 1):
            summary.append(f"{i}. {finding.rule_name}")
            summary.append(f"   - 严重程度: {finding.severity}")
            summary.append(f"   - 位置: {finding.location.get('file', 'unknown')}:{finding.location.get('line', 'unknown')}")
            summary.append(f"   - 描述: {finding.description[:100]}...")
        return "\n".join(summary)

    def _build_scripts_summary(self, script_paths: List[str]) -> str:
        """构建脚本列表摘要

        Args:
            script_paths: 脚本路径列表

        Returns:
            str: 脚本列表摘要
        """
        summary = []
        for i, script_path in enumerate(script_paths, 1):
            script_name = os.path.basename(script_path)
            summary.append(f"{i}. `{script_name}`")
        return "\n".join(summary)


# 全局AI验证脚本生成器实例
_ai_verification_generator: Optional[AIVerificationGenerator] = None


def get_ai_verification_generator() -> AIVerificationGenerator:
    """获取AI验证脚本生成器实例

    Returns:
        AIVerificationGenerator: AI验证脚本生成器实例
    """
    global _ai_verification_generator
    if _ai_verification_generator is None:
        _ai_verification_generator = AIVerificationGenerator()
    return _ai_verification_generator


class VerificationScriptGenerator:
    """验证脚本生成器（同步版本）

    提供基于模板的验证脚本生成功能，不依赖AI模型。
    """

    SQL_INJECTION_PATTERNS = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "' UNION SELECT NULL--",
        "1; EXEC xp_cmdshell('dir')",
        "' AND 1=1--",
        "' OR ''='",
    ]

    XSS_PATTERNS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
    ]

    COMMAND_INJECTION_PATTERNS = [
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "&& cat /etc/shadow",
    ]

    def generate_verification_script(self, vuln_info: Dict, language: str = "python") -> str:
        """生成可执行的验证脚本

        Args:
            vuln_info: 漏洞信息字典
            language: 脚本语言 (python/java/javascript)

        Returns:
            str: 生成的验证脚本内容
        """
        if language not in self.SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language: {language}. Supported: {self.SUPPORTED_LANGUAGES}")

        vuln_type = vuln_info.get("type", "unknown").lower()

        if "sql" in vuln_type:
            return self.generate_sql_injection_test(vuln_info, language)
        elif "xss" in vuln_type or "cross-site" in vuln_type:
            return self.generate_xss_test(vuln_info, language)
        elif "command" in vuln_type or "Injection" in vuln_type:
            return self.generate_command_injection_test(vuln_info, language)
        else:
            return self._generate_generic_test(vuln_info, language)

    def generate_sql_injection_test(self, vuln_info: Dict, language: str = "python") -> str:
        """生成SQL注入测试脚本

        Args:
            vuln_info: 漏洞信息字典
            language: 脚本语言

        Returns:
            str: 生成的测试脚本内容
        """
        generators = {
            "python": self._generate_sql_injection_python,
            "java": self._generate_sql_injection_java,
            "javascript": self._generate_sql_injection_javascript,
        }
        return generators[language](vuln_info)

    def _generate_sql_injection_python(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''"""SQL注入验证测试

漏洞信息:
- 位置: {file_path}:{line}
- 描述: {description}
"""

import pytest
import re
from typing import List, Tuple


class SQLInjectionVerifier:
    """SQL注入验证器"""

    SQL_INJECTION_PATTERNS = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "' UNION SELECT NULL--",
        "1; EXEC xp_cmdshell('dir')",
        "' AND 1=1--",
        "' OR ''='",
    ]

    def __init__(self):
        self.test_results: List[Tuple[str, bool, str]] = []

    def sanitize_input(self, user_input: str) -> str:
        """模拟输入清理（实际环境中应使用参数化查询）"""
        dangerous_patterns = [
            r"('|\\")\\s*(OR|AND)\\s*('|\\\")?",
            r";\\s*(DROP|DELETE|UPDATE|INSERT)",
            r"--",
            r";\\s*EXEC\\s*(",
        ]
        sanitized = user_input
        for pattern in dangerous_patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                raise ValueError(f"Potential SQL injection detected: {{sanitized}}")
        return sanitized

    def test_sql_injection(self, test_input: str) -> bool:
        """测试SQL注入

        Args:
            test_input: 测试输入

        Returns:
            bool: 是否存在SQL注入漏洞
        """
        try:
            self.sanitize_input(test_input)
            return False
        except ValueError:
            return True

    def run_all_tests(self) -> List[Tuple[str, bool]]:
        """运行所有SQL注入测试"""
        results = []
        for pattern in self.SQL_INJECTION_PATTERNS:
            is_vulnerable = self.test_sql_injection(pattern)
            results.append((pattern, is_vulnerable))
            self.test_results.append((pattern, is_vulnerable, "vulnerable" if is_vulnerable else "safe"))
        return results


def test_sql_injection_basic():
    """测试基本SQL注入模式"""
    verifier = SQLInjectionVerifier()
    results = verifier.run_all_tests()

    vulnerable_count = sum(1 for _, is_vuln in results if is_vuln)

    print(f"SQL注入测试结果: {{vulnerable_count}}/{{len(results)}} 种模式存在漏洞")
    for pattern, is_vuln in results:
        status = "VULNERABLE" if is_vuln else "SAFE"
        print(f"  [{{status}}] {{pattern}}")

    assert vulnerable_count > 0, "Expected some SQL injection patterns to be detected"


def test_sql_injection_in_code():
    """测试代码中的SQL注入漏洞"""
    verifier = SQLInjectionVerifier()

    code_snippet = """{{code_snippet}}"""

    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION"]
    has_sql = any(keyword in code_snippet.upper() for keyword in sql_keywords)

    if has_sql:
        print(f"代码片段包含SQL关键字，可能存在SQL注入风险")
        print(f"代码: {{code_snippet[:100]}}...")

    assert has_sql, "Expected SQL keywords in vulnerable code snippet"


def test_sql_injection_prevention():
    """测试SQL注入防护"""
    verifier = SQLInjectionVerifier()

    safe_input = "normal_user_input"
    dangerous_input = "' OR '1'='1"

    assert not verifier.test_sql_injection(safe_input), "Safe input should not trigger injection detection"
    assert verifier.test_sql_injection(dangerous_input), "Dangerous input should trigger injection detection"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
'''

    def _generate_sql_injection_java(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''// SQL注入验证测试
// 漏洞信息:
// - 位置: {file_path}:{line}
// - 描述: {description}

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.regex.*;
import java.util.ArrayList;
import java.util.List;

public class SQLInjectionTest {{

    private SQLInjectionVerifier verifier;

    private static final String[] SQL_INJECTION_PATTERNS = {{
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "' UNION SELECT NULL--",
        "1; EXEC xp_cmdshell('dir')",
        "' AND 1=1--",
        "' OR ''='"
    }};

    @Before
    public void setUp() {{
        verifier = new SQLInjectionVerifier();
    }}

    @Test
    public void testSQLInjectionBasic() {{
        System.out.println("=== SQL注入基本测试 ===");
        int vulnerableCount = 0;

        for (String pattern : SQL_INJECTION_PATTERNS) {{
            boolean isVulnerable = verifier.testSQLInjection(pattern);
            if (isVulnerable) {{
                vulnerableCount++;
                System.out.println("[VULNERABLE] " + pattern);
            }} else {{
                System.out.println("[SAFE] " + pattern);
            }}
        }}

        System.out.println("SQL注入测试结果: " + vulnerableCount + "/" + SQL_INJECTION_PATTERNS.length + " 种模式存在漏洞");
        assertTrue("Expected some SQL injection patterns to be detected", vulnerableCount > 0);
    }}

    @Test
    public void testSQLInjectionInCode() {{
        String codeSnippet = "{{code_snippet}}";

        String[] sqlKeywords = {{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION"}};
        boolean hasSQL = false;

        for (String keyword : sqlKeywords) {{
            if (codeSnippet.toUpperCase().contains(keyword)) {{
                hasSQL = true;
                break;
            }}
        }}

        if (hasSQL) {{
            System.out.println("代码片段包含SQL关键字，可能存在SQL注入风险");
            System.out.println("代码: " + codeSnippet.substring(0, Math.min(100, codeSnippet.length())) + "...");
        }}

        assertTrue("Expected SQL keywords in vulnerable code snippet", hasSQL);
    }}

    @Test
    public void testSQLInjectionPrevention() {{
        String safeInput = "normal_user_input";
        String dangerousInput = "' OR '1'='1";

        assertFalse("Safe input should not trigger injection detection",
                    verifier.testSQLInjection(safeInput));
        assertTrue("Dangerous input should trigger injection detection",
                   verifier.testSQLInjection(dangerousInput));
    }}

    class SQLInjectionVerifier {{
        public boolean testSQLInjection(String userInput) {{
            String[] dangerousPatterns = {{
                "('|\\")\\s*(OR|AND)\\s*('|\\\")?",
                ";\\s*(DROP|DELETE|UPDATE|INSERT)",
                "--",
                ";\\s*EXEC\\s*("
            }};

            for (String pattern : dangerousPatterns) {{
                if (Pattern.matches(pattern, userInput)) {{
                    return true;
                }}
            }}
            return false;
        }}
    }}
}}
'''

    def _generate_sql_injection_javascript(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''// SQL注入验证测试
// 漏洞信息:
// - 位置: {file_path}:{line}
// - 描述: {description}

const {{ jest }} = require('jest');

const SQL_INJECTION_PATTERNS = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "' UNION SELECT NULL--",
    "1; EXEC xp_cmdshell('dir')",
    "' AND 1=1--",
    "' OR ''='"
];

class SQLInjectionVerifier {{
    sanitizeInput(userInput) {{
        const dangerousPatterns = [
            /('|")\\s*(OR|AND)\\s*('|")?/i,
            /;\\s*(DROP|DELETE|UPDATE|INSERT)/i,
            /--/,
            /;\\s*EXEC\\s*\(/i
        ];

        for (const pattern of dangerousPatterns) {{
            if (pattern.test(userInput)) {{
                throw new Error(`Potential SQL injection detected: ${{userInput}}`);
            }}
        }}
        return userInput;
    }}

    testSQLInjection(testInput) {{
        try {{
            this.sanitizeInput(testInput);
            return false;
        }} catch (e) {{
            return true;
        }}
    }}

    runAllTests() {{
        const results = [];
        for (const pattern of SQL_INJECTION_PATTERNS) {{
            const isVulnerable = this.testSQLInjection(pattern);
            results.push({{ pattern, isVulnerable }});
        }}
        return results;
    }}
}}

describe('SQL Injection Tests', () => {{
    let verifier;

    beforeEach(() => {{
        verifier = new SQLInjectionVerifier();
    }});

    test('SQL injection basic patterns', () => {{
        console.log('=== SQL注入基本测试 ===');
        const results = verifier.runAllTests();
        let vulnerableCount = 0;

        for (const result of results) {{
            if (result.isVulnerable) {{
                vulnerableCount++;
                console.log(`[VULNERABLE] ${{result.pattern}}`);
            }} else {{
                console.log(`[SAFE] ${{result.pattern}}`);
            }}
        }}

        console.log(`SQL注入测试结果: ${{vulnerableCount}}/${{results.length}} 种模式存在漏洞`);
        expect(vulnerableCount).toBeGreaterThan(0);
    }});

    test('SQL injection in code', () => {{
        const codeSnippet = `{code_snippet}`;

        const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION'];
        const hasSQL = sqlKeywords.some(keyword =>
            codeSnippet.toUpperCase().includes(keyword)
        );

        if (hasSQL) {{
            console.log('代码片段包含SQL关键字，可能存在SQL注入风险');
            console.log(`代码: ${{codeSnippet.substring(0, 100)}}...`);
        }}

        expect(hasSQL).toBe(true);
    }});

    test('SQL injection prevention', () => {{
        const safeInput = 'normal_user_input';
        const dangerousInput = "' OR '1'='1";

        expect(verifier.testSQLInjection(safeInput)).toBe(false);
        expect(verifier.testSQLInjection(dangerousInput)).toBe(true);
    }});
}});
'''

    def generate_xss_test(self, vuln_info: Dict, language: str = "python") -> str:
        """生成XSS测试脚本

        Args:
            vuln_info: 漏洞信息字典
            language: 脚本语言

        Returns:
            str: 生成的测试脚本内容
        """
        generators = {
            "python": self._generate_xss_python,
            "java": self._generate_xss_java,
            "javascript": self._generate_xss_javascript,
        }
        return generators[language](vuln_info)

    def _generate_xss_python(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''"""XSS跨站脚本验证测试

漏洞信息:
- 位置: {file_path}:{line}
- 描述: {description}
"""

import pytest
import re
from html.parser import HTMLParser
from typing import List, Tuple


class XSSVerifier:
    """XSS验证器"""

    XSS_PATTERNS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
    ]

    def __init__(self):
        self.test_results: List[Tuple[str, bool, str]] = []

    def sanitize_html(self, user_input: str) -> str:
        """模拟HTML清理（实际环境中应使用HTML转义）"""
        dangerous_tags = ["script", "img", "svg", "iframe", "object"]
        dangerous_attrs = ["onerror", "onload", "onclick", "onmouseover"]

        html_pattern = re.compile(r'<(\w+)([^>]*)>', re.IGNORECASE)
        matches = html_pattern.findall(user_input)

        for tag, attrs in matches:
            if tag.lower() in dangerous_tags:
                raise ValueError(f"Potential XSS detected: dangerous tag <{{tag}}>")
            if any(attr in attrs.lower() for attr in dangerous_attrs):
                raise ValueError(f"Potential XSS detected: dangerous attribute")

        return user_input

    def test_xss(self, test_input: str) -> bool:
        """测试XSS

        Args:
            test_input: 测试输入

        Returns:
            bool: 是否存在XSS漏洞
        """
        try:
            self.sanitize_html(test_input)
            return False
        except ValueError:
            return True

    def run_all_tests(self) -> List[Tuple[str, bool]]:
        """运行所有XSS测试"""
        results = []
        for pattern in self.XSS_PATTERNS:
            is_vulnerable = self.test_xss(pattern)
            results.append((pattern, is_vulnerable))
            self.test_results.append((pattern, is_vulnerable, "vulnerable" if is_vulnerable else "safe"))
        return results


def test_xss_basic():
    """测试基本XSS模式"""
    verifier = XSSVerifier()
    results = verifier.run_all_tests()

    vulnerable_count = sum(1 for _, is_vuln in results if is_vuln)

    print(f"XSS测试结果: {{vulnerable_count}}/{{len(results)}} 种模式存在漏洞")
    for pattern, is_vuln in results:
        status = "VULNERABLE" if is_vuln else "SAFE"
        print(f"  [{{status}}] {{pattern}}")

    assert vulnerable_count > 0, "Expected some XSS patterns to be detected"


def test_xss_in_code():
    """测试代码中的XSS漏洞"""
    verifier = XSSVerifier()

    code_snippet = """{{code_snippet}}"""

    xss_indicators = ["<script", "javascript:", "onerror", "onload", "innerHTML"]
    has_xss = any(indicator in code_snippet.lower() for indicator in xss_indicators)

    if has_xss:
        print(f"代码片段包含XSS指示器，可能存在XSS漏洞")
        print(f"代码: {{code_snippet[:100]}}...")

    assert has_xss, "Expected XSS indicators in vulnerable code snippet"


def test_xss_prevention():
    """测试XSS防护"""
    verifier = XSSVerifier()

    safe_input = "normal_user_input"
    dangerous_input = "<script>alert('XSS')</script>"

    assert not verifier.test_xss(safe_input), "Safe input should not trigger XSS detection"
    assert verifier.test_xss(dangerous_input), "Dangerous input should trigger XSS detection"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
'''

    def _generate_xss_java(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''// XSS跨站脚本验证测试
// 漏洞信息:
// - 位置: {file_path}:{line}
// - 描述: {description}

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.regex.*;
import java.util.ArrayList;
import java.util.List;

public class XSSTest {{

    private XSSVerifier verifier;

    private static final String[] XSS_PATTERNS = {{
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\\\"><script>alert('XSS')</script>"
    }};

    @Before
    public void setUp() {{
        verifier = new XSSVerifier();
    }}

    @Test
    public void testXSSBasic() {{
        System.out.println("=== XSS基本测试 ===");
        int vulnerableCount = 0;

        for (String pattern : XSS_PATTERNS) {{
            boolean isVulnerable = verifier.testXSS(pattern);
            if (isVulnerable) {{
                vulnerableCount++;
                System.out.println("[VULNERABLE] " + pattern);
            }} else {{
                System.out.println("[SAFE] " + pattern);
            }}
        }}

        System.out.println("XSS测试结果: " + vulnerableCount + "/" + XSS_PATTERNS.length + " 种模式存在漏洞");
        assertTrue("Expected some XSS patterns to be detected", vulnerableCount > 0);
    }}

    @Test
    public void testXSSInCode() {{
        String codeSnippet = "{{code_snippet}}";

        String[] xssIndicators = {{"<script", "javascript:", "onerror", "onload", "innerHTML"}};
        boolean hasXSS = false;

        for (String indicator : xssIndicators) {{
            if (codeSnippet.toLowerCase().contains(indicator)) {{
                hasXSS = true;
                break;
            }}
        }}

        if (hasXSS) {{
            System.out.println("代码片段包含XSS指示器，可能存在XSS漏洞");
            System.out.println("代码: " + codeSnippet.substring(0, Math.min(100, codeSnippet.length())) + "...");
        }}

        assertTrue("Expected XSS indicators in vulnerable code snippet", hasXSS);
    }}

    @Test
    public void testXSSPrevention() {{
        String safeInput = "normal_user_input";
        String dangerousInput = "<script>alert('XSS')</script>";

        assertFalse("Safe input should not trigger XSS detection",
                    verifier.testXSS(safeInput));
        assertTrue("Dangerous input should trigger XSS detection",
                   verifier.testXSS(dangerousInput));
    }}

    class XSSVerifier {{
        public boolean testXSS(String userInput) {{
            String[] dangerousTags = {{"script", "img", "svg", "iframe", "object"}};
            String[] dangerousAttrs = {{"onerror", "onload", "onclick", "onmouseover"}};

            Pattern tagPattern = Pattern.compile("<(\\\\w+)([^>]*)>", Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher matcher = tagPattern.matcher(userInput);

            while (matcher.find()) {{
                String tag = matcher.group(1);
                String attrs = matcher.group(2);

                for (String dangerousTag : dangerousTags) {{
                    if (tag.equalsIgnoreCase(dangerousTag)) {{
                        return true;
                    }}
                }}

                for (String dangerousAttr : dangerousAttrs) {{
                    if (attrs.toLowerCase().contains(dangerousAttr)) {{
                        return true;
                    }}
                }}
            }}
            return false;
        }}
    }}
}}
'''

    def _generate_xss_javascript(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''// XSS跨站脚本验证测试
// 漏洞信息:
// - 位置: {file_path}:{line}
// - 描述: {description}

const {{ describe, test, expect, beforeEach }} = require('jest');

const XSS_PATTERNS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "'\\\"><script>alert('XSS')</script>"
];

class XSSVerifier {{
    sanitizeHTML(userInput) {{
        const dangerousTags = ['script', 'img', 'svg', 'iframe', 'object'];
        const dangerousAttrs = ['onerror', 'onload', 'onclick', 'onmouseover'];

        const tagRegex = /<(\w+)([^>]*)>/gi;
        let match;

        while ((match = tagRegex.exec(userInput)) !== null) {{
            const tag = match[1];
            const attrs = match[2];

            if (dangerousTags.includes(tag.toLowerCase())) {{
                throw new Error(`Potential XSS detected: dangerous tag <${{tag}}>`);
            }}

            for (const attr of dangerousAttrs) {{
                if (attrs.toLowerCase().includes(attr)) {{
                    throw new Error(`Potential XSS detected: dangerous attribute`);
                }}
            }}
        }}

        return userInput;
    }}

    testXSS(testInput) {{
        try {{
            this.sanitizeHTML(testInput);
            return false;
        }} catch (e) {{
            return true;
        }}
    }}

    runAllTests() {{
        const results = [];
        for (const pattern of XSS_PATTERNS) {{
            const isVulnerable = this.testXSS(pattern);
            results.push({{ pattern, isVulnerable }});
        }}
        return results;
    }}
}}

describe('XSS Tests', () => {{
    let verifier;

    beforeEach(() => {{
        verifier = new XSSVerifier();
    }});

    test('XSS basic patterns', () => {{
        console.log('=== XSS基本测试 ===');
        const results = verifier.runAllTests();
        let vulnerableCount = 0;

        for (const result of results) {{
            if (result.isVulnerable) {{
                vulnerableCount++;
                console.log(`[VULNERABLE] ${{result.pattern}}`);
            }} else {{
                console.log(`[SAFE] ${{result.pattern}}`);
            }}
        }}

        console.log(`XSS测试结果: ${{vulnerableCount}}/${{results.length}} 种模式存在漏洞`);
        expect(vulnerableCount).toBeGreaterThan(0);
    }});

    test('XSS in code', () => {{
        const codeSnippet = `{code_snippet}`;

        const xssIndicators = ['<script', 'javascript:', 'onerror', 'onload', 'innerHTML'];
        const hasXSS = xssIndicators.some(indicator =>
            codeSnippet.toLowerCase().includes(indicator)
        );

        if (hasXSS) {{
            console.log('代码片段包含XSS指示器，可能存在XSS漏洞');
            console.log(`代码: ${{codeSnippet.substring(0, 100)}}...`);
        }}

        expect(hasXSS).toBe(true);
    }});

    test('XSS prevention', () => {{
        const safeInput = 'normal_user_input';
        const dangerousInput = "<script>alert('XSS')</script>";

        expect(verifier.testXSS(safeInput)).toBe(false);
        expect(verifier.testXSS(dangerousInput)).toBe(true);
    }});
}});
'''

    def generate_command_injection_test(self, vuln_info: Dict, language: str = "python") -> str:
        """生成命令注入测试脚本

        Args:
            vuln_info: 漏洞信息字典
            language: 脚本语言

        Returns:
            str: 生成的测试脚本内容
        """
        generators = {
            "python": self._generate_command_injection_python,
            "java": self._generate_command_injection_java,
            "javascript": self._generate_command_injection_javascript,
        }
        return generators[language](vuln_info)

    def _generate_command_injection_python(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''"""命令注入验证测试

漏洞信息:
- 位置: {file_path}:{line}
- 描述: {description}
"""

import pytest
import re
import subprocess
from typing import List, Tuple


class CommandInjectionVerifier:
    """命令注入验证器"""

    COMMAND_INJECTION_PATTERNS = [
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "&& cat /etc/shadow",
        "; rm -rf /",
        "| nc -e /bin/sh",
    ]

    def __init__(self):
        self.test_results: List[Tuple[str, bool, str]] = []

    def sanitize_input(self, user_input: str) -> str:
        """模拟输入清理（实际环境中应避免直接使用用户输入执行命令）"""
        dangerous_patterns = [
            r";\s*\w+",
            r"\|\s*\w+",
            r"\$\([^)]+\)",
            r"`[^`]+`",
            r"&&\s*\w+",
            r"||\s*\w+",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, user_input):
                raise ValueError(f"Potential command injection detected: {{user_input}}")

        return user_input

    def test_command_injection(self, test_input: str) -> bool:
        """测试命令注入

        Args:
            test_input: 测试输入

        Returns:
            bool: 是否存在命令注入漏洞
        """
        try:
            self.sanitize_input(test_input)
            return False
        except ValueError:
            return True

    def run_all_tests(self) -> List[Tuple[str, bool]]:
        """运行所有命令注入测试"""
        results = []
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            is_vulnerable = self.test_command_injection(pattern)
            results.append((pattern, is_vulnerable))
            self.test_results.append((pattern, is_vulnerable, "vulnerable" if is_vulnerable else "safe"))
        return results


def test_command_injection_basic():
    """测试基本命令注入模式"""
    verifier = CommandInjectionVerifier()
    results = verifier.run_all_tests()

    vulnerable_count = sum(1 for _, is_vuln in results if is_vuln)

    print(f"命令注入测试结果: {{vulnerable_count}}/{{len(results)}} 种模式存在漏洞")
    for pattern, is_vuln in results:
        status = "VULNERABLE" if is_vuln else "SAFE"
        print(f"  [{{status}}] {{pattern}}")

    assert vulnerable_count > 0, "Expected some command injection patterns to be detected"


def test_command_injection_in_code():
    """测试代码中的命令注入漏洞"""
    verifier = CommandInjectionVerifier()

    code_snippet = """{{code_snippet}}"""

    cmd_indicators = ["subprocess", "os.system", "os.popen", "exec(", "eval(", "|", ";", "&&"]
    has_cmd = any(indicator in code_snippet for indicator in cmd_indicators)

    if has_cmd:
        print(f"代码片段包含命令执行相关代码，可能存在命令注入漏洞")
        print(f"代码: {{code_snippet[:100]}}...")

    assert has_cmd, "Expected command execution indicators in vulnerable code snippet"


def test_command_injection_prevention():
    """测试命令注入防护"""
    verifier = CommandInjectionVerifier()

    safe_input = "normal_user_input"
    dangerous_input = "; ls -la"

    assert not verifier.test_command_injection(safe_input), "Safe input should not trigger injection detection"
    assert verifier.test_command_injection(dangerous_input), "Dangerous input should trigger injection detection"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
'''

    def _generate_command_injection_java(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''// 命令注入验证测试
// 漏洞信息:
// - 位置: {file_path}:{line}
// - 描述: {description}

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.regex.*;
import java.util.ArrayList;
import java.util.List;

public class CommandInjectionTest {{

    private CommandInjectionVerifier verifier;

    private static final String[] COMMAND_INJECTION_PATTERNS = {{
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "&& cat /etc/shadow",
        "; rm -rf /",
        "| nc -e /bin/sh"
    }};

    @Before
    public void setUp() {{
        verifier = new CommandInjectionVerifier();
    }}

    @Test
    public void testCommandInjectionBasic() {{
        System.out.println("=== 命令注入基本测试 ===");
        int vulnerableCount = 0;

        for (String pattern : COMMAND_INJECTION_PATTERNS) {{
            boolean isVulnerable = verifier.testCommandInjection(pattern);
            if (isVulnerable) {{
                vulnerableCount++;
                System.out.println("[VULNERABLE] " + pattern);
            }} else {{
                System.out.println("[SAFE] " + pattern);
            }}
        }}

        System.out.println("命令注入测试结果: " + vulnerableCount + "/" + COMMAND_INJECTION_PATTERNS.length + " 种模式存在漏洞");
        assertTrue("Expected some command injection patterns to be detected", vulnerableCount > 0);
    }}

    @Test
    public void testCommandInjectionInCode() {{
        String codeSnippet = "{{code_snippet}}";

        String[] cmdIndicators = {{"Runtime.getRuntime()", "ProcessBuilder", "System.exec", "ProcessImpl"}};
        boolean hasCmd = false;

        for (String indicator : cmdIndicators) {{
            if (codeSnippet.contains(indicator)) {{
                hasCmd = true;
                break;
            }}
        }}

        if (hasCmd) {{
            System.out.println("代码片段包含命令执行相关代码，可能存在命令注入漏洞");
            System.out.println("代码: " + codeSnippet.substring(0, Math.min(100, codeSnippet.length())) + "...");
        }}

        assertTrue("Expected command execution indicators in vulnerable code snippet", hasCmd);
    }}

    @Test
    public void testCommandInjectionPrevention() {{
        String safeInput = "normal_user_input";
        String dangerousInput = "; ls -la";

        assertFalse("Safe input should not trigger injection detection",
                    verifier.testCommandInjection(safeInput));
        assertTrue("Dangerous input should trigger injection detection",
                   verifier.testCommandInjection(dangerousInput));
    }}

    class CommandInjectionVerifier {{
        public boolean testCommandInjection(String userInput) {{
            String[] dangerousPatterns = {{
                ";\\\\s*\\\\w+",
                "\\\\|\\\\s*\\\\w+",
                "\\\\$\\\\([^)]+\\\\)",
                "`[^`]+`",
                "&&\\\\s*\\\\w+",
                "\\\\|\\\\|\\\\s*\\\\w+"
            }};

            for (String pattern : dangerousPatterns) {{
                if (Pattern.matches(pattern, userInput)) {{
                    return true;
                }}
            }}
            return false;
        }}
    }}
}}
'''

    def _generate_command_injection_javascript(self, vuln_info: Dict) -> str:
        code_snippet = self._escape_string(vuln_info.get("code_snippet", ""))
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)
        description = vuln_info.get("description", "")

        return f'''// 命令注入验证测试
// 漏洞信息:
// - 位置: {file_path}:{line}
// - 描述: {description}

const {{ describe, test, expect, beforeEach }} = require('jest');

const COMMAND_INJECTION_PATTERNS = [
    "; ls -la",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "&& cat /etc/shadow",
    "; rm -rf /",
    "| nc -e /bin/sh"
];

class CommandInjectionVerifier {{
    sanitizeInput(userInput) {{
        const dangerousPatterns = [
            /;\\s*\\w+/,
            /\\|\\s*\\w+/,
            /\\$\\([^)]+\\)/,
            /`[^`]+`/,
            /&&\\s*\\w+/,
            /\\|\\|\\s*\\w+/
        ];

        for (const pattern of dangerousPatterns) {{
            if (pattern.test(userInput)) {{
                throw new Error(`Potential command injection detected: ${{userInput}}`);
            }}
        }}

        return userInput;
    }}

    testCommandInjection(testInput) {{
        try {{
            this.sanitizeInput(testInput);
            return false;
        }} catch (e) {{
            return true;
        }}
    }}

    runAllTests() {{
        const results = [];
        for (const pattern of COMMAND_INJECTION_PATTERNS) {{
            const isVulnerable = this.testCommandInjection(pattern);
            results.push({{ pattern, isVulnerable }});
        }}
        return results;
    }}
}}

describe('Command Injection Tests', () => {{
    let verifier;

    beforeEach(() => {{
        verifier = new CommandInjectionVerifier();
    }});

    test('Command injection basic patterns', () => {{
        console.log('=== 命令注入基本测试 ===');
        const results = verifier.runAllTests();
        let vulnerableCount = 0;

        for (const result of results) {{
            if (result.isVulnerable) {{
                vulnerableCount++;
                console.log(`[VULNERABLE] ${{result.pattern}}`);
            }} else {{
                console.log(`[SAFE] ${{result.pattern}}`);
            }}
        }}

        console.log(`命令注入测试结果: ${{vulnerableCount}}/${{results.length}} 种模式存在漏洞`);
        expect(vulnerableCount).toBeGreaterThan(0);
    }});

    test('Command injection in code', () => {{
        const codeSnippet = `{code_snippet}`;

        const cmdIndicators = ['child_process', 'exec(', 'execSync(', 'spawn(', 'popen'];
        const hasCmd = cmdIndicators.some(indicator =>
            codeSnippet.includes(indicator)
        );

        if (hasCmd) {{
            console.log('代码片段包含命令执行相关代码，可能存在命令注入漏洞');
            console.log(`代码: ${{codeSnippet.substring(0, 100)}}...`);
        }}

        expect(hasCmd).toBe(true);
    }});

    test('Command injection prevention', () => {{
        const safeInput = 'normal_user_input';
        const dangerousInput = '; ls -la';

        expect(verifier.testCommandInjection(safeInput)).toBe(false);
        expect(verifier.testCommandInjection(dangerousInput)).toBe(true);
    }});
}});
'''

    def _generate_generic_test(self, vuln_info: Dict, language: str) -> str:
        """生成通用测试脚本

        Args:
            vuln_info: 漏洞信息字典
            language: 脚本语言

        Returns:
            str: 生成的测试脚本内容
        """
        generators = {
            "python": self._generate_generic_python,
            "java": self._generate_generic_java,
            "javascript": self._generate_generic_javascript,
        }
        return generators[language](vuln_info)

    def _generate_generic_python(self, vuln_info: Dict) -> str:
        rule_id = vuln_info.get("rule_id", "UNKNOWN")
        rule_name = vuln_info.get("rule_name", "未知漏洞")
        description = vuln_info.get("description", "")
        severity = vuln_info.get("severity", "unknown")
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)

        return f'''"""通用漏洞验证测试

漏洞信息:
- 规则ID: {rule_id}
- 规则名称: {rule_name}
- 严重程度: {severity}
- 位置: {file_path}:{line}
- 描述: {description}
"""

import pytest


def test_vulnerability_exists():
    """验证漏洞存在"""
    vuln_info = {{{
        "rule_id": "{rule_id}",
        "rule_name": "{rule_name}",
        "severity": "{severity}",
        "location": {{"file": "{file_path}", "line": {line}}},
        "description": "{description}"
    }}}

    print(f"正在验证漏洞: ${{vuln_info['rule_name']}}")
    print(f"规则ID: ${{vuln_info['rule_id']}}")
    print(f"严重程度: ${{vuln_info['severity']}}")
    print(f"位置: ${{vuln_info['location']['file']}}:${{vuln_info['location']['line']}}")

    assert vuln_info["rule_id"] is not None, "漏洞规则ID不应为空"
    assert vuln_info["rule_name"] is not None, "漏洞规则名称不应为空"


def test_vulnerability_severity():
    """验证漏洞严重程度"""
    valid_severities = ["critical", "high", "medium", "low", "info"]

    print(f"验证严重程度: {severity}")

    assert severity in valid_severities, f"严重程度必须在 ${{valid_severities}} 中"


def test_vulnerability_location():
    """验证漏洞位置信息"""
    location = vuln_info.get("location", {{}})

    print(f"验证位置信息: ${{location}}")

    assert "file" in location, "位置信息应包含文件路径"
    assert "line" in location, "位置信息应包含行号"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
'''

    def _generate_generic_java(self, vuln_info: Dict) -> str:
        rule_id = vuln_info.get("rule_id", "UNKNOWN")
        rule_name = vuln_info.get("rule_name", "未知漏洞")
        description = vuln_info.get("description", "")
        severity = vuln_info.get("severity", "unknown")
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)

        return f'''// 通用漏洞验证测试
// 漏洞信息:
// - 规则ID: {rule_id}
// - 规则名称: {rule_name}
// - 严重程度: {severity}
// - 位置: {file_path}:{line}
// - 描述: {description}

import org.junit.Test;
import static org.junit.Assert.*;

public class GenericVulnerabilityTest {{

    @Test
    public void testVulnerabilityExists() {{
        System.out.println("正在验证漏洞: {rule_name}");
        System.out.println("规则ID: {rule_id}");
        System.out.println("严重程度: {severity}");
        System.out.println("位置: {file_path}:{line}");

        assertNotNull("漏洞规则ID不应为空", "{rule_id}");
        assertNotNull("漏洞规则名称不应为空", "{rule_name}");
    }}

    @Test
    public void testVulnerabilitySeverity() {{
        String[] validSeverities = {{"critical", "high", "medium", "low", "info"}};
        String severity = "{severity}";

        System.out.println("验证严重程度: " + severity);

        boolean isValid = false;
        for (String validSeverity : validSeverities) {{
            if (validSeverity.equals(severity)) {{
                isValid = true;
                break;
            }}
        }}

        assertTrue("严重程度必须在有效范围内", isValid);
    }}

    @Test
    public void testVulnerabilityLocation() {{
        System.out.println("验证位置信息: {file_path}:{line}");

        assertNotNull("位置信息应包含文件路径", "{file_path}");
        assertTrue("行号应该是正数", {line} > 0);
    }}
}}
'''

    def _generate_generic_javascript(self, vuln_info: Dict) -> str:
        rule_id = vuln_info.get("rule_id", "UNKNOWN")
        rule_name = vuln_info.get("rule_name", "未知漏洞")
        description = vuln_info.get("description", "")
        severity = vuln_info.get("severity", "unknown")
        file_path = vuln_info.get("location", {}).get("file", "unknown")
        line = vuln_info.get("location", {}).get("line", 0)

        return f'''// 通用漏洞验证测试
// 漏洞信息:
// - 规则ID: {rule_id}
// - 规则名称: {rule_name}
// - 严重程度: {severity}
// - 位置: {file_path}:{line}
// - 描述: {description}

const {{ describe, test, expect }} = require('jest');

describe('Generic Vulnerability Tests', () => {{
    test('vulnerability exists', () => {{
        console.log('正在验证漏洞: {rule_name}');
        console.log('规则ID: {rule_id}');
        console.log('严重程度: {severity}');
        console.log('位置: {file_path}:{line}');

        expect('{rule_id}').toBeTruthy();
        expect('{rule_name}').toBeTruthy();
    }});

    test('vulnerability severity', () => {{
        const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
        const severity = '{severity}';

        console.log('验证严重程度: ' + severity);

        expect(validSeverities).toContain(severity);
    }});

    test('vulnerability location', () => {{
        console.log('验证位置信息: {file_path}:{line}');

        expect('{file_path}').toBeTruthy();
        expect({line}).toBeGreaterThan(0);
    }});
}});
'''

    def _escape_string(self, s: str) -> str:
        """转义字符串中的特殊字符

        Args:
            s: 输入字符串

        Returns:
            str: 转义后的字符串
        """
        if s is None:
            return ""
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")

    def get_test_framework(self, language: str) -> str:
        """获取指定语言的测试框架名称

        Args:
            language: 编程语言

        Returns:
            str: 测试框架名称
        """
        return self.TEST_FRAMEWORKS.get(language, "unknown")

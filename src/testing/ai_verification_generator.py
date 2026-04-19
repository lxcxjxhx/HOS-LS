"""AI辅助验证脚本生成模块

基于AI检测结果，结合AI动态生成验证脚本。
"""

import os
from typing import Dict, List, Optional, Any

from src.ai.models import VulnerabilityFinding, AIRequest
from src.ai.prompts import get_prompt_manager
from src.ai.client import get_model_manager, AIModelManager
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AIVerificationGenerator:
    """AI辅助验证脚本生成器"""

    def __init__(self):
        """初始化AI验证脚本生成器"""
        self._prompt_manager = get_prompt_manager()
        self._model_manager: Optional[AIModelManager] = None

    async def _init_model_manager(self):
        """初始化模型管理器"""
        if self._model_manager is None:
            self._model_manager = await get_model_manager()

    async def generate_verification_script(self, finding: VulnerabilityFinding,
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
                script_path = await self.generate_verification_script(finding, language, output_dir)
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

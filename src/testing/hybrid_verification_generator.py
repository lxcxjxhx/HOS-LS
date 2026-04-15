"""混合验证脚本生成模块

结合固定模板和AI动态生成的验证脚本生成器。
"""

import os
from typing import Dict, List, Optional, Any

from src.ai.models import VulnerabilityFinding
from src.testing.verification_script_generator import get_verification_generator
from src.testing.ai_verification_generator import get_ai_verification_generator
from src.utils.logger import get_logger

logger = get_logger(__name__)


class HybridVerificationGenerator:
    """混合验证脚本生成器"""

    def __init__(self):
        """初始化混合验证脚本生成器"""
        self._template_generator = get_verification_generator()
        self._ai_generator = get_ai_verification_generator()

    async def generate_verification_script(self, finding: VulnerabilityFinding,
                                            mode: str = "hybrid",
                                            language: str = "python",
                                            output_dir: str = "./verification_scripts") -> str:
        """生成验证脚本

        Args:
            finding: 漏洞发现
            mode: 生成模式 (template, ai, hybrid)
            language: 脚本语言
            output_dir: 输出目录

        Returns:
            str: 生成的脚本路径
        """
        try:
            if mode == "template":
                # 只使用模板
                logger.info("Using template-only mode for verification script generation")
                return self._template_generator.generate_script(finding, language, output_dir)
            
            elif mode == "ai":
                # 只使用AI
                logger.info("Using AI-only mode for verification script generation")
                return await self._ai_generator.generate_verification_script(finding, language, output_dir)
            
            else:
                # 混合模式：先尝试AI，如果失败则使用模板
                logger.info("Using hybrid mode for verification script generation")
                try:
                    script_path = await self._ai_generator.generate_verification_script(finding, language, output_dir)
                    if script_path:
                        return script_path
                except Exception as e:
                    logger.warning(f"AI generation failed, falling back to template: {e}")
                
                return self._template_generator.generate_script(finding, language, output_dir)
                
        except Exception as e:
            logger.error(f"Failed to generate verification script: {e}")
            return ""

    async def generate_scripts_for_findings(self, findings: List[VulnerabilityFinding],
                                             mode: str = "hybrid",
                                             language: str = "python",
                                             output_dir: str = "./verification_scripts") -> List[str]:
        """为多个漏洞发现生成验证脚本

        Args:
            findings: 漏洞发现列表
            mode: 生成模式
            language: 脚本语言
            output_dir: 输出目录

        Returns:
            List[str]: 生成的脚本路径列表
        """
        script_paths = []
        
        for finding in findings:
            # 只为高危漏洞生成脚本
            if finding.severity in ["critical", "high"]:
                script_path = await self.generate_verification_script(finding, mode, language, output_dir)
                if script_path:
                    script_paths.append(script_path)
        
        return script_paths

    async def generate_readme(self, findings: List[VulnerabilityFinding],
                               script_paths: List[str],
                               mode: str = "hybrid",
                               output_dir: str = "./verification_scripts") -> str:
        """生成README文件

        Args:
            findings: 漏洞发现列表
            script_paths: 脚本路径列表
            mode: 生成模式
            output_dir: 输出目录

        Returns:
            str: README文件路径
        """
        try:
            if mode == "template":
                # 使用模板生成README
                return self._template_generator.generate_readme(findings, script_paths, output_dir)
            
            elif mode == "ai":
                # 使用AI生成README
                return await self._ai_generator.generate_readme(findings, script_paths, output_dir)
            
            else:
                # 混合模式：先尝试AI，如果失败则使用模板
                try:
                    readme_path = await self._ai_generator.generate_readme(findings, script_paths, output_dir)
                    if readme_path:
                        return readme_path
                except Exception as e:
                    logger.warning(f"AI README generation failed, falling back to template: {e}")
                
                return self._template_generator.generate_readme(findings, script_paths, output_dir)
                
        except Exception as e:
            logger.error(f"Failed to generate README: {e}")
            return ""


# 全局混合验证脚本生成器实例
_hybrid_verification_generator: Optional[HybridVerificationGenerator] = None


def get_hybrid_verification_generator() -> HybridVerificationGenerator:
    """获取混合验证脚本生成器实例

    Returns:
        HybridVerificationGenerator: 混合验证脚本生成器实例
    """
    global _hybrid_verification_generator
    if _hybrid_verification_generator is None:
        _hybrid_verification_generator = HybridVerificationGenerator()
    return _hybrid_verification_generator

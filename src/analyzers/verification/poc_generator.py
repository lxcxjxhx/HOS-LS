"""AI POC 生成器 - 适配层

作为 src.pentest.poc.ai_poc_generator.AIPocGenerator 的 facade/adapter。
保持与现有调用方兼容的公共接口，内部完全委托给新的 AI POC 生成系统。
无任何硬编码模板、VULN_TYPE_PATTERNS 或漏洞类型 if-else 分支。
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

from .interfaces import VulnContext
from .method_storage import MethodStorage, MethodDefinition

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 延迟导入新的 AI POC 生成器
# ---------------------------------------------------------------------------
_AIPocGenerator = None
_AI_POC_IMPORT_ERROR = None

try:
    from src.pentest.poc.ai_poc_generator import (
        AIPocGenerator as _AIPocGenerator,
        PocGenerationResult,
    )
except ImportError as e:
    _AI_POC_IMPORT_ERROR = str(e)
    logger.warning(
        f"无法导入新的 AI POC 生成器: {_AI_POC_IMPORT_ERROR}。"
        f"所有 POC 操作将返回失败结果。"
    )


class AIPOCGenerator:
    """AI POC 验证脚本生成器（Facade / Adapter）

    公共接口与旧版完全兼容，内部完全委托给新的 AI 驱动 POC 生成系统。
    """

    def __init__(self, method_storage: MethodStorage, pocs_output_path: str, ai_client=None):
        """
        Args:
            method_storage: 方法存储实例
            pocs_output_path: POC 文件输出目录
            ai_client: AI 客户端实例（传递给底层 AIPocGenerator）
        """
        self.method_storage = method_storage
        self.pocs_output_path = Path(pocs_output_path)
        self.pocs_output_path.mkdir(parents=True, exist_ok=True)
        self._poc_classes_cache: Dict[str, type] = {}

        # 初始化底层 AI POC 生成器
        if _AIPocGenerator is not None:
            self._ai_poc_gen = _AIPocGenerator(ai_client=ai_client)
        else:
            self._ai_poc_gen = None
            logger.warning(
                "AI POC 生成器不可用: %s。所有 POC 生成操作将返回失败。",
                _AI_POC_IMPORT_ERROR,
            )

    # ------------------------------------------------------------------ #
    #  公开接口（保持与旧版兼容）
    # ------------------------------------------------------------------ #

    def generate_poc(self, context: VulnContext, validator_name: str = None) -> str:
        """为漏洞生成 POC 验证脚本

        Args:
            context: 漏洞上下文
            validator_name: 验证器名称（可选）

        Returns:
            POC 方法ID（存储在 method_storage 中），失败时返回空字符串
        """
        if self._ai_poc_gen is None:
            logger.warning("POC 生成失败: AI POC 生成器不可用")
            return ""

        # 新系统是 async 的，在同步上下文中运行
        result = self._run_async(
            self._ai_poc_gen.generate_poc(context, validator_name)
        )

        if not result or not result.success:
            error_msg = result.error if result else "Unknown error"
            logger.warning("POC 生成失败: %s", error_msg)
            return ""

        # 将结果存入 method_storage
        method_id = result.method_id
        method_def = MethodDefinition(
            id=method_id,
            name=f"{context.vuln_type.replace('_', ' ').title()} POC - {context.file_path}:{context.line_number}",
            vuln_type=context.vuln_type,
            pattern="ai_generated",
            confidence_level='high',
            validation={
                'type': 'ai_generated',
                'steps': []
            },
            poc_template=result.poc_code,
            evidence_required=['code_snippet', 'file_path'],
            metadata={
                'file_path': context.file_path,
                'line_number': context.line_number,
                'validator_name': validator_name,
                'generated_by': 'AIPOCGenerator (AI-driven)',
                'generation_time': result.generation_time,
                **result.metadata,
            }
        )

        self.method_storage.save_method(method_id, method_def)

        # 保存 POC 文件
        self._save_poc_file(method_id, result.poc_code, context)

        return method_id

    def generate_verification_steps(self, context: VulnContext) -> List[str]:
        """生成验证步骤（人工验证用）

        委托给 AI 动态生成，不再使用硬编码 if-else。

        Args:
            context: 漏洞上下文

        Returns:
            步骤列表
        """
        # 基于漏洞上下文返回通用验证框架
        # 详细步骤由 AI 在生成 POC 时内嵌到脚本中
        return [
            f"1. 检查 {context.file_path}:{context.line_number} 处的代码",
            f"2. 分析 {context.vuln_type} 漏洞上下文和触发条件",
            "3. 执行 AI 生成的 POC 验证脚本",
            "4. 确认漏洞可利用性",
            "5. 评估影响范围",
        ]

    def execute_poc(self, poc_method_id: str, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行生成的 POC

        Args:
            poc_method_id: POC 方法ID
            target: 目标 URL
            params: 额外参数

        Returns:
            执行结果
        """
        method = self.method_storage.load_method(poc_method_id)
        if method is None:
            return {'error': f'Method not found: {poc_method_id}'}

        poc_code = method.poc_template
        if not poc_code:
            return {'error': 'POC code is empty', 'executed': False}

        if params is None:
            params = {}

        try:
            result = self._execute_poc_code(poc_code, method.vuln_type, target, params)
            return result
        except Exception as e:
            return {
                'error': str(e),
                'executed': False,
                'poc_method_id': poc_method_id,
                'target': target
            }

    # ------------------------------------------------------------------ #
    #  辅助方法
    # ------------------------------------------------------------------ #

    @staticmethod
    def _run_async(coro):
        """在同步上下文中运行 async coroutine"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # 在已有的事件循环中（如 Jupyter），使用 nest_asyncio 或新策略
                import nest_asyncio
                nest_asyncio.apply()
                return loop.run_until_complete(coro)
        except RuntimeError:
            pass
        return asyncio.run(coro)

    def _execute_poc_code(self, poc_code: str, vuln_type: str, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """动态执行 POC 代码

        Args:
            poc_code: POC 代码字符串
            vuln_type: 漏洞类型
            target: 目标 URL
            params: 额外参数

        Returns:
            执行结果
        """
        import json
        import subprocess
        import sys
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(poc_code)
            temp_file = f.name

        try:
            result = subprocess.run(
                [sys.executable, temp_file, '--target', target, '--vuln-type', vuln_type],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {
                        'output': result.stdout,
                        'executed': True,
                        'returncode': result.returncode
                    }
            else:
                return {
                    'error': result.stderr,
                    'executed': False,
                    'returncode': result.returncode
                }
        except subprocess.TimeoutExpired:
            return {'error': 'POC execution timeout', 'executed': False}
        except Exception as e:
            return {'error': str(e), 'executed': False}
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def _save_poc_file(self, method_id: str, poc_code: str, context: VulnContext):
        """保存 POC 文件到磁盘"""
        vuln_type = context.vuln_type
        type_dir = self.pocs_output_path / vuln_type
        type_dir.mkdir(parents=True, exist_ok=True)

        poc_file = type_dir / f"{method_id}.py"
        with open(poc_file, 'w', encoding='utf-8') as f:
            f.write(poc_code)

    def list_generated_pocs(self, vuln_type: str = None) -> List[Dict[str, str]]:
        """列出已生成的 POC

        Args:
            vuln_type: 漏洞类型过滤（可选）

        Returns:
            POC 信息列表
        """
        pocs = []

        if vuln_type:
            type_dir = self.pocs_output_path / vuln_type
            if type_dir.exists():
                for poc_file in type_dir.glob("*.py"):
                    pocs.append({
                        'method_id': poc_file.stem,
                        'file_path': str(poc_file),
                        'vuln_type': vuln_type
                    })
        else:
            for type_dir in self.pocs_output_path.iterdir():
                if type_dir.is_dir():
                    for poc_file in type_dir.glob("*.py"):
                        pocs.append({
                            'method_id': poc_file.stem,
                            'file_path': str(poc_file),
                            'vuln_type': type_dir.name
                        })

        return pocs

    def get_poc_script(self, poc_method_id: str) -> Optional[str]:
        """获取 POC 脚本内容

        Args:
            poc_method_id: POC 方法ID

        Returns:
            POC 脚本内容
        """
        method = self.method_storage.load_method(poc_method_id)
        if method is None:
            return None
        return method.poc_template

"""AI 语义引擎

提供函数级、文件级、项目级的分层语义分析。
"""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.ai.analyzer import AIAnalyzer, AnalysisContext
from src.ai.models import AnalysisLevel, SecurityAnalysisResult
from src.core.config import Config, get_config


@dataclass
class SemanticContext:
    """语义上下文"""

    file_path: str
    language: str
    functions: List[Dict[str, Any]] = field(default_factory=list)
    classes: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    data_flow: List[Dict[str, Any]] = field(default_factory=list)


class SemanticEngine:
    """AI 语义引擎

    提供分层语义分析功能。
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()
        self._analyzer = AIAnalyzer(config)

    async def initialize(self) -> None:
        """初始化引擎"""
        await self._analyzer.initialize()

    async def close(self) -> None:
        """关闭引擎"""
        await self._analyzer.close()

    async def analyze_function(
        self,
        file_path: str,
        function_name: str,
        function_code: str,
        language: str,
        class_name: Optional[str] = None,
    ) -> SecurityAnalysisResult:
        """分析函数级别"""
        context = AnalysisContext(
            file_path=file_path,
            code_content=function_code,
            language=language,
            function_name=function_name,
            class_name=class_name,
            analysis_level=AnalysisLevel.FUNCTION,
        )
        return await self._analyzer.analyze(context)

    async def analyze_file(
        self,
        file_path: str,
        file_content: str,
        language: str,
    ) -> SecurityAnalysisResult:
        """分析文件级别"""
        context = AnalysisContext(
            file_path=file_path,
            code_content=file_content,
            language=language,
            analysis_level=AnalysisLevel.FILE,
        )

        file_result = await self._analyzer.analyze(context)

        # 提取函数并逐个分析
        functions = self._extract_functions(file_content, language)

        if functions:
            function_contexts = [
                AnalysisContext(
                    file_path=file_path,
                    code_content=func["code"],
                    language=language,
                    function_name=func["name"],
                    class_name=func.get("class_name"),
                    analysis_level=AnalysisLevel.FUNCTION,
                )
                for func in functions
            ]

            function_results = await self._analyzer.analyze_batch(
                function_contexts, max_concurrent=self.config.scan.max_workers
            )

            for func_result in function_results:
                file_result.findings.extend(func_result.findings)
                file_result.false_positives.extend(func_result.false_positives)

        file_result.risk_score = self._calculate_combined_risk_score(file_result)
        return file_result

    async def analyze_project(
        self,
        project_path: str,
        files: List[Dict[str, Any]],
    ) -> SecurityAnalysisResult:
        """分析项目级别"""
        file_results = []

        for file_info in files:
            result = await self.analyze_file(
                file_info["path"],
                file_info["content"],
                file_info["language"],
            )
            file_results.append(result)

        combined_result = SecurityAnalysisResult(
            findings=[],
            false_positives=[],
            risk_score=0.0,
            summary="",
            recommendations=[],
            metadata={"project_path": project_path, "files_analyzed": len(files)},
        )

        for result in file_results:
            combined_result.findings.extend(result.findings)
            combined_result.false_positives.extend(result.false_positives)
            combined_result.recommendations.extend(result.recommendations)

        combined_result.findings = self._deduplicate_findings(combined_result.findings)
        combined_result.risk_score = self._calculate_combined_risk_score(combined_result)
        combined_result.summary = self._generate_project_summary(combined_result, len(files))

        return combined_result

    def _extract_functions(self, file_content: str, language: str) -> List[Dict[str, Any]]:
        """提取函数定义"""
        functions = []

        if language == "python":
            import re

            pattern = r"(class\s+(\w+)[\s\S]*?)?\n(def\s+(\w+)\s*\([^)]*\)[\s\S]*?(?=\n(?:def|class)|\Z))"
            for match in re.finditer(pattern, file_content, re.MULTILINE):
                class_name = match.group(2)
                func_name = match.group(4)
                func_code = match.group(3)

                functions.append({
                    "name": func_name,
                    "class_name": class_name,
                    "code": func_code.strip(),
                })

        return functions

    def _deduplicate_findings(self, findings: List[Any]) -> List[Any]:
        """去重发现"""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.rule_id, finding.code_snippet[:100])
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _calculate_combined_risk_score(self, result: SecurityAnalysisResult) -> float:
        """计算综合风险评分"""
        if not result.findings:
            return 0.0

        severity_weights = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 1.0,
        }

        total_score = 0.0
        for finding in result.findings:
            weight = severity_weights.get(finding.severity, 5.0)
            total_score += weight * finding.confidence

        return min(total_score / len(result.findings), 10.0)

    def _generate_project_summary(self, result: SecurityAnalysisResult, files_count: int) -> str:
        """生成项目摘要"""
        if not result.findings:
            return f"分析了 {files_count} 个文件，未发现安全问题"

        severity_counts: Dict[str, int] = {}
        for finding in result.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        parts = [
            f"分析了 {files_count} 个文件",
            f"发现 {len(result.findings)} 个问题",
        ]

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                parts.append(f"{severity}: {count}")

        return "，".join(parts)

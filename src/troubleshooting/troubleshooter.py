"""排查模块核心功能

基于测试模块衍生的排查功能，支持文件范围限制和AI文件优先级分级。
"""

import asyncio
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass

from src.utils.logger import get_logger
from src.utils.ai_file_prioritizer import AIFilePrioritizer
from src.testing.test_generator import TestCaseGenerator, TestType, VulnerabilityType
from src.troubleshooting.report_generator import ReportGenerator

logger = get_logger(__name__)


@dataclass
class TroubleshootingResult:
    """排查结果"""
    file_path: Path
    priority_score: float
    priority_level: str
    vulnerabilities: List[str]
    test_cases: List[Any]
    analysis_summary: str
    risk_level: str


class Troubleshooter:
    """排查器
    
    基于测试模块衍生的排查功能，支持文件范围限制和AI文件优先级分级。
    """
    
    def __init__(self, ai_client=None, config=None):
        """初始化排查器
        
        Args:
            ai_client: AI客户端
            config: 配置对象
        """
        self.ai_client = ai_client
        self.config = config
        self.file_prioritizer = AIFilePrioritizer(ai_client, config)
        self.test_generator = TestCaseGenerator()
        self.report_generator = ReportGenerator()
        
    async def troubleshoot(
        self,
        file_patterns: List[str],
        max_files: Optional[int] = None,
        depth: str = "medium",
        include_vulnerabilities: Optional[List[str]] = None
    ) -> List[TroubleshootingResult]:
        """执行排查
        
        Args:
            file_patterns: 文件模式列表，如 ["*.py", "src/**/*.js"]
            max_files: 最大文件数量限制
            depth: 分析深度 (low, medium, high)
            include_vulnerabilities: 要包含的漏洞类型列表
            
        Returns:
            排查结果列表
        """
        logger.info(f"开始排查，文件模式: {file_patterns}, 最大文件数: {max_files}, 深度: {depth}")
        
        # 1. 收集文件
        files = self._collect_files(file_patterns)
        logger.info(f"收集到 {len(files)} 个文件")
        
        if not files:
            logger.warning("没有找到匹配的文件")
            return []
        
        # 2. 优先级排序
        prioritized_files = await self.file_prioritizer.prioritize_files(files)
        logger.info(f"文件优先级排序完成")
        
        # 3. 限制文件数量
        if max_files:
            prioritized_files = prioritized_files[:max_files]
            logger.info(f"限制文件数量为 {max_files}")
        
        # 4. 执行分析
        results = await self._analyze_files(prioritized_files, depth, include_vulnerabilities)
        
        logger.info(f"排查完成，共分析 {len(results)} 个文件")
        return results
    
    def _collect_files(self, file_patterns: List[str]) -> List[Path]:
        """收集匹配的文件
        
        Args:
            file_patterns: 文件模式列表
            
        Returns:
            文件路径列表
        """
        collected_files: Set[Path] = set()
        
        for pattern in file_patterns:
            # 处理通配符模式
            if '**' in pattern:
                # 递归查找
                parts = pattern.split('**')
                if parts[0]:
                    base_dir = Path(parts[0].rstrip('/'))
                else:
                    base_dir = Path('.')
                
                if parts[1]:
                    file_pattern = parts[1].lstrip('/')
                else:
                    file_pattern = '*'
                
                for file in base_dir.rglob(file_pattern):
                    if file.is_file():
                        collected_files.add(file)
            else:
                # 非递归查找
                for file in Path('.').glob(pattern):
                    if file.is_file():
                        collected_files.add(file)
        
        return list(collected_files)
    
    async def _analyze_files(
        self,
        prioritized_files: List[Tuple[Path, float, str]],
        depth: str,
        include_vulnerabilities: Optional[List[str]]
    ) -> List[TroubleshootingResult]:
        """分析文件
        
        Args:
            prioritized_files: 优先级排序后的文件列表
            depth: 分析深度
            include_vulnerabilities: 要包含的漏洞类型列表
            
        Returns:
            排查结果列表
        """
        results: List[TroubleshootingResult] = []
        
        # 并行分析文件
        tasks = []
        for file_path, priority_score, priority_level in prioritized_files:
            tasks.append(
                self._analyze_single_file(
                    file_path, 
                    priority_score, 
                    priority_level, 
                    depth, 
                    include_vulnerabilities
                )
            )
        
        # 限制并行数量
        batch_size = 5
        for i in range(0, len(tasks), batch_size):
            batch_tasks = tasks[i:i+batch_size]
            batch_results = await asyncio.gather(*batch_tasks)
            results.extend([r for r in batch_results if r])
        
        return results
    
    async def _analyze_single_file(
        self,
        file_path: Path,
        priority_score: float,
        priority_level: str,
        depth: str,
        include_vulnerabilities: Optional[List[str]]
    ) -> Optional[TroubleshootingResult]:
        """分析单个文件
        
        Args:
            file_path: 文件路径
            priority_score: 优先级分数
            priority_level: 优先级级别
            depth: 分析深度
            include_vulnerabilities: 要包含的漏洞类型列表
            
        Returns:
            排查结果
        """
        try:
            logger.debug(f"分析文件: {file_path}")
            
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # 确定文件语言
            language = self._detect_language(file_path)
            
            # 生成测试用例
            vulnerabilities = []
            test_cases = []
            
            if include_vulnerabilities:
                # 生成指定类型的安全测试
                test_cases = self.test_generator.generate_security_tests(
                    code, language, include_vulnerabilities
                )
                vulnerabilities = include_vulnerabilities
            else:
                # 生成所有类型的安全测试
                test_cases = self.test_generator.generate_test_cases(
                    code, language, TestType.SECURITY
                )
                # 提取漏洞类型
                for tc in test_cases:
                    if tc.vulnerability_type:
                        vuln = tc.vulnerability_type.value
                        if vuln not in vulnerabilities:
                            vulnerabilities.append(vuln)
            
            # 生成分析摘要
            analysis_summary = self._generate_analysis_summary(
                file_path, priority_level, vulnerabilities, len(test_cases)
            )
            
            # 评估风险级别
            risk_level = self._evaluate_risk_level(priority_level, len(vulnerabilities))
            
            result = TroubleshootingResult(
                file_path=file_path,
                priority_score=priority_score,
                priority_level=priority_level,
                vulnerabilities=vulnerabilities,
                test_cases=test_cases,
                analysis_summary=analysis_summary,
                risk_level=risk_level
            )
            
            return result
            
        except Exception as e:
            logger.error(f"分析文件 {file_path} 时出错: {e}")
            return None
    
    def _detect_language(self, file_path: Path) -> str:
        """检测文件语言
        
        Args:
            file_path: 文件路径
            
        Returns:
            语言名称
        """
        ext = file_path.suffix.lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cs': 'csharp',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.swift': 'swift',
            '.kt': 'kotlin',
        }
        
        return language_map.get(ext, 'python')
    
    def _generate_analysis_summary(
        self,
        file_path: Path,
        priority_level: str,
        vulnerabilities: List[str],
        test_count: int
    ) -> str:
        """生成分析摘要
        
        Args:
            file_path: 文件路径
            priority_level: 优先级级别
            vulnerabilities: 漏洞类型列表
            test_count: 测试用例数量
            
        Returns:
            分析摘要
        """
        summary = f"文件 {file_path.name} 的分析结果："
        summary += f"优先级级别: {priority_level}，"
        summary += f"发现 {len(vulnerabilities)} 种潜在漏洞，"
        summary += f"生成 {test_count} 个测试用例。"
        
        if vulnerabilities:
            summary += f" 漏洞类型: {', '.join(vulnerabilities)}"
        
        return summary
    
    def _evaluate_risk_level(self, priority_level: str, vulnerability_count: int) -> str:
        """评估风险级别
        
        Args:
            priority_level: 优先级级别
            vulnerability_count: 漏洞数量
            
        Returns:
            风险级别
        """
        if priority_level == 'high' and vulnerability_count > 3:
            return 'critical'
        elif priority_level == 'high' or vulnerability_count > 1:
            return 'high'
        elif priority_level == 'medium' or vulnerability_count == 1:
            return 'medium'
        else:
            return 'low'
    
    def generate_report(
        self,
        results: List[TroubleshootingResult],
        output_path: str,
        format: str = 'json'
    ) -> None:
        """生成排查报告
        
        Args:
            results: 排查结果列表
            output_path: 输出路径
            format: 输出格式 (json, html, markdown)
        """
        self.report_generator.generate(
            results, output_path, format
        )
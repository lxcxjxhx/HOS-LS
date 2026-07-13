"""AI基于文件名的文件优先级评估模块

使用AI语义理解评估文件的安全重要性，结合 Search Agent 实现高效文件筛选。
增强版本：集成语义搜索、调用链分析和历史漏洞权重。
"""

import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from src.utils.logger import get_logger
from src.utils.file_prioritizer import FilePrioritizer

logger = get_logger(__name__)


@dataclass
class PriorityEvaluation:
    """优先级评估结果"""
    priority_score: float
    priority_level: str
    analysis_summary: str
    key_risk_factors: List[str]
    security_sensitivity: str
    code_complexity: str
    impact_scope: str


class AIFilePrioritizer:
    """AI文件优先级评估器

    使用AI语义理解评估文件的安全重要性，结合 Search Agent 实现高效文件筛选。
    增强版本：集成语义搜索、调用链分析和历史漏洞权重。
    """

    def __init__(self, ai_client=None, config=None):
        """初始化AI文件优先级评估器

        Args:
            ai_client: AI客户端
            config: 配置对象
        """
        self.ai_client = ai_client
        self.config = config
        self.fallback_prioritizer = FilePrioritizer()
        self.cache: Dict[str, PriorityEvaluation] = {}
        self.enabled = ai_client is not None

        self._search_agent = None
        self._score_calculator = None
        self._semantic_searcher = None
        self._file_index = None
        self._historical_vulns: List[Dict[str, Any]] = []
        self._last_scan_results: List[str] = []

        if self.enabled:
            self._initialize_search_components()
            logger.info("AI文件优先级评估器已启用（增强版：集成Search Agent）")
        else:
            logger.info("AI文件优先级评估器未启用，使用回退机制")

    def _initialize_search_components(self) -> None:
        """初始化 Search Agent 相关组件"""
        try:
            from src.ai.search_agent import SemanticSearcher, ScoreCalculator, FileIndex

            storage_path = Path.home() / '.hos_ls' / 'semantic_index'
            self._semantic_searcher = SemanticSearcher(storage_path=storage_path)
            self._score_calculator = ScoreCalculator()
            self._file_index = FileIndex()

            logger.debug("Search Agent 组件初始化成功")

        except Exception as e:
            logger.warning(f"Search Agent 组件初始化失败: {e}")
            self._semantic_searcher = None
            self._score_calculator = None
            self._file_index = None

    def set_historical_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """设置历史漏洞数据，用于权重计算

        Args:
            vulnerabilities: 历史漏洞列表
        """
        self._historical_vulns = vulnerabilities

        if self._score_calculator:
            self._score_calculator.set_historical_vulnerabilities(vulnerabilities)

    def set_last_scan_results(self, file_paths: List[str]) -> None:
        """设置上次扫描结果，用于变更检测

        Args:
            file_paths: 上次扫描的文件路径列表
        """
        self._last_scan_results = file_paths

        if self._score_calculator:
            self._score_calculator.set_last_scan_files(file_paths)

    async def search_relevant_files(
        self,
        query: str,
        candidate_files: List[str],
        top_k: int = 20
    ) -> List[Tuple[str, float]]:
        """使用语义搜索查找相关文件

        Args:
            query: 搜索查询
            candidate_files: 候选文件列表
            top_k: 返回数量

        Returns:
            (文件路径, 相关度分数) 列表
        """
        if not self._semantic_searcher:
            return []

        try:
            results = await self._semantic_searcher.search(
                query=query,
                top_k=top_k,
                file_filter=candidate_files
            )

            return [(r.file_path, r.similarity) for r in results]

        except Exception as e:
            logger.warning(f"语义搜索失败: {e}")
            return []

    def calculate_priority_with_search(
        self,
        file_path: str,
        file_content: str,
        keyword: str = "",
        is_changed: bool = False,
        call_chain: Optional[List[str]] = None
    ) -> Tuple[float, str]:
        """使用增强评分计算器计算文件优先级

        Args:
            file_path: 文件路径
            file_content: 文件内容
            keyword: 搜索关键词
            is_changed: 文件是否已变更
            call_chain: 调用链

        Returns:
            (优先级分数, 优先级级别)
        """
        if not self._score_calculator:
            return self.fallback_prioritizer.evaluate_file_priority(Path(file_path))

        try:
            file_score = self._score_calculator.calculate_score(
                file_path=file_path,
                file_content=file_content,
                keyword=keyword,
                is_changed=is_changed,
                call_chain=call_chain
            )

            return file_score.total_score, file_score.priority_level

        except Exception as e:
            logger.warning(f"增强评分计算失败: {e}")
            return self.fallback_prioritizer.evaluate_file_priority(Path(file_path))

    async def prioritize_with_search_agent(
        self,
        files: List[Path],
        query: str = "",
        top_k: int = 20,
        include_all: bool = False
    ) -> List[Tuple[Path, float, str]]:
        """使用 Search Agent 增强的优先级排序

        Args:
            files: 文件路径列表
            query: 搜索查询
            top_k: 返回 Top-K 文件
            include_all: 是否返回所有文件

        Returns:
            (文件路径, 优先级分数, 优先级级别) 列表
        """
        if not self.enabled or not self._score_calculator:
            return await self.prioritize_files(files)

        try:
            file_data: List[Tuple[str, str]] = []
            for fp in files:
                try:
                    content = fp.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    content = ""
                file_data.append((str(fp), content))

            changed_files = set()
            if self._last_scan_results:
                current_files = {str(f) for f in files}
                last_files = set(self._last_scan_results)
                changed_files = current_files - last_files

            scores = self._score_calculator.batch_calculate(
                files=file_data,
                keyword=query,
                changed_files=list(changed_files)
            )

            if not include_all:
                top_scores = scores[:top_k]
            else:
                top_scores = scores

            results: List[Tuple[Path, float, str]] = []
            for score in top_scores:
                results.append((
                    Path(score.file_path),
                    score.total_score,
                    score.priority_level
                ))

            if include_all:
                remaining_files = {str(f) for f in files} - {s.file_path for s in top_scores}
                for fp in files:
                    if str(fp) in remaining_files:
                        fallback_score, fallback_level = self.fallback_prioritizer.evaluate_file_priority(fp)
                        results.append((fp, fallback_score, fallback_level))

            results.sort(key=lambda x: x[1], reverse=True)
            return results

        except Exception as e:
            logger.warning(f"Search Agent 优先级排序失败: {e}")
            return await self.prioritize_files(files)
    
    async def evaluate_file_priority(
        self, 
        file_path: Path, 
        file_content: Optional[str] = None
    ) -> Tuple[float, str]:
        """评估文件优先级
        
        Args:
            file_path: 文件路径
            file_content: 文件内容（不再使用）
            
        Returns:
            (优先级分数, 优先级级别)
        """
        file_path_str = str(file_path)
        
        # 检查缓存
        if file_path_str in self.cache:
            cached = self.cache[file_path_str]
            return cached.priority_score, cached.priority_level
        
        try:
            # 如果启用了AI，使用AI评估
            if self.enabled:
                evaluation = await self._evaluate_with_ai(file_path)
                if evaluation:
                    self.cache[file_path_str] = evaluation
                    return evaluation.priority_score, evaluation.priority_level
        except Exception as e:
            logger.warning(f"AI优先级评估失败，使用回退机制: {e}")
        
        # 回退到传统方法
        return self.fallback_prioritizer.evaluate_file_priority(file_path)
    
    async def _evaluate_with_ai(
        self, 
        file_path: Path
    ) -> Optional[PriorityEvaluation]:
        """使用AI评估文件优先级（只基于文件名）
        
        Args:
            file_path: 文件路径
            
        Returns:
            优先级评估结果，如果失败返回None
        """
        try:
            # 只使用文件名
            filename = file_path.name
            logger.debug(f"开始AI优先级评估: {filename}")
            
            # 构建提示
            prompt = f"""你是一个代码安全专家，需要基于文件名评估文件的安全重要性。

文件名: {filename}

请基于以下标准评估该文件的安全优先级：
1. 安全敏感性：是否涉及认证、授权、密码等安全相关功能
2. 功能重要性：是否是核心功能文件
3. 影响范围：修改该文件可能影响的范围
4. 风险程度：潜在安全风险的严重程度

请返回JSON格式的评估结果，包含：
{{
  "priority_score": 0.0-1.0,  # 优先级分数，越高越重要
  "priority_level": "high/medium/low",  # 优先级级别
  "analysis_summary": "简要分析",
  "key_risk_factors": ["风险因素1", "风险因素2"],
  "security_sensitivity": "high/medium/low",
  "code_complexity": "high/medium/low",
  "impact_scope": "global/local/isolated"
}}
"""
            
            # 调用AI（添加超时机制）
            if hasattr(self.ai_client, 'generate'):
                from src.ai.models import AIRequest
                # 获取模型名称，默认使用deepseek-chat
                model = getattr(self.config, 'ai_priority_model', 'deepseek-chat')
                # 创建AIRequest对象
                request = AIRequest(prompt=prompt, model=model)
                # 添加超时机制，5秒超时
                try:
                    response = await asyncio.wait_for(self.ai_client.generate(request), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning(f"AI评估超时: {filename}")
                    return None
            else:
                # 尝试直接调用
                response = str(self.ai_client(prompt))
            
            # 解析响应
            if hasattr(response, 'content'):
                response_content = response.content
            else:
                response_content = str(response)
            
            evaluation = self._parse_evaluation_response(response_content)
            if evaluation:
                logger.debug(f"AI优先级评估完成: {file_path.name} -> {evaluation.priority_level} ({evaluation.priority_score:.2f})")
                return evaluation
            else:
                logger.warning(f"AI响应解析失败: {filename}")
                
        except Exception as e:
            logger.warning(f"AI评估过程出错: {e}")
        
        return None
    
    def _parse_evaluation_response(self, response: str) -> Optional[PriorityEvaluation]:
        """解析AI评估响应
        
        Args:
            response: AI响应字符串
            
        Returns:
            优先级评估结果，如果解析失败返回None
        """
        try:
            import json
            import re
            
            # 清理响应
            cleaned_response = response.strip()
            
            # 尝试直接解析
            try:
                data = json.loads(cleaned_response)
                return self._create_evaluation_from_dict(data)
            except json.JSONDecodeError:
                pass
            
            # 提取JSON部分
            json_match = re.search(r'```json\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                try:
                    data = json.loads(json_match.group(1).strip())
                    return self._create_evaluation_from_dict(data)
                except json.JSONDecodeError:
                    pass
            
            # 尝试匹配 { ... }
            json_match = re.search(r'\{[\s\S]*\}', cleaned_response)
            if json_match:
                try:
                    data = json.loads(json_match.group(0))
                    return self._create_evaluation_from_dict(data)
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.warning(f"解析AI响应失败: {e}")
        
        return None
    
    def _create_evaluation_from_dict(self, data: Dict[str, Any]) -> PriorityEvaluation:
        """从字典创建评估结果
        
        Args:
            data: 解析后的JSON数据
            
        Returns:
            优先级评估结果
        """
        # 处理优先级分数，避免类型转换错误
        priority_score_value = data.get('priority_score', 0.5)
        try:
            priority_score = float(priority_score_value)
        except (ValueError, TypeError):
            priority_score = 0.5
        
        return PriorityEvaluation(
            priority_score=priority_score,
            priority_level=str(data.get('priority_level', 'medium')),
            analysis_summary=str(data.get('analysis_summary', '')),
            key_risk_factors=list(data.get('key_risk_factors', [])),
            security_sensitivity=str(data.get('security_sensitivity', 'medium')),
            code_complexity=str(data.get('code_complexity', 'medium')),
            impact_scope=str(data.get('impact_scope', 'local'))
        )
    
    async def prioritize_files(
        self, 
        files: List[Path],
        file_contents: Optional[Dict[str, str]] = None
    ) -> List[Tuple[Path, float, str]]:
        """对文件列表进行优先级排序
        
        Args:
            files: 文件路径列表
            file_contents: 文件内容字典（不再使用）
            
        Returns:
            排序后的文件列表，包含(文件路径, 优先级分数, 优先级级别)
        """
        prioritized = []
        
        # 批量处理：先收集所有需要AI评估的文件
        files_to_evaluate = []
        cached_results = {}
        
        # 先检查缓存
        for file_path in files:
            file_path_str = str(file_path)
            if file_path_str in self.cache:
                cached = self.cache[file_path_str]
                cached_results[file_path_str] = (cached.priority_score, cached.priority_level)
            else:
                files_to_evaluate.append(file_path)
        
        # 批量评估未缓存的文件（限制并行数量）
        if files_to_evaluate and self.enabled:
            # 限制并行评估的文件数量，避免API过载
            batch_size = 5
            for i in range(0, len(files_to_evaluate), batch_size):
                batch_files = files_to_evaluate[i:i+batch_size]
                tasks = []
                for file_path in batch_files:
                    tasks.append(self.evaluate_file_priority(file_path))
                
                # 并行评估
                results = await asyncio.gather(*tasks)
                
                # 构建结果映射
                for j, file_path in enumerate(batch_files):
                    score, priority = results[j]
                    file_path_str = str(file_path)
                    cached_results[file_path_str] = (score, priority)
        
        # 构建最终结果
        for file_path in files:
            file_path_str = str(file_path)
            if file_path_str in cached_results:
                score, priority = cached_results[file_path_str]
            else:
                # 回退到传统方法
                score, priority = self.fallback_prioritizer.evaluate_file_priority(file_path)
            prioritized.append((file_path, score, priority))
        
        # 按优先级分数降序排序
        prioritized.sort(key=lambda x: x[1], reverse=True)
        return prioritized
    
    def clear_cache(self):
        """清除缓存"""
        self.cache.clear()
        logger.info("AI文件优先级评估器缓存已清除")

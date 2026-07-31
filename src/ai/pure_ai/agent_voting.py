"""Agent 并行投票聚合模块

对标 CodeX-Verify 论文的多 Agent 并行验证方法：
- 多个独立 Agent 实例对同一代码片段进行分析
- 通过投票机制聚合结果，提高检测置信度
- 支持加权投票（按置信度加权）和多数投票
- 检测 Agent 间一致性，识别争议性发现

核心思想：
1. 对同一文件启动 N 个独立分析（不同 temperature/prompt 变体）
2. 收集所有 Agent 的漏洞发现结果
3. 基于 signal_id 和位置进行匹配对齐
4. 通过投票策略（多数/加权/共识）决定最终结论
5. 输出共识级别和每个发现的投票统计
"""

import asyncio
import hashlib
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================
# 数据结构
# ============================================================

class VoteStrategy(Enum):
    """投票策略"""
    MAJORITY = "majority"           # 简单多数投票
    WEIGHTED = "weighted"           # 置信度加权投票
    UNANIMOUS = "unanimous"         # 全票一致
    CONSENSUS = "consensus"         # 共识阈值（可配置比例）


class ConsensusLevel(Enum):
    """共识级别"""
    FULL = "full"           # 所有 Agent 一致同意
    STRONG = "strong"       # >= 80% Agent 同意
    MODERATE = "moderate"   # >= 60% Agent 同意
    WEAK = "weak"           # >= 40% Agent 同意
    NONE = "none"           # < 40% Agent 同意


@dataclass
class AgentVote:
    """单个 Agent 的投票"""
    agent_id: str                   # Agent 标识
    finding_id: str                 # 发现标识（signal_id 或生成的 ID）
    decision: str                   # CONFIRMED / REJECTED / REFINED
    confidence: float               # 置信度 0.0-1.0
    severity: str                   # CRITICAL/HIGH/MEDIUM/LOW/INFO
    vuln_type: str                  # 漏洞类型
    location: str                   # 位置信息
    description: str                # 描述
    reasoning: str = ""             # 推理过程
    execution_time_ms: int = 0      # 执行时间
    token_cost: int = 0             # Token 消耗


@dataclass
class FindingCluster:
    """发现聚类 —— 多个 Agent 对同一漏洞的投票集合"""
    cluster_id: str                 # 聚类标识
    location: str                   # 归一化位置
    description: str                # 代表性描述
    votes: List[AgentVote] = field(default_factory=list)
    
    # 投票统计
    confirm_count: int = 0
    reject_count: int = 0
    refine_count: int = 0
    total_votes: int = 0
    
    # 加权投票统计
    weighted_confirm: float = 0.0
    weighted_reject: float = 0.0
    weighted_refine: float = 0.0
    
    # 共识分析
    consensus_level: ConsensusLevel = ConsensusLevel.NONE
    final_decision: str = "REJECTED"
    aggregated_confidence: float = 0.0
    agreement_ratio: float = 0.0    # 同意比例
    
    # 严重度投票
    severity_votes: Dict[str, int] = field(default_factory=dict)
    aggregated_severity: str = "INFO"
    
    # 统计
    avg_execution_time_ms: float = 0.0
    total_token_cost: int = 0


@dataclass
class VotingResult:
    """投票聚合结果"""
    file_path: str
    total_agents: int
    total_findings: int             # 聚类后的发现数
    total_raw_votes: int            # 原始投票总数
    
    clusters: List[FindingCluster] = field(default_factory=list)
    
    # 全局统计
    confirmed_count: int = 0
    rejected_count: int = 0
    refined_count: int = 0
    controversial_count: int = 0    # 存在争议的发现
    
    # 性能统计
    total_execution_time_ms: int = 0
    total_token_cost: int = 0
    avg_agent_agreement: float = 0.0  # 平均 Agent 一致率
    
    # 投票策略信息
    strategy: VoteStrategy = VoteStrategy.MAJORITY
    consensus_threshold: float = 0.6  # 共识阈值


# ============================================================
# 位置归一化与匹配
# ============================================================

class FindingMatcher:
    """发现匹配器 —— 将多个 Agent 的发现对齐到同一聚类"""
    
    def __init__(self, location_tolerance: int = 5, description_threshold: float = 0.6):
        """
        Args:
            location_tolerance: 行号容差（行）
            description_threshold: 描述相似度阈值
        """
        self.location_tolerance = location_tolerance
        self.description_threshold = description_threshold
    
    def match_findings(self, all_votes: List[AgentVote]) -> List[FindingCluster]:
        """将所有投票匹配到聚类中
        
        Args:
            all_votes: 所有 Agent 的投票列表
            
        Returns:
            发现聚类列表
        """
        clusters: List[FindingCluster] = []
        
        for vote in all_votes:
            matched_cluster = self._find_matching_cluster(vote, clusters)
            
            if matched_cluster:
                matched_cluster.votes.append(vote)
            else:
                # 创建新聚类
                new_cluster = FindingCluster(
                    cluster_id=self._generate_cluster_id(vote),
                    location=vote.location,
                    description=vote.description,
                    votes=[vote]
                )
                clusters.append(new_cluster)
        
        # 计算每个聚类的统计信息
        for cluster in clusters:
            self._compute_cluster_stats(cluster)
        
        return clusters
    
    def _find_matching_cluster(
        self, vote: AgentVote, clusters: List[FindingCluster]
    ) -> Optional[FindingCluster]:
        """查找匹配的聚类"""
        for cluster in clusters:
            if self._is_match(vote, cluster):
                return cluster
        return None
    
    def _is_match(self, vote: AgentVote, cluster: FindingCluster) -> bool:
        """判断投票是否匹配聚类"""
        # 1. 优先通过 signal_id 匹配
        if vote.finding_id and cluster.votes:
            for existing_vote in cluster.votes:
                if existing_vote.finding_id == vote.finding_id:
                    return True
        
        # 2. 通过位置匹配
        if self._location_matches(vote.location, cluster.location):
            # 位置匹配后，检查描述相似度
            if self._description_similar(vote.description, cluster.description):
                return True
            # 即使描述不完全相似，如果位置非常接近（容差内），也认为是同一发现
            if self._location_very_close(vote.location, cluster.location):
                return True
        
        return False
    
    def _location_matches(self, loc1: str, loc2: str) -> bool:
        """检查两个位置是否匹配（带容差）"""
        file1, line1 = self._parse_location(loc1)
        file2, line2 = self._parse_location(loc2)
        
        # 文件必须相同
        if file1 != file2:
            return False
        
        # 行号在容差范围内
        if line1 >= 0 and line2 >= 0:
            return abs(line1 - line2) <= self.location_tolerance
        
        return file1 == file2
    
    def _location_very_close(self, loc1: str, loc2: str) -> bool:
        """检查两个位置是否非常接近（容差的一半）"""
        file1, line1 = self._parse_location(loc1)
        file2, line2 = self._parse_location(loc2)
        
        if file1 != file2:
            return False
        
        if line1 >= 0 and line2 >= 0:
            return abs(line1 - line2) <= max(1, self.location_tolerance // 2)
        
        return False
    
    def _description_similar(self, desc1: str, desc2: str) -> bool:
        """检查两个描述的相似度"""
        if not desc1 or not desc2:
            return False
        
        # 简单的 token 重叠相似度
        tokens1 = set(desc1.lower().split())
        tokens2 = set(desc2.lower().split())
        
        if not tokens1 or not tokens2:
            return False
        
        intersection = tokens1 & tokens2
        union = tokens1 | tokens2
        
        jaccard = len(intersection) / len(union) if union else 0
        return jaccard >= self.description_threshold
    
    @staticmethod
    def _parse_location(location: str) -> Tuple[str, int]:
        """解析位置字符串为 (文件路径, 行号)"""
        if not location or ":" not in location:
            return ("", -1)
        
        parts = location.rsplit(":", 1)
        file_path = parts[0]
        try:
            line_num = int(parts[1])
        except (ValueError, IndexError):
            line_num = -1
        
        return (file_path, line_num)
    
    @staticmethod
    def _generate_cluster_id(vote: AgentVote) -> str:
        """生成聚类 ID"""
        content = f"{vote.location}:{vote.vuln_type}:{vote.description[:50]}"
        return f"CLUSTER-{hashlib.md5(content.encode()).hexdigest()[:8]}"
    
    @staticmethod
    def _compute_cluster_stats(cluster: FindingCluster) -> None:
        """计算聚类统计信息"""
        if not cluster.votes:
            return
        
        # 统计投票
        for vote in cluster.votes:
            cluster.total_votes += 1
            
            if vote.decision == "CONFIRMED":
                cluster.confirm_count += 1
                cluster.weighted_confirm += vote.confidence
            elif vote.decision == "REJECTED":
                cluster.reject_count += 1
                cluster.weighted_reject += vote.confidence
            elif vote.decision == "REFINED":
                cluster.refine_count += 1
                cluster.weighted_refine += vote.confidence
            
            # 严重度投票
            cluster.severity_votes[vote.severity] = cluster.severity_votes.get(vote.severity, 0) + 1
            
            # 执行时间和 token
            cluster.avg_execution_time_ms += vote.execution_time_ms
            cluster.total_token_cost += vote.token_cost
        
        # 平均执行时间
        cluster.avg_execution_time_ms /= len(cluster.votes)
        
        # 计算同意比例
        if cluster.total_votes > 0:
            cluster.agreement_ratio = cluster.confirm_count / cluster.total_votes
        
        # 确定最终决策（将在投票策略中覆盖）
        if cluster.confirm_count > cluster.reject_count and cluster.confirm_count > cluster.refine_count:
            cluster.final_decision = "CONFIRMED"
        elif cluster.reject_count >= cluster.confirm_count:
            cluster.final_decision = "REJECTED"
        else:
            cluster.final_decision = "REFINED"
        
        # 确定聚合严重度（取最高票数的严重度）
        if cluster.severity_votes:
            cluster.aggregated_severity = max(
                cluster.severity_votes, key=cluster.severity_votes.get
            )


# ============================================================
# 投票策略
# ============================================================

class VotingEngine:
    """投票引擎 —— 实现不同的投票聚合策略"""
    
    def __init__(
        self,
        strategy: VoteStrategy = VoteStrategy.WEIGHTED,
        consensus_threshold: float = 0.6,
        min_agents: int = 3,
    ):
        """
        Args:
            strategy: 投票策略
            consensus_threshold: 共识阈值（用于 CONSENSUS 策略）
            min_agents: 最少 Agent 数量
        """
        self.strategy = strategy
        self.consensus_threshold = consensus_threshold
        self.min_agents = min_agents
        self.matcher = FindingMatcher()
    
    def aggregate_votes(self, all_votes: List[AgentVote], file_path: str) -> VotingResult:
        """聚合所有 Agent 的投票
        
        Args:
            all_votes: 所有 Agent 的投票列表
            file_path: 被分析的文件路径
            
        Returns:
            投票聚合结果
        """
        start_time = time.time()
        
        # 1. 匹配发现到聚类
        clusters = self.matcher.match_findings(all_votes)
        
        # 2. 对每个聚类应用投票策略
        for cluster in clusters:
            self._apply_voting_strategy(cluster)
        
        # 3. 计算全局统计
        confirmed = sum(1 for c in clusters if c.final_decision == "CONFIRMED")
        rejected = sum(1 for c in clusters if c.final_decision == "REJECTED")
        refined = sum(1 for c in clusters if c.final_decision == "REFINED")
        controversial = sum(1 for c in clusters if self._is_controversial(c))
        
        # 4. 计算平均一致率
        avg_agreement = (
            sum(c.agreement_ratio for c in clusters) / len(clusters)
            if clusters else 0.0
        )
        
        # 5. 计算总执行时间和 token
        total_time = sum(c.avg_execution_time_ms * c.total_votes for c in clusters)
        total_tokens = sum(c.total_token_cost for c in clusters)
        
        # 6. 按严重度排序聚类
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        clusters.sort(key=lambda c: (
            severity_order.get(c.aggregated_severity, 5),
            -c.aggregated_confidence
        ))
        
        elapsed_ms = int((time.time() - start_time) * 1000)
        
        # 统计 Agent 数量
        agent_ids = set(v.agent_id for v in all_votes)
        
        return VotingResult(
            file_path=file_path,
            total_agents=len(agent_ids),
            total_findings=len(clusters),
            total_raw_votes=len(all_votes),
            clusters=clusters,
            confirmed_count=confirmed,
            rejected_count=rejected,
            refined_count=refined,
            controversial_count=controversial,
            total_execution_time_ms=total_time + elapsed_ms,
            total_token_cost=total_tokens,
            avg_agent_agreement=avg_agreement,
            strategy=self.strategy,
            consensus_threshold=self.consensus_threshold,
        )
    
    def _apply_voting_strategy(self, cluster: FindingCluster) -> None:
        """对单个聚类应用投票策略"""
        if self.strategy == VoteStrategy.MAJORITY:
            self._majority_vote(cluster)
        elif self.strategy == VoteStrategy.WEIGHTED:
            self._weighted_vote(cluster)
        elif self.strategy == VoteStrategy.UNANIMOUS:
            self._unanimous_vote(cluster)
        elif self.strategy == VoteStrategy.CONSENSUS:
            self._consensus_vote(cluster)
    
    def _majority_vote(self, cluster: FindingCluster) -> None:
        """简单多数投票"""
        votes = {
            "CONFIRMED": cluster.confirm_count,
            "REJECTED": cluster.reject_count,
            "REFINED": cluster.refine_count,
        }
        
        cluster.final_decision = max(votes, key=votes.get)  # type: ignore[arg-type]
        
        # 聚合置信度 = 该决策的票数 / 总票数
        if cluster.total_votes > 0:
            decision_count = votes[cluster.final_decision]
            cluster.aggregated_confidence = decision_count / cluster.total_votes
        else:
            cluster.aggregated_confidence = 0.0
        
        # 共识级别
        cluster.consensus_level = self._compute_consensus_level(cluster.agreement_ratio)
    
    def _weighted_vote(self, cluster: FindingCluster) -> None:
        """置信度加权投票"""
        weights = {
            "CONFIRMED": cluster.weighted_confirm,
            "REJECTED": cluster.weighted_reject,
            "REFINED": cluster.weighted_refine,
        }
        
        total_weight = sum(weights.values())
        
        if total_weight > 0:
            cluster.final_decision = max(weights, key=weights.get)  # type: ignore[arg-type]
            cluster.aggregated_confidence = weights[cluster.final_decision] / total_weight
        else:
            cluster.final_decision = "REJECTED"
            cluster.aggregated_confidence = 0.0
        
        # 共识级别
        cluster.consensus_level = self._compute_consensus_level(cluster.agreement_ratio)
    
    def _unanimous_vote(self, cluster: FindingCluster) -> None:
        """全票一致投票 —— 只有所有 Agent 一致同意才确认"""
        if cluster.total_votes == 0:
            cluster.final_decision = "REJECTED"
            cluster.consensus_level = ConsensusLevel.NONE
            return
        
        # 检查是否全票一致
        if cluster.confirm_count == cluster.total_votes:
            cluster.final_decision = "CONFIRMED"
            cluster.consensus_level = ConsensusLevel.FULL
            cluster.aggregated_confidence = 1.0
        elif cluster.reject_count == cluster.total_votes:
            cluster.final_decision = "REJECTED"
            cluster.consensus_level = ConsensusLevel.FULL
            cluster.aggregated_confidence = 1.0
        elif cluster.refine_count == cluster.total_votes:
            cluster.final_decision = "REFINED"
            cluster.consensus_level = ConsensusLevel.FULL
            cluster.aggregated_confidence = 1.0
        else:
            # 非全票一致，降级为多数投票
            self._majority_vote(cluster)
            cluster.consensus_level = self._compute_consensus_level(cluster.agreement_ratio)
    
    def _consensus_vote(self, cluster: FindingCluster) -> None:
        """共识阈值投票 —— 达到阈值即确认"""
        if cluster.total_votes == 0:
            cluster.final_decision = "REJECTED"
            cluster.consensus_level = ConsensusLevel.NONE
            return
        
        confirm_ratio = cluster.confirm_count / cluster.total_votes
        
        if confirm_ratio >= self.consensus_threshold:
            cluster.final_decision = "CONFIRMED"
            cluster.aggregated_confidence = confirm_ratio
        elif cluster.reject_count / cluster.total_votes >= self.consensus_threshold:
            cluster.final_decision = "REJECTED"
            cluster.aggregated_confidence = cluster.reject_count / cluster.total_votes
        else:
            cluster.final_decision = "REFINED"
            cluster.aggregated_confidence = max(
                confirm_ratio,
                cluster.reject_count / cluster.total_votes,
                cluster.refine_count / cluster.total_votes,
            )
        
        cluster.consensus_level = self._compute_consensus_level(cluster.agreement_ratio)
    
    @staticmethod
    def _compute_consensus_level(ratio: float) -> ConsensusLevel:
        """根据同意比例计算共识级别"""
        if ratio >= 0.99:
            return ConsensusLevel.FULL
        elif ratio >= 0.8:
            return ConsensusLevel.STRONG
        elif ratio >= 0.6:
            return ConsensusLevel.MODERATE
        elif ratio >= 0.4:
            return ConsensusLevel.WEAK
        else:
            return ConsensusLevel.NONE
    
    @staticmethod
    def _is_controversial(cluster: FindingCluster) -> bool:
        """判断是否存在争议（CONFIRMED 和 REJECTED 票数接近）"""
        if cluster.total_votes < 2:
            return False
        
        max_vote = max(cluster.confirm_count, cluster.reject_count, cluster.refine_count)
        min_vote = min(cluster.confirm_count, cluster.reject_count, cluster.refine_count)
        
        # 如果最高票和最低票差距不超过 1，认为存在争议
        return (max_vote - min_vote) <= 1


# ============================================================
# Agent 并行执行器
# ============================================================

class ParallelAgentExecutor:
    """并行 Agent 执行器
    
    对标 CodeX-Verify 论文的多实例并行验证方法：
    - 启动 N 个独立 Agent 实例分析同一文件
    - 每个实例使用不同的 temperature 或 prompt 变体
    - 收集所有结果并通过投票引擎聚合
    """
    
    def __init__(
        self,
        num_agents: int = 3,
        strategy: VoteStrategy = VoteStrategy.WEIGHTED,
        consensus_threshold: float = 0.6,
        max_concurrent: int = 5,
        temperature_variants: Optional[List[float]] = None,
    ):
        """
        Args:
            num_agents: Agent 实例数量
            strategy: 投票策略
            consensus_threshold: 共识阈值
            max_concurrent: 最大并发数
            temperature_variants: 温度变体列表（用于生成不同的 Agent 行为）
        """
        self.num_agents = num_agents
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # 默认温度变体：低/中/高
        self.temperature_variants = temperature_variants or [0.1, 0.3, 0.5]
        
        # 投票引擎
        self.voting_engine = VotingEngine(
            strategy=strategy,
            consensus_threshold=consensus_threshold,
            min_agents=num_agents,
        )
        
        # 统计
        self.stats = {
            "total_runs": 0,
            "total_votes": 0,
            "total_confirmed": 0,
            "total_rejected": 0,
            "total_refined": 0,
            "total_controversial": 0,
            "avg_agreement": 0.0,
            "total_execution_time_ms": 0,
            "total_token_cost": 0,
        }
    
    async def run_voting_analysis(
        self,
        file_path: str,
        file_content: str,
        agent_fn: Callable,
        detected_language: str = "java",
        context: Optional[Dict] = None,
        **kwargs,
    ) -> VotingResult:
        """运行投票分析
        
        Args:
            file_path: 文件路径
            file_content: 文件内容
            agent_fn: Agent 分析函数，签名: async def fn(file_path, file_content, config, **kwargs) -> List[AgentVote]
            detected_language: 检测到的编程语言
            context: 上下文信息
            **kwargs: 传递给 agent_fn 的额外参数
            
        Returns:
            投票聚合结果
        """
        start_time = time.time()
        
        # 1. 生成 Agent 配置变体
        agent_configs = self._generate_agent_configs()
        
        # 2. 并行执行所有 Agent
        tasks = []
        for i, config in enumerate(agent_configs):
            task = self._run_single_agent(
                agent_id=f"agent_{i}",
                file_path=file_path,
                file_content=file_content,
                agent_fn=agent_fn,
                config=config,
                detected_language=detected_language,
                context=context,
                **kwargs,
            )
            tasks.append(task)
        
        # 3. 等待所有 Agent 完成
        all_votes_lists = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 4. 收集所有投票
        all_votes: List[AgentVote] = []
        for i, result in enumerate(all_votes_lists):
            if isinstance(result, Exception):
                logger.error(f"Agent {i} 执行失败: {result}")
                continue
            if isinstance(result, list):
                all_votes.extend(result)
        
        # 5. 投票聚合
        voting_result = self.voting_engine.aggregate_votes(all_votes, file_path)
        
        # 6. 更新统计
        self._update_stats(voting_result)
        
        logger.info(
            f"投票分析完成: {file_path} | "
            f"Agents={voting_result.total_agents} | "
            f"Findings={voting_result.total_findings} | "
            f"Confirmed={voting_result.confirmed_count} | "
            f"Rejected={voting_result.rejected_count} | "
            f"Controversial={voting_result.controversial_count} | "
            f"Agreement={voting_result.avg_agent_agreement:.2%}"
        )
        
        return voting_result
    
    async def _run_single_agent(
        self,
        agent_id: str,
        file_path: str,
        file_content: str,
        agent_fn: Callable,
        config: Dict[str, Any],
        detected_language: str,
        context: Optional[Dict],
        **kwargs,
    ) -> List[AgentVote]:
        """运行单个 Agent 实例"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                raw_results = await agent_fn(
                    file_path=file_path,
                    file_content=file_content,
                    config=config,
                    detected_language=detected_language,
                    context=context,
                    **kwargs,
                )
                
                elapsed_ms = int((time.time() - start_time) * 1000)
                
                # 将原始结果转换为 AgentVote
                votes = []
                for result in (raw_results or []):
                    vote = AgentVote(
                        agent_id=agent_id,
                        finding_id=result.get("signal_id", ""),
                        decision=result.get("verification_decision", result.get("decision", "CONFIRMED")),
                        confidence=float(result.get("confidence", 0.5)),
                        severity=result.get("severity", "MEDIUM"),
                        vuln_type=result.get("vuln_type", "security_vuln"),
                        location=result.get("location", ""),
                        description=result.get("title", result.get("description", "")),
                        reasoning=result.get("verification_reason", ""),
                        execution_time_ms=elapsed_ms,
                        token_cost=result.get("token_cost", 0),
                    )
                    votes.append(vote)
                
                return votes
                
            except Exception as e:
                logger.error(f"Agent {agent_id} 分析失败: {e}")
                return []
    
    def _generate_agent_configs(self) -> List[Dict[str, Any]]:
        """生成 Agent 配置变体
        
        通过不同的 temperature 和 prompt 策略创建多样化的 Agent 行为，
        类似于 CodeX-Verify 论文中的 self-consistency sampling。
        """
        configs = []
        
        for i in range(self.num_agents):
            # 温度变体（循环使用）
            temp_idx = i % len(self.temperature_variants)
            temperature = self.temperature_variants[temp_idx]
            
            config = {
                "agent_id": f"voter_{i}",
                "temperature": temperature,
                "top_p": max(0.1, 1.0 - temperature * 0.5),
                # 不同的分析侧重点
                "focus": self._get_analysis_focus(i),
                # 是否启用严格模式
                "strict_mode": i % 2 == 0,
            }
            configs.append(config)
        
        return configs
    
    @staticmethod
    def _get_analysis_focus(agent_index: int) -> str:
        """获取 Agent 的分析侧重点"""
        focuses = [
            "data_flow",          # 数据流分析
            "control_flow",       # 控制流分析
            "pattern_matching",   # 模式匹配
            "context_aware",      # 上下文感知
            "security_boundary",  # 安全边界分析
        ]
        return focuses[agent_index % len(focuses)]
    
    def _update_stats(self, result: VotingResult) -> None:
        """更新统计信息"""
        self.stats["total_runs"] += 1
        self.stats["total_votes"] += result.total_raw_votes
        self.stats["total_confirmed"] += result.confirmed_count
        self.stats["total_rejected"] += result.rejected_count
        self.stats["total_refined"] += result.refined_count
        self.stats["total_controversial"] += result.controversial_count
        self.stats["total_execution_time_ms"] += result.total_execution_time_ms
        self.stats["total_token_cost"] += result.total_token_cost
        
        # 更新平均一致率
        n = self.stats["total_runs"]
        prev_avg = self.stats["avg_agreement"]
        self.stats["avg_agreement"] = prev_avg + (result.avg_agent_agreement - prev_avg) / n
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return dict(self.stats)


# ============================================================
# 与现有 Pipeline 的集成接口
# ============================================================

class VotingPipelineIntegration:
    """投票管道集成器
    
    将投票机制集成到现有的 MultiAgentPipeline 中，
    在关键决策点（Agent-3 验证、Agent-4 攻击链、Agent-5 对抗验证）
    启用多 Agent 投票。
    """
    
    def __init__(
        self,
        num_voters: int = 3,
        strategy: VoteStrategy = VoteStrategy.WEIGHTED,
        enable_at_agents: Optional[List[str]] = None,
    ):
        """
        Args:
            num_voters: 投票 Agent 数量
            strategy: 投票策略
            enable_at_agents: 在哪些 Agent 阶段启用投票
                           默认 ["agent_3", "agent_4", "agent_5"]
        """
        self.num_voters = num_voters
        self.strategy = strategy
        self.enable_at_agents = enable_at_agents or ["agent_3", "agent_4", "agent_5"]
        
        self.executor = ParallelAgentExecutor(
            num_agents=num_voters,
            strategy=strategy,
        )
        
        self.logger = get_logger(__name__)
    
    async def vote_on_verification(
        self,
        file_path: str,
        file_content: str,
        risk_signals: List[Dict],
        agent_fn: Callable,
        **kwargs,
    ) -> VotingResult:
        """对漏洞验证阶段进行投票
        
        Args:
            file_path: 文件路径
            file_content: 文件内容
            risk_signals: Agent-2 输出的风险信号
            agent_fn: Agent 分析函数
            **kwargs: 额外参数
            
        Returns:
            投票结果
        """
        if "agent_3" not in self.enable_at_agents:
            # 不启用投票，直接运行单次分析
            return await self._run_single_analysis(
                file_path, file_content, agent_fn, **kwargs
            )
        
        self.logger.info(f"启用投票验证: {file_path} (voters={self.num_voters})")
        
        return await self.executor.run_voting_analysis(
            file_path=file_path,
            file_content=file_content,
            agent_fn=agent_fn,
            context={"risk_signals": risk_signals},
            **kwargs,
        )
    
    async def vote_on_attack_chain(
        self,
        file_path: str,
        file_content: str,
        verified_vulns: List[Dict],
        agent_fn: Callable,
        **kwargs,
    ) -> VotingResult:
        """对攻击链分析阶段进行投票"""
        if "agent_4" not in self.enable_at_agents:
            return await self._run_single_analysis(
                file_path, file_content, agent_fn, **kwargs
            )
        
        self.logger.info(f"启用攻击链投票: {file_path} (voters={self.num_voters})")
        
        return await self.executor.run_voting_analysis(
            file_path=file_path,
            file_content=file_content,
            agent_fn=agent_fn,
            context={"verified_vulns": verified_vulns},
            **kwargs,
        )
    
    async def vote_on_adversarial(
        self,
        file_path: str,
        file_content: str,
        attack_chains: List[Dict],
        agent_fn: Callable,
        **kwargs,
    ) -> VotingResult:
        """对对抗验证阶段进行投票"""
        if "agent_5" not in self.enable_at_agents:
            return await self._run_single_analysis(
                file_path, file_content, agent_fn, **kwargs
            )
        
        self.logger.info(f"启用对抗验证投票: {file_path} (voters={self.num_voters})")
        
        return await self.executor.run_voting_analysis(
            file_path=file_path,
            file_content=file_content,
            agent_fn=agent_fn,
            context={"attack_chains": attack_chains},
            **kwargs,
        )
    
    async def _run_single_analysis(
        self,
        file_path: str,
        file_content: str,
        agent_fn: Callable,
        **kwargs,
    ) -> VotingResult:
        """运行单次分析（不启用投票）"""
        votes = await agent_fn(
            file_path=file_path,
            file_content=file_content,
            config={"temperature": 0.2},
            **kwargs,
        )
        
        all_votes = []
        for result in (votes or []):
            vote = AgentVote(
                agent_id="single",
                finding_id=result.get("signal_id", ""),
                decision=result.get("verification_decision", "CONFIRMED"),
                confidence=float(result.get("confidence", 0.5)),
                severity=result.get("severity", "MEDIUM"),
                vuln_type=result.get("vuln_type", "security_vuln"),
                location=result.get("location", ""),
                description=result.get("title", result.get("description", "")),
            )
            all_votes.append(vote)
        
        engine = VotingEngine(strategy=self.strategy)
        return engine.aggregate_votes(all_votes, file_path)
    
    def convert_voting_to_pipeline_format(
        self, voting_result: VotingResult
    ) -> List[Dict[str, Any]]:
        """将投票结果转换为 Pipeline 可接受的格式
        
        Args:
            voting_result: 投票聚合结果
            
        Returns:
            转换后的漏洞列表
        """
        findings = []
        
        for cluster in voting_result.clusters:
            if cluster.final_decision != "CONFIRMED":
                continue
            
            finding = {
                "title": cluster.description,
                "location": cluster.location,
                "severity": cluster.aggregated_severity,
                "confidence": cluster.aggregated_confidence,
                "verification_decision": "CONFIRMED",
                "consensus_level": cluster.consensus_level.value,
                "agreement_ratio": cluster.agreement_ratio,
                "confirm_votes": cluster.confirm_count,
                "reject_votes": cluster.reject_count,
                "refine_votes": cluster.refine_count,
                "total_votes": cluster.total_votes,
                "is_controversial": self._is_controversial(cluster),
                # 保留投票详情
                "vote_details": [
                    {
                        "agent_id": v.agent_id,
                        "decision": v.decision,
                        "confidence": v.confidence,
                        "severity": v.severity,
                    }
                    for v in cluster.votes
                ],
            }
            findings.append(finding)
        
        return findings
    
    @staticmethod
    def _is_controversial(cluster: FindingCluster) -> bool:
        """判断聚类是否存在争议"""
        if cluster.total_votes < 2:
            return False
        max_vote = max(cluster.confirm_count, cluster.reject_count, cluster.refine_count)
        min_vote = min(cluster.confirm_count, cluster.reject_count, cluster.refine_count)
        return (max_vote - min_vote) <= 1

"""自一致性采样模块

对标 MultiVer 论文的自一致性采样方法，通过多次独立采样提升 LLM 分析结果的可靠性：
- 对同一输入使用不同温度参数进行 N 次独立采样
- 通过多种比较策略（哈希、语义、结构）分析采样间的一致性
- 支持多种输出选择方法（多数投票、加权置信、中位数、共识合并）
- 输出一致性报告，量化分析结果的可信程度

核心思想：
1. 对同一 prompt 生成 N 个独立样本（不同 temperature）
2. 归一化各样本输出并进行一致性比较
3. 根据一致性比例判断结果可靠程度
4. 通过选择策略确定最终输出
5. 输出完整的一致性报告供下游使用
"""

import asyncio
import hashlib
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================
# 数据结构
# ============================================================

@dataclass
class SampleResult:
    """单次采样结果"""
    sample_id: int                    # 采样编号
    output: Dict[str, Any]            # LLM 输出（解析后的字典）
    confidence: float                 # 置信度 0.0-1.0
    reasoning_path: str               # 推理路径/过程描述
    token_cost: int                   # Token 消耗量


@dataclass
class ConsistencyReport:
    """一致性分析报告"""
    input_hash: str                              # 输入内容的哈希标识
    num_samples: int                             # 采样总数
    consistent_count: int                        # 一致样本数
    consistency_ratio: float                     # 一致性比例 0.0-1.0
    selected_output: Dict[str, Any]              # 最终选择的输出
    selection_method: str                        # 选择方法名称
    all_samples: List[SampleResult] = field(default_factory=list)


@dataclass
class ConsistencyConfig:
    """自一致性采样配置"""
    num_samples: int = 5                                    # 采样次数
    temperature_range: Tuple[float, float] = (0.1, 0.5)    # 温度范围
    consistency_threshold: float = 0.6                      # 一致性阈值（60% 同意）
    selection_method: str = "weighted_confidence"           # 选择方法


# ============================================================
# 自一致性采样器
# ============================================================

class SelfConsistencySampler:
    """自一致性采样器

    对标 MultiVer 论文的自一致性采样方法：
    - 对同一 prompt 进行 N 次独立采样（使用不同温度）
    - 分析采样间的一致性程度
    - 通过多种策略选择最佳输出
    - 生成一致性报告

    支持的选择方法：
    - majority: 多数投票（选择出现次数最多的输出）
    - weighted_confidence: 置信度加权投票
    - median: 中位数选择（按置信度取中位）
    - consensus_merge: 共识合并（合并一致部分）
    """

    # 默认温度调度列表
    DEFAULT_TEMPERATURES = [0.1, 0.2, 0.3, 0.4, 0.5]

    def __init__(self, config: Optional[ConsistencyConfig] = None):
        """初始化自一致性采样器

        Args:
            config: 采样配置，为 None 时使用默认配置
        """
        self.config = config or ConsistencyConfig()
        self._stats = {
            "total_runs": 0,
            "total_samples": 0,
            "total_consistent": 0,
            "avg_consistency_ratio": 0.0,
            "total_token_cost": 0,
            "total_execution_time_ms": 0,
        }

    async def sample(
        self,
        llm_fn: Callable,
        prompt: str,
        **kwargs,
    ) -> ConsistencyReport:
        """执行自一致性采样

        对给定的 prompt 进行 N 次独立采样，分析一致性并选择最佳输出。

        Args:
            llm_fn: LLM 调用函数，签名为 async def fn(prompt: str, **kwargs) -> Dict
                    返回的 Dict 应包含输出结果，可选字段：
                    - confidence (float): 置信度
                    - reasoning_path (str): 推理路径
                    - token_cost (int): Token 消耗
            prompt: 输入 prompt
            **kwargs: 传递给 llm_fn 的额外参数

        Returns:
            一致性分析报告
        """
        start_time = time.time()
        input_hash = self._compute_hash(prompt)

        logger.info(
            f"开始自一致性采样: input_hash={input_hash[:8]}... | "
            f"num_samples={self.config.num_samples} | "
            f"method={self.config.selection_method}"
        )

        # 1. 生成 N 个独立样本
        samples = await self._generate_samples(
            llm_fn, prompt, self.config.num_samples, **kwargs
        )

        if not samples:
            logger.warning("所有采样均失败，返回空结果")
            return ConsistencyReport(
                input_hash=input_hash,
                num_samples=0,
                consistent_count=0,
                consistency_ratio=0.0,
                selected_output={},
                selection_method=self.config.selection_method,
                all_samples=[],
            )

        # 2. 分析一致性
        consistent_count, consistency_ratio = self._analyze_consistency(samples)

        # 3. 选择最佳输出
        selected_output = self._select_best_output(
            samples, self.config.selection_method
        )

        elapsed_ms = int((time.time() - start_time) * 1000)

        report = ConsistencyReport(
            input_hash=input_hash,
            num_samples=len(samples),
            consistent_count=consistent_count,
            consistency_ratio=consistency_ratio,
            selected_output=selected_output,
            selection_method=self.config.selection_method,
            all_samples=samples,
        )

        # 4. 更新统计
        self._update_stats(report, elapsed_ms)

        logger.info(
            f"自一致性采样完成: input_hash={input_hash[:8]}... | "
            f"samples={report.num_samples} | "
            f"consistent={report.consistent_count}/{report.num_samples} | "
            f"ratio={report.consistency_ratio:.2%} | "
            f"method={report.selection_method} | "
            f"time={elapsed_ms}ms"
        )

        return report

    async def _generate_samples(
        self,
        llm_fn: Callable,
        prompt: str,
        n_samples: int,
        **kwargs,
    ) -> List[SampleResult]:
        """生成 N 个独立样本（使用不同温度）

        温度调度策略：
        - 在配置的温度范围内均匀分布 N 个温度值
        - 较低温度（如 0.1）产生更确定性的输出
        - 较高温度（如 0.5）探索更多可能性
        - 所有采样并行执行以提高效率

        Args:
            llm_fn: LLM 调用函数
            prompt: 输入 prompt
            n_samples: 采样数量
            **kwargs: 传递给 llm_fn 的额外参数

        Returns:
            采样结果列表
        """
        temperatures = self._compute_temperature_schedule(n_samples)

        logger.debug(
            f"温度调度: {temperatures} (范围: {self.config.temperature_range})"
        )

        # 并行执行所有采样
        tasks = []
        for i, temp in enumerate(temperatures):
            task = self._run_single_sample(
                sample_id=i,
                llm_fn=llm_fn,
                prompt=prompt,
                temperature=temp,
                **kwargs,
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 收集成功的采样结果
        samples: List[SampleResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"采样 {i} (temperature={temperatures[i]:.2f}) 失败: {result}")
                continue
            if isinstance(result, SampleResult):
                samples.append(result)

        logger.info(f"成功生成 {len(samples)}/{n_samples} 个样本")
        return samples

    async def _run_single_sample(
        self,
        sample_id: int,
        llm_fn: Callable,
        prompt: str,
        temperature: float,
        **kwargs,
    ) -> SampleResult:
        """运行单次采样

        Args:
            sample_id: 采样编号
            llm_fn: LLM 调用函数
            prompt: 输入 prompt
            temperature: 采样温度
            **kwargs: 额外参数

        Returns:
            单次采样结果
        """
        start_time = time.time()

        # 调用 LLM，传入温度参数
        raw_output = await llm_fn(
            prompt=prompt,
            temperature=temperature,
            **kwargs,
        )

        elapsed_ms = int((time.time() - start_time) * 1000)

        # 从输出中提取各字段
        if isinstance(raw_output, dict):
            output = raw_output
        else:
            output = {"raw": raw_output}

        confidence = float(output.get("confidence", 0.5))
        reasoning_path = output.get("reasoning_path", output.get("reasoning", ""))
        token_cost = int(output.get("token_cost", output.get("usage", {}).get("total_tokens", 0)))

        logger.debug(
            f"采样 {sample_id} 完成: temperature={temperature:.2f} | "
            f"confidence={confidence:.3f} | "
            f"tokens={token_cost} | "
            f"time={elapsed_ms}ms"
        )

        return SampleResult(
            sample_id=sample_id,
            output=output,
            confidence=confidence,
            reasoning_path=str(reasoning_path),
            token_cost=token_cost,
        )

    def _analyze_consistency(
        self, samples: List[SampleResult]
    ) -> Tuple[int, float]:
        """分析采样间的一致性

        使用多层次比较策略：
        1. 哈希比较：归一化输出后比较哈希值（最快）
        2. 语义比较：比较关键字段（漏洞类型、位置、严重度）
        3. 结构比较：比较 JSON 结构和字段值

        Args:
            samples: 采样结果列表

        Returns:
            (一致样本数, 一致性比例)
        """
        if not samples:
            return (0, 0.0)

        if len(samples) == 1:
            return (1, 1.0)

        # 方法 1: 基于归一化哈希的比较
        hash_groups = self._hash_based_comparison(samples)

        # 方法 2: 基于关键字段的语义比较
        semantic_groups = self._semantic_comparison(samples)

        # 方法 3: 基于 JSON 结构的比较
        structural_groups = self._structural_comparison(samples)

        # 综合三种比较结果：取最大一致组
        # 优先使用语义比较（最有意义），哈希比较作为快速路径
        best_consistent_count = max(
            max((len(g) for g in hash_groups.values()), default=0),
            max((len(g) for g in semantic_groups.values()), default=0),
            max((len(g) for g in structural_groups.values()), default=0),
        )

        consistency_ratio = best_consistent_count / len(samples)

        logger.debug(
            f"一致性分析: hash_groups={len(hash_groups)} | "
            f"semantic_groups={len(semantic_groups)} | "
            f"structural_groups={len(structural_groups)} | "
            f"best_consistent={best_consistent_count}/{len(samples)} | "
            f"ratio={consistency_ratio:.2%}"
        )

        return (best_consistent_count, consistency_ratio)

    def _select_best_output(
        self, samples: List[SampleResult], method: str
    ) -> Dict[str, Any]:
        """根据指定方法选择最佳输出

        Args:
            samples: 采样结果列表
            method: 选择方法名称
                - "majority": 多数投票
                - "weighted_confidence": 置信度加权投票
                - "median": 中位数选择
                - "consensus_merge": 共识合并

        Returns:
            选中的最佳输出
        """
        if not samples:
            return {}

        if len(samples) == 1:
            return samples[0].output

        if method == "majority":
            return self._select_by_majority(samples)
        elif method == "weighted_confidence":
            return self._select_by_weighted_confidence(samples)
        elif method == "median":
            return self._select_by_median(samples)
        elif method == "consensus_merge":
            return self._select_by_consensus_merge(samples)
        else:
            logger.warning(f"未知的选择方法 '{method}'，回退到 majority")
            return self._select_by_majority(samples)

    def _normalize_output(self, output: Dict[str, Any]) -> str:
        """归一化 LLM 输出用于比较

        归一化策略：
        - 键名统一为小写
        - 去除空白字符
        - 对列表进行排序
        - 序列化为规范 JSON 字符串

        Args:
            output: 原始输出字典

        Returns:
            归一化后的字符串
        """
        normalized = self._normalize_value(output)
        return json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    # ============================================================
    # 选择方法实现
    # ============================================================

    def _select_by_majority(self, samples: List[SampleResult]) -> Dict[str, Any]:
        """多数投票：选择出现次数最多的输出

        通过归一化哈希对输出分组，选择最大组的代表输出。
        如果存在并列，选择置信度最高的那个。

        Args:
            samples: 采样结果列表

        Returns:
            多数投票选中的输出
        """
        # 按归一化哈希分组
        groups: Dict[str, List[SampleResult]] = defaultdict(list)
        for sample in samples:
            norm_hash = self._compute_hash(self._normalize_output(sample.output))
            groups[norm_hash].append(sample)

        # 找到最大组
        max_group_key = max(groups, key=lambda k: len(groups[k]))
        max_group = groups[max_group_key]

        # 如果有多组大小相同，选置信度总和最高的
        max_size = len(max_group)
        candidates = [g for g in groups.values() if len(g) == max_size]

        if len(candidates) > 1:
            best_group = max(candidates, key=lambda g: sum(s.confidence for s in g))
        else:
            best_group = max_group

        # 从最佳组中选择置信度最高的样本
        representative = max(best_group, key=lambda s: s.confidence)

        logger.debug(
            f"多数投票: {len(groups)} 个不同输出 | "
            f"最大组={len(best_group)}/{len(samples)} | "
            f"选择 sample_id={representative.sample_id}"
        )

        return representative.output

    def _select_by_weighted_confidence(self, samples: List[SampleResult]) -> Dict[str, Any]:
        """置信度加权投票：按置信度加权选择

        每个归一化输出组的权重 = 组内所有样本的置信度之和。
        低温度样本获得额外权重加成（因为更确定性）。

        Args:
            samples: 采样结果列表

        Returns:
            加权投票选中的输出
        """
        # 按归一化哈希分组
        groups: Dict[str, List[SampleResult]] = defaultdict(list)
        for sample in samples:
            norm_hash = self._compute_hash(self._normalize_output(sample.output))
            groups[norm_hash].append(sample)

        # 计算每组的加权分数
        # 低温度样本（sample_id 较小）获得更高权重
        group_scores: Dict[str, float] = {}
        for norm_hash, group in groups.items():
            score = 0.0
            for sample in group:
                # 温度权重：低温度（sample_id 小）权重更高
                temperature_weight = 1.0 + (len(samples) - sample.sample_id) / len(samples)
                score += sample.confidence * temperature_weight
            group_scores[norm_hash] = score

        # 选择得分最高的组
        best_hash = max(group_scores, key=group_scores.get)  # type: ignore[arg-type]
        best_group = groups[best_hash]

        # 从最佳组中选择置信度最高的样本
        representative = max(best_group, key=lambda s: s.confidence)

        logger.debug(
            f"加权置信投票: {len(groups)} 个不同输出 | "
            f"最佳组得分={group_scores[best_hash]:.3f} | "
            f"选择 sample_id={representative.sample_id}"
        )

        return representative.output

    def _select_by_median(self, samples: List[SampleResult]) -> Dict[str, Any]:
        """中位数选择：按置信度排序取中位数

        将所有样本按置信度排序，选择中间位置的样本。
        这种方法对异常值更鲁棒。

        Args:
            samples: 采样结果列表

        Returns:
            中位数位置的输出
        """
        sorted_samples = sorted(samples, key=lambda s: s.confidence)
        median_index = len(sorted_samples) // 2
        selected = sorted_samples[median_index]

        logger.debug(
            f"中位数选择: 排序后置信度="
            f"{[f'{s.confidence:.3f}' for s in sorted_samples]} | "
            f"选择 sample_id={selected.sample_id} "
            f"(confidence={selected.confidence:.3f})"
        )

        return selected.output

    def _select_by_consensus_merge(self, samples: List[SampleResult]) -> Dict[str, Any]:
        """共识合并：合并所有样本中一致的部分

        策略：
        - 对每个字段，检查所有样本中该字段的值
        - 如果多数样本在该字段上一致，使用一致值
        - 如果不一致，使用出现频率最高的值
        - 对于数值字段，使用加权平均值

        Args:
            samples: 采样结果列表

        Returns:
            合并后的输出
        """
        if not samples:
            return {}

        # 收集所有样本中出现的所有键
        all_keys: set = set()
        for sample in samples:
            all_keys.update(sample.output.keys())

        merged: Dict[str, Any] = {}

        for key in all_keys:
            values = []
            for sample in samples:
                if key in sample.output:
                    values.append((sample.output[key], sample.confidence))

            if not values:
                continue

            merged[key] = self._merge_field_values(values)

        logger.debug(
            f"共识合并: {len(all_keys)} 个字段 | "
            f"从 {len(samples)} 个样本中合并"
        )

        return merged

    # ============================================================
    # 比较方法实现
    # ============================================================

    def _hash_based_comparison(
        self, samples: List[SampleResult]
    ) -> Dict[str, List[SampleResult]]:
        """基于哈希的比较：归一化输出后比较哈希值

        最快的比较方式，适合完全一致的输出检测。

        Args:
            samples: 采样结果列表

        Returns:
            哈希值到样本列表的映射
        """
        groups: Dict[str, List[SampleResult]] = defaultdict(list)
        for sample in samples:
            normalized = self._normalize_output(sample.output)
            h = self._compute_hash(normalized)
            groups[h].append(sample)
        return groups

    def _semantic_comparison(
        self, samples: List[SampleResult]
    ) -> Dict[str, List[SampleResult]]:
        """基于语义的比较：比较关键字段

        提取安全分析中的关键字段进行比较：
        - 漏洞类型 (vulnerability type / vuln_type / type)
        - 位置 (location / file / path)
        - 严重度 (severity / risk_level)
        - CWE 编号 (cwe_id / cwe)

        Args:
            samples: 采样结果列表

        Returns:
            语义键到样本列表的映射
        """
        # 关键字段名映射（支持多种命名风格）
        key_fields = [
            ("vuln_type", "vulnerability_type", "type", "vulnerability", "risk_type"),
            ("location", "file", "path", "file_path", "source_location"),
            ("severity", "risk_level", "risk", "impact"),
            ("cwe_id", "cwe", "cwe_number"),
            ("owasp_category", "owasp", "category"),
        ]

        groups: Dict[str, List[SampleResult]] = defaultdict(list)
        for sample in samples:
            semantic_key = self._extract_semantic_key(sample.output, key_fields)
            groups[semantic_key].append(sample)

        return groups

    def _structural_comparison(
        self, samples: List[SampleResult]
    ) -> Dict[str, List[SampleResult]]:
        """基于结构的比较：比较 JSON 结构和字段值

        比较维度：
        - JSON 顶层键集合是否相同
        - 对应键的值类型是否一致
        - 关键字段的值是否相同

        Args:
            samples: 采样结果列表

        Returns:
            结构键到样本列表的映射
        """
        groups: Dict[str, List[SampleResult]] = defaultdict(list)
        for sample in samples:
            structure_key = self._compute_structure_key(sample.output)
            groups[structure_key].append(sample)
        return groups

    # ============================================================
    # 辅助方法
    # ============================================================

    def _compute_temperature_schedule(self, n_samples: int) -> List[float]:
        """计算温度调度

        在配置的温度范围内均匀分布 n_samples 个温度值。
        如果 n_samples 超过默认温度列表长度，则线性插值。

        Args:
            n_samples: 采样数量

        Returns:
            温度值列表
        """
        low, high = self.config.temperature_range

        if n_samples == 1:
            return [low]

        if n_samples == 2:
            return [low, high]

        # 均匀分布
        step = (high - low) / (n_samples - 1)
        temperatures = [round(low + i * step, 2) for i in range(n_samples)]

        return temperatures

    def _extract_semantic_key(
        self,
        output: Dict[str, Any],
        key_fields: List[Tuple[str, ...]],
    ) -> str:
        """从输出中提取语义键

        对每组候选字段名，尝试在输出中找到匹配字段，
        将所有找到的字段值拼接为语义键。

        Args:
            output: 输出字典
            key_fields: 关键字段名元组列表

        Returns:
            语义键字符串
        """
        parts = []
        for field_group in key_fields:
            value = None
            for field_name in field_group:
                # 尝试精确匹配（不区分大小写）
                for key in output:
                    if key.lower() == field_name.lower():
                        value = output[key]
                        break
                if value is not None:
                    break

            if value is not None:
                parts.append(str(value).strip().lower())
            else:
                parts.append("__missing__")

        return "|".join(parts)

    def _compute_structure_key(self, output: Dict[str, Any]) -> str:
        """计算输出的结构键

        结构键由顶层键集合和各键的值类型组成。

        Args:
            output: 输出字典

        Returns:
            结构键字符串
        """
        structure_parts = []
        for key in sorted(output.keys()):
            value = output[key]
            value_type = type(value).__name__

            # 对于简单值，也纳入结构键
            if isinstance(value, (str, int, float, bool)):
                structure_parts.append(f"{key}:{value_type}:{str(value)[:30]}")
            elif isinstance(value, list):
                structure_parts.append(f"{key}:list[{len(value)}]")
            elif isinstance(value, dict):
                structure_parts.append(f"{key}:dict{{{len(value)}}}")
            else:
                structure_parts.append(f"{key}:{value_type}")

        return "|".join(structure_parts)

    def _merge_field_values(
        self, values: List[Tuple[Any, float]]
    ) -> Any:
        """合并同一字段的多个值

        策略：
        - 字符串/布尔：选择出现频率最高的值（按置信度加权）
        - 数值：计算置信度加权平均值
        - 列表：合并所有列表并去重
        - 字典：递归合并

        Args:
            values: (值, 置信度) 元组列表

        Returns:
            合并后的值
        """
        if not values:
            return None

        if len(values) == 1:
            return values[0][0]

        # 检查值的类型
        first_val = values[0][0]

        # 数值类型：加权平均
        if isinstance(first_val, (int, float)) and all(
            isinstance(v, (int, float)) for v, _ in values
        ):
            total_weight = sum(w for _, w in values)
            if total_weight > 0:
                weighted_sum = sum(v * w for v, w in values)
                result = weighted_sum / total_weight
                # 如果原始值都是整数且结果接近整数，返回整数
                if all(isinstance(v, int) for v, _ in values):
                    return round(result)
                return round(result, 4)
            return first_val

        # 列表类型：合并去重
        if isinstance(first_val, list):
            merged_list = []
            seen = set()
            for val, _ in values:
                if isinstance(val, list):
                    for item in val:
                        item_key = json.dumps(item, sort_keys=True, ensure_ascii=False) if isinstance(item, (dict, list)) else str(item)
                        if item_key not in seen:
                            seen.add(item_key)
                            merged_list.append(item)
            return merged_list

        # 字典类型：递归合并
        if isinstance(first_val, dict):
            merged_dict: Dict[str, Any] = {}
            dict_values = [(v, w) for v, w in values if isinstance(v, dict)]
            if dict_values:
                all_dict_keys: set = set()
                for d, _ in dict_values:
                    all_dict_keys.update(d.keys())
                for key in all_dict_keys:
                    sub_values = [(d[key], w) for d, w in dict_values if key in d]
                    if sub_values:
                        merged_dict[key] = self._merge_field_values(sub_values)
            return merged_dict

        # 字符串/其他类型：按置信度加权投票
        weighted_votes: Dict[str, Tuple[Any, float]] = {}
        for val, conf in values:
            val_key = str(val).strip().lower()
            if val_key in weighted_votes:
                weighted_votes[val_key] = (weighted_votes[val_key][0], weighted_votes[val_key][1] + conf)
            else:
                weighted_votes[val_key] = (val, conf)

        if weighted_votes:
            best_key = max(weighted_votes, key=lambda k: weighted_votes[k][1])
            return weighted_votes[best_key][0]

        return first_val

    @staticmethod
    def _compute_hash(content: str) -> str:
        """计算内容的 MD5 哈希

        Args:
            content: 输入字符串

        Returns:
            MD5 哈希值的十六进制字符串
        """
        return hashlib.md5(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_value(value: Any) -> Any:
        """递归归一化值

        - 字典键转小写
        - 字符串去除首尾空白
        - 列表排序（如果元素可比较）

        Args:
            value: 待归一化的值

        Returns:
            归一化后的值
        """
        if isinstance(value, dict):
            return {
                k.lower(): SelfConsistencySampler._normalize_value(v)
                for k, v in value.items()
            }
        elif isinstance(value, str):
            return value.strip()
        elif isinstance(value, list):
            normalized = [SelfConsistencySampler._normalize_value(item) for item in value]
            # 尝试排序（仅当元素均为同类型且可比较时）
            try:
                if normalized and all(isinstance(item, (str, int, float)) for item in normalized):
                    return sorted(normalized)
            except TypeError:
                pass
            return normalized
        else:
            return value

    def _update_stats(self, report: ConsistencyReport, elapsed_ms: int) -> None:
        """更新内部统计信息

        Args:
            report: 一致性报告
            elapsed_ms: 执行时间（毫秒）
        """
        self._stats["total_runs"] += 1
        self._stats["total_samples"] += report.num_samples
        self._stats["total_consistent"] += report.consistent_count
        self._stats["total_token_cost"] += sum(s.token_cost for s in report.all_samples)
        self._stats["total_execution_time_ms"] += elapsed_ms

        # 增量更新平均一致性比例
        n = self._stats["total_runs"]
        prev_avg = self._stats["avg_consistency_ratio"]
        self._stats["avg_consistency_ratio"] = prev_avg + (
            report.consistency_ratio - prev_avg
        ) / n

    def get_stats(self) -> Dict[str, Any]:
        """获取采样器统计信息

        Returns:
            统计信息字典
        """
        return dict(self._stats)


# ============================================================
# 集成辅助函数
# ============================================================

async def run_with_consistency(
    pipeline_fn: Callable,
    file_path: str,
    file_content: str,
    config: Optional[ConsistencyConfig] = None,
    **kwargs,
) -> Tuple[Dict[str, Any], ConsistencyReport]:
    """带自一致性的 Pipeline 运行包装器

    对 pipeline_fn 进行多次独立调用，分析结果一致性，
    并返回最终选择的输出和一致性报告。

    Args:
        pipeline_fn: Pipeline 函数，签名为
                     async def fn(file_path: str, file_content: str, **kwargs) -> Dict
        file_path: 待分析的文件路径
        file_content: 文件内容
        config: 自一致性采样配置，为 None 时使用默认配置
        **kwargs: 传递给 pipeline_fn 的额外参数

    Returns:
        (最终输出, 一致性报告) 元组
    """
    sampler = SelfConsistencySampler(config=config)

    # 构造 LLM 调用包装函数
    async def llm_wrapper(prompt: str, **llm_kwargs) -> Dict[str, Any]:
        """将 pipeline_fn 包装为标准的 LLM 调用接口"""
        result = await pipeline_fn(
            file_path=file_path,
            file_content=file_content,
            **kwargs,
            **llm_kwargs,
        )
        if isinstance(result, dict):
            return result
        return {"raw": result}

    # 构造 prompt（用于标识和哈希）
    prompt = f"analyze:{file_path}:{sampler._compute_hash(file_content)[:16]}"

    # 执行自一致性采样
    report = await sampler.sample(llm_wrapper, prompt)

    return (report.selected_output, report)

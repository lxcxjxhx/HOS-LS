"""运行时间预估模块

用于基于历史执行数据预测扫描时间。
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

from src.core.config import get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class TimeEstimator:
    """运行时间预估器"""

    def __init__(self):
        """初始化时间预估器"""
        self.config = get_config()
        self._history: List[Dict[str, Any]] = []
        self._save_path = os.path.join(
            os.getcwd(),
            "execution_history.json"
        )
        self._load_history()

    def record_execution(self, file_count: int, total_lines: int, 
                        vulnerability_count: int, duration: float, 
                        success: bool = True) -> None:
        """记录执行数据

        Args:
            file_count: 文件数量
            total_lines: 总行数
            vulnerability_count: 漏洞数量
            duration: 执行时间（秒）
            success: 是否成功
        """
        record = {
            "timestamp": datetime.now().isoformat(),
            "file_count": file_count,
            "total_lines": total_lines,
            "vulnerability_count": vulnerability_count,
            "duration": duration,
            "success": success
        }
        
        self._history.append(record)
        logger.info(f"Recorded execution: {file_count} files, {total_lines} lines, "
                   f"{vulnerability_count} vulnerabilities in {duration:.2f}s")
        
        # 定期保存
        if len(self._history) % 5 == 0:
            self.save_history()

    def estimate_time(self, file_count: int, total_lines: int) -> float:
        """预估执行时间

        Args:
            file_count: 文件数量
            total_lines: 总行数

        Returns:
            float: 预估执行时间（秒）
        """
        if not self._history:
            # 如果没有历史数据，使用默认估算
            return self._default_estimate(file_count, total_lines)
        
        # 基于历史数据进行估算
        similar_records = self._find_similar_records(file_count, total_lines)
        
        if not similar_records:
            # 如果没有相似记录，使用默认估算
            return self._default_estimate(file_count, total_lines)
        
        # 计算加权平均值
        estimated_time = self._calculate_weighted_average(similar_records, file_count, total_lines)
        logger.info(f"Estimated execution time: {estimated_time:.2f}s for {file_count} files, {total_lines} lines")
        return estimated_time

    def _default_estimate(self, file_count: int, total_lines: int) -> float:
        """默认时间估算

        Args:
            file_count: 文件数量
            total_lines: 总行数

        Returns:
            float: 预估执行时间（秒）
        """
        # 基于经验值的估算
        # 假设每个文件平均处理时间 + 每行代码处理时间
        base_time_per_file = 0.5  # 每个文件的基础时间
        time_per_line = 0.01  # 每行代码的处理时间
        
        estimated_time = (file_count * base_time_per_file) + (total_lines * time_per_line)
        # 至少返回1秒
        return max(1.0, estimated_time)

    def _find_similar_records(self, file_count: int, total_lines: int) -> List[Dict[str, Any]]:
        """查找相似的历史记录

        Args:
            file_count: 文件数量
            total_lines: 总行数

        Returns:
            List[Dict[str, Any]]: 相似的历史记录
        """
        similar_records = []
        
        for record in self._history:
            # 查找文件数量和代码行数相似的记录
            file_diff = abs(record["file_count"] - file_count) / max(file_count, 1)
            lines_diff = abs(record["total_lines"] - total_lines) / max(total_lines, 1)
            
            # 相似度阈值：文件数量差异不超过30%，代码行数差异不超过30%
            if file_diff <= 0.3 and lines_diff <= 0.3:
                similar_records.append(record)
        
        # 按相似度排序，取最近的10条记录
        similar_records.sort(key=lambda x: (
            abs(x["file_count"] - file_count) + 
            abs(x["total_lines"] - total_lines)
        ))
        
        return similar_records[:10]

    def _calculate_weighted_average(self, records: List[Dict[str, Any]], 
                                   file_count: int, total_lines: int) -> float:
        """计算加权平均值

        Args:
            records: 历史记录
            file_count: 文件数量
            total_lines: 总行数

        Returns:
            float: 加权平均时间
        """
        if not records:
            return self._default_estimate(file_count, total_lines)
        
        total_weight = 0.0
        weighted_sum = 0.0
        
        for record in records:
            # 计算相似度权重
            file_similarity = 1.0 - abs(record["file_count"] - file_count) / max(file_count, 1)
            lines_similarity = 1.0 - abs(record["total_lines"] - total_lines) / max(total_lines, 1)
            weight = (file_similarity + lines_similarity) / 2
            
            # 时间调整因子
            time_adjustment = (file_count / max(record["file_count"], 1)) * \
                            (total_lines / max(record["total_lines"], 1))
            adjusted_time = record["duration"] * time_adjustment
            
            weighted_sum += adjusted_time * weight
            total_weight += weight
        
        if total_weight == 0:
            return self._default_estimate(file_count, total_lines)
        
        return weighted_sum / total_weight

    def get_execution_stats(self) -> Dict[str, Any]:
        """获取执行统计

        Returns:
            Dict[str, Any]: 执行统计
        """
        if not self._history:
            return {
                "total_executions": 0,
                "average_duration": 0,
                "average_files_per_execution": 0,
                "average_lines_per_execution": 0,
                "average_vulnerabilities_per_execution": 0
            }
        
        total_duration = sum(record["duration"] for record in self._history)
        total_files = sum(record["file_count"] for record in self._history)
        total_lines = sum(record["total_lines"] for record in self._history)
        total_vulnerabilities = sum(record["vulnerability_count"] for record in self._history)
        success_count = sum(1 for record in self._history if record["success"])
        
        return {
            "total_executions": len(self._history),
            "average_duration": total_duration / len(self._history),
            "average_files_per_execution": total_files / len(self._history),
            "average_lines_per_execution": total_lines / len(self._history),
            "average_vulnerabilities_per_execution": total_vulnerabilities / len(self._history),
            "success_rate": (success_count / len(self._history)) * 100
        }

    def save_history(self) -> None:
        """保存执行历史"""
        try:
            os.makedirs(os.path.dirname(self._save_path), exist_ok=True)
            with open(self._save_path, 'w', encoding='utf-8') as f:
                json.dump(self._history, f, ensure_ascii=False, indent=2)
            logger.info(f"Saved execution history to {self._save_path}")
        except Exception as e:
            logger.error(f"Failed to save execution history: {e}")

    def _load_history(self) -> None:
        """加载执行历史"""
        try:
            if os.path.exists(self._save_path):
                with open(self._save_path, 'r', encoding='utf-8') as f:
                    self._history = json.load(f)
                logger.info(f"Loaded {len(self._history)} execution records")
        except Exception as e:
            logger.error(f"Failed to load execution history: {e}")

    def generate_report(self) -> str:
        """生成执行报告

        Returns:
            str: 执行报告
        """
        stats = self.get_execution_stats()
        
        report = f"""# 执行时间统计报告

## 总体统计
- 总执行次数: {stats['total_executions']}
- 平均执行时间: {stats['average_duration']:.2f}秒
- 平均每次执行文件数: {stats['average_files_per_execution']:.2f}
- 平均每次执行代码行数: {stats['average_lines_per_execution']:.2f}
- 平均每次执行发现漏洞数: {stats['average_vulnerabilities_per_execution']:.2f}
- 成功率: {stats['success_rate']:.2f}%

## 时间预估模型
基于历史执行数据，系统会根据文件数量和代码行数自动预估执行时间。

预估公式: 基础时间(0.5s/文件) + 代码处理时间(0.01s/行) + 历史数据修正
"""
        
        return report


# 全局时间预估器实例
_time_estimator: Optional[TimeEstimator] = None


def get_time_estimator() -> TimeEstimator:
    """获取时间预估器实例

    Returns:
        TimeEstimator: 时间预估器实例
    """
    global _time_estimator
    if _time_estimator is None:
        _time_estimator = TimeEstimator()
    return _time_estimator

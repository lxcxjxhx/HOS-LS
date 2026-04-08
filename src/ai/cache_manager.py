"""缓存管理器模块

实现文件哈希到分析结果的缓存，提高纯AI分析的性能。
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional, List

from src.ai.models import VulnerabilityFinding


class CacheManager:
    """缓存管理器

    实现文件哈希到分析结果的缓存。
    """

    def __init__(self, cache_dir: str = ".cache/pure_ai"):
        """初始化缓存管理器

        Args:
            cache_dir: 缓存目录
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def generate_cache_key(self, file_path: str, file_content: str) -> str:
        """生成缓存键

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            缓存键
        """
        # 生成文件内容的哈希
        content_hash = hashlib.md5(file_content.encode()).hexdigest()
        # 生成文件路径的哈希
        path_hash = hashlib.md5(file_path.encode()).hexdigest()
        # 组合成缓存键
        return f"{path_hash}_{content_hash}"

    def get_cache(self, cache_key: str) -> Optional[List[VulnerabilityFinding]]:
        """获取缓存

        Args:
            cache_key: 缓存键

        Returns:
            缓存的漏洞发现列表，不存在则返回None
        """
        cache_file = self.cache_dir / f"{cache_key}.json"
        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # 转换为 VulnerabilityFinding 对象
            findings = []
            for finding_data in data:
                finding = VulnerabilityFinding(**finding_data)
                findings.append(finding)
            return findings
        except Exception as e:
            print(f"[DEBUG] 读取缓存失败: {e}")
            return None

    def set_cache(self, cache_key: str, findings: List[VulnerabilityFinding]) -> bool:
        """设置缓存

        Args:
            cache_key: 缓存键
            findings: 漏洞发现列表

        Returns:
            是否成功设置缓存
        """
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            # 转换为可序列化的字典
            data = []
            for finding in findings:
                # 将对象转换为字典
                finding_dict = {
                    "rule_id": finding.rule_id,
                    "rule_name": finding.rule_name,
                    "description": finding.description,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "location": finding.location,
                    "code_snippet": finding.code_snippet,
                    "fix_suggestion": finding.fix_suggestion,
                    "explanation": finding.explanation,
                    "references": finding.references,
                    "exploit_scenario": finding.exploit_scenario
                }
                data.append(finding_dict)
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"[DEBUG] 写入缓存失败: {e}")
            return False

    def clear_cache(self) -> bool:
        """清除所有缓存

        Returns:
            是否成功清除缓存
        """
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
            return True
        except Exception as e:
            print(f"[DEBUG] 清除缓存失败: {e}")
            return False

    def get_cache_size(self) -> int:
        """获取缓存大小

        Returns:
            缓存文件数量
        """
        return len(list(self.cache_dir.glob("*.json")))

    def remove_cache(self, cache_key: str) -> bool:
        """移除指定缓存

        Args:
            cache_key: 缓存键

        Returns:
            是否成功移除缓存
        """
        cache_file = self.cache_dir / f"{cache_key}.json"
        if not cache_file.exists():
            return True
        try:
            cache_file.unlink()
            return True
        except Exception as e:
            print(f"[DEBUG] 移除缓存失败: {e}")
            return False

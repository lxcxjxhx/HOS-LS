"""评分计算器模块

实现文件优先级评分算法：
score(file) =
  keyword_match × 0.3 +
  call_chain_weight × 0.25 +
  historical_vuln_location × 0.2 +
  file_type_weight × 0.15 +
  diff_change × 0.1
"""

from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import re

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FileScore:
    """文件评分结果"""
    file_path: str
    total_score: float
    keyword_score: float
    call_chain_score: float
    historical_score: float
    file_type_score: float
    diff_score: float
    priority_level: str
    factors: List[str]


class ScoreCalculator:
    """评分计算器

    根据多个维度计算文件的安全优先级分数。
    """

    WEIGHT_KEYWORD = 0.30
    WEIGHT_CALL_CHAIN = 0.25
    WEIGHT_HISTORICAL = 0.20
    WEIGHT_FILE_TYPE = 0.15
    WEIGHT_DIFF = 0.10

    VULNERABILITY_KEYWORDS = {
        'sql', 'injection', 'command', 'exec', 'eval', 'system',
        'password', 'secret', 'key', 'token', 'credential', 'auth',
        'xss', 'script', 'html', 'innerHTML', 'document.write',
        'crypto', 'hash', 'md5', 'sha1', 'des', 'random',
        'file', 'path', 'upload', 'download', 'read', 'write',
        'permission', 'access', 'admin', 'root', 'sudo',
        'session', 'cookie', 'jwt', 'oauth', 'saml',
        'http', 'request', 'response', 'redirect', 'url',
        'database', 'query', 'cursor', 'connection',
        'process', 'subprocess', 'spawn', 'shell',
        'deserialize', 'pickle', 'yaml', 'xml',
        'ldap', 'smtp', 'ftp', 'telnet',
        'redis', 'memcached', 'cache',
        'log', 'logging', 'debug', 'error',
    }

    SECURITY_SENSITIVE_DIRS = {
        'auth', 'login', 'logout', 'signup', 'register',
        'password', 'credential', 'token', 'session',
        'admin', 'dashboard', 'config', 'setting',
        'api', 'gateway', 'middleware',
        'security', 'crypto', 'encrypt', 'decrypt',
        'payment', 'billing', 'order', 'transaction',
        'user', 'profile', 'account',
        'database', 'db', 'repository',
        'service', 'core', 'business',
    }

    FILE_TYPE_SCORES = {
        '.py': 1.0,
        '.js': 0.9,
        '.ts': 0.9,
        '.java': 0.9,
        '.go': 0.9,
        '.rb': 0.8,
        '.php': 0.8,
        '.cs': 0.8,
        '.cpp': 0.7,
        '.c': 0.7,
        '.h': 0.6,
    }

    def __init__(self):
        """初始化评分计算器"""
        self._historical_vuln_locations: Dict[str, int] = {}
        self._last_scan_files: List[str] = []

    def set_historical_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """设置历史漏洞数据

        Args:
            vulnerabilities: 历史漏洞列表
        """
        self._historical_vuln_locations.clear()

        for vuln in vulnerabilities:
            file_path = vuln.get('file_path', '')
            if file_path:
                self._historical_vuln_locations[file_path] = \
                    self._historical_vuln_locations.get(file_path, 0) + 1

    def set_last_scan_files(self, files: List[str]) -> None:
        """设置上次扫描的文件列表

        Args:
            files: 文件路径列表
        """
        self._last_scan_files = files

    def calculate_score(
        self,
        file_path: str,
        file_content: str = "",
        keyword: str = "",
        is_changed: bool = False,
        call_chain: Optional[List[str]] = None
    ) -> FileScore:
        """计算文件优先级分数

        Args:
            file_path: 文件路径
            file_content: 文件内容（可选）
            keyword: 搜索关键词（可选）
            is_changed: 文件是否已变更
            call_chain: 调用链列表（可选）

        Returns:
            文件评分结果
        """
        path_obj = Path(file_path)

        keyword_score = self._calculate_keyword_score(file_path, file_content, keyword)
        call_chain_score = self._calculate_call_chain_score(file_path, call_chain)
        historical_score = self._calculate_historical_score(file_path)
        file_type_score = self._calculate_file_type_score(path_obj)
        diff_score = self._calculate_diff_score(file_path, is_changed)

        total_score = (
            keyword_score * self.WEIGHT_KEYWORD +
            call_chain_score * self.WEIGHT_CALL_CHAIN +
            historical_score * self.WEIGHT_HISTORICAL +
            file_type_score * self.WEIGHT_FILE_TYPE +
            diff_score * self.WEIGHT_DIFF
        )

        factors = []
        if keyword_score > 0:
            factors.append(f"关键词匹配(+{keyword_score:.2f})")
        if call_chain_score > 0:
            factors.append(f"调用链(+{call_chain_score:.2f})")
        if historical_score > 0:
            factors.append(f"历史漏洞(+{historical_score:.2f})")
        if file_type_score >= 0.8:
            factors.append(f"高风险文件类型(+{file_type_score:.2f})")
        if is_changed:
            factors.append(f"已变更文件(+{diff_score:.2f})")

        if total_score >= 0.7:
            priority_level = "high"
        elif total_score >= 0.4:
            priority_level = "medium"
        else:
            priority_level = "low"

        return FileScore(
            file_path=file_path,
            total_score=total_score,
            keyword_score=keyword_score,
            call_chain_score=call_chain_score,
            historical_score=historical_score,
            file_type_score=file_type_score,
            diff_score=diff_score,
            priority_level=priority_level,
            factors=factors
        )

    def _calculate_keyword_score(
        self,
        file_path: str,
        file_content: str,
        keyword: str
    ) -> float:
        """计算关键词匹配分数

        Args:
            file_path: 文件路径
            file_content: 文件内容
            keyword: 搜索关键词

        Returns:
            分数 0.0 - 1.0
        """
        if not keyword:
            return 0.0

        score = 0.0
        keyword_lower = keyword.lower()
        path_lower = file_path.lower()
        content_lower = file_content.lower()

        if keyword_lower in path_lower:
            score += 0.5

        filename = Path(file_path).name.lower()
        if keyword_lower in filename:
            score += 0.3

        dir_parts = path_lower.split(str(Path.sep))
        for part in dir_parts:
            if keyword_lower in part and part not in ['src', 'lib', 'app', 'tests']:
                score += 0.2
                break

        if keyword_lower in content_lower:
            matches = content_lower.count(keyword_lower)
            score += min(0.5, matches * 0.05)

        return min(1.0, score)

    def _calculate_call_chain_score(
        self,
        file_path: str,
        call_chain: Optional[List[str]]
    ) -> float:
        """计算调用链分数

        Args:
            file_path: 文件路径
            call_chain: 调用链列表

        Returns:
            分数 0.0 - 1.0
        """
        if not call_chain:
            return 0.0

        file_path_lower = file_path.lower()

        for chain_file in call_chain:
            if file_path_lower in chain_file.lower() or chain_file.lower() in file_path_lower:
                return 0.8

        vuln_keywords_in_chain = [
            kw for kw in self.VULNERABILITY_KEYWORDS
            if any(kw in f.lower() for f in call_chain)
        ]

        if len(vuln_keywords_in_chain) >= 3:
            return 0.6
        elif len(vuln_keywords_in_chain) >= 1:
            return 0.3

        return 0.0

    def _calculate_historical_score(self, file_path: str) -> float:
        """计算历史漏洞分数

        Args:
            file_path: 文件路径

        Returns:
            分数 0.0 - 1.0
        """
        vuln_count = self._historical_vuln_locations.get(file_path, 0)

        if vuln_count >= 5:
            return 1.0
        elif vuln_count >= 3:
            return 0.8
        elif vuln_count >= 2:
            return 0.6
        elif vuln_count >= 1:
            return 0.4

        return 0.0

    def _calculate_file_type_score(self, path: Path) -> float:
        """计算文件类型分数

        Args:
            path: 文件路径对象

        Returns:
            分数 0.0 - 1.0
        """
        ext = path.suffix.lower()
        base_score = self.FILE_TYPE_SCORES.get(ext, 0.5)

        path_str = str(path).lower()
        for sensitive_dir in self.SECURITY_SENSITIVE_DIRS:
            if sensitive_dir in path_str:
                base_score = min(1.0, base_score + 0.2)
                break

        return base_score

    def _calculate_diff_score(self, file_path: str, is_changed: bool) -> float:
        """计算变更分数

        Args:
            file_path: 文件路径
            is_changed: 文件是否已变更

        Returns:
            分数 0.0 - 1.0
        """
        if not is_changed:
            return 0.0

        path_obj = Path(file_path)
        ext = path_obj.suffix.lower()

        if ext in ['.py', '.js', '.ts', '.java', '.go']:
            return 0.8

        if ext in ['.yaml', '.yml', '.json', '.toml', '.env']:
            return 0.5

        return 0.3

    def batch_calculate(
        self,
        files: List[Tuple[str, str]],
        keyword: str = "",
        changed_files: Optional[List[str]] = None,
        call_chains: Optional[Dict[str, List[str]]] = None
    ) -> List[FileScore]:
        """批量计算文件分数

        Args:
            files: (文件路径, 文件内容) 元组列表
            keyword: 搜索关键词
            changed_files: 变更文件列表
            call_chains: 文件调用链字典

        Returns:
            FileScore 列表，按分数降序排列
        """
        changed_set = set(changed_files) if changed_files else set()

        scores = []
        for file_path, file_content in files:
            is_changed = file_path in changed_set
            call_chain = call_chains.get(file_path) if call_chains else None

            score = self.calculate_score(
                file_path=file_path,
                file_content=file_content,
                keyword=keyword,
                is_changed=is_changed,
                call_chain=call_chain
            )
            scores.append(score)

        scores.sort(key=lambda x: x.total_score, reverse=True)
        return scores

    def get_top_k_files(self, scores: List[FileScore], top_k: int = 20) -> List[str]:
        """获取 Top-K 文件路径

        Args:
            scores: 文件分数列表
            top_k: 返回数量

        Returns:
            文件路径列表
        """
        return [s.file_path for s in scores[:top_k]]

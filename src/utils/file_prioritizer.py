"""文件优先级评估模块

实现文件名语义分析和文件重要性评估，优化特大型项目的扫描策略。
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


class FilePrioritizer:
    """文件优先级评估器

    基于文件名语义分析和文件特征评估文件的重要性。
    """

    def __init__(self):
        """初始化文件优先级评估器"""
        # 安全敏感关键词
        self.security_keywords = {
            'auth', 'login', 'password', 'credential', 'token', 'secret', 'key',
            'secure', 'encrypt', 'decrypt', 'crypto', 'hash', 'session', 'cookie',
            'admin', 'user', 'permission', 'role', 'access', 'authorization',
            'api', 'endpoint', 'route', 'controller', 'middleware', 'filter',
            'database', 'db', 'sql', 'query', 'connection', 'config', 'setting',
            'network', 'http', 'https', 'request', 'response', 'header', 'payload',
            'input', 'validation', 'sanitize', 'escape', 'inject', 'xss', 'csrf',
            'cors', 'clickjack', 'redirect', 'oauth', 'jwt', 'oauth2', 'openid'
        }

        # 高优先级文件扩展名
        self.high_priority_extensions = {
            '.py', '.js', '.ts', '.java', '.c', '.cpp', '.cs', '.go', '.rb',
            '.php', '.scala', '.swift', '.kt', '.rs', '.html', '.css', '.json',
            '.yml', '.yaml', '.xml', '.ini', '.conf', '.cfg'
        }

        # 低优先级文件扩展名
        self.low_priority_extensions = {
            '.txt', '.md', '.rst', '.log', '.tmp', '.temp', '.bak', '.backup',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.exe', '.dll', '.so', '.dylib',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.mp3', '.mp4', '.avi',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        }

        # 目录重要性权重
        self.directory_weights = {
            'auth': 0.9, 'security': 0.9, 'api': 0.8, 'routes': 0.8, 'controllers': 0.8,
            'middleware': 0.8, 'config': 0.7, 'settings': 0.7, 'database': 0.7, 'db': 0.7,
            'models': 0.6, 'views': 0.5, 'templates': 0.5, 'static': 0.3, 'public': 0.3,
            'tests': 0.2, 'docs': 0.1, 'examples': 0.1
        }

    def evaluate_file_priority(self, file_path: Path) -> Tuple[float, str]:
        """评估文件优先级

        Args:
            file_path: 文件路径

        Returns:
            (优先级分数, 优先级级别)
        """
        score = 0.0
        
        # 首先检查是否是测试文件，如果是则强制降低优先级
        filename_lower = file_path.name.lower()
        is_test_file = (
            filename_lower.startswith('test_') or
            filename_lower.endswith('_test.py') or
            filename_lower.endswith('_test.js') or
            filename_lower.endswith('_test.ts') or
            filename_lower.startswith('spec_') or
            filename_lower.endswith('_spec.py') or
            filename_lower.endswith('_spec.js') or
            filename_lower.endswith('_spec.ts') or
            'tests' in str(file_path.parent).lower() or
            '__tests__' in str(file_path.parent).lower()
        )

        # 评估文件名
        filename_score = self._evaluate_filename(file_path.name)
        score += filename_score * 0.4

        # 评估文件扩展名
        extension_score = self._evaluate_extension(file_path.suffix)
        score += extension_score * 0.3

        # 评估目录路径
        directory_score = self._evaluate_directory(file_path.parent)
        score += directory_score * 0.3
        
        # 如果是测试文件，强制降低分数
        if is_test_file:
            score = min(score * 0.3, 0.3)

        # 确定优先级级别
        if score >= 0.7:
            priority = 'high'
        elif score >= 0.4:
            priority = 'medium'
        else:
            priority = 'low'

        logger.debug(f"文件 {file_path} 优先级评估: 分数={score:.2f}, 级别={priority}, 测试文件={is_test_file}")
        return score, priority

    def _evaluate_filename(self, filename: str) -> float:
        """评估文件名

        Args:
            filename: 文件名

        Returns:
            评分 (0-1)
        """
        score = 0.0
        filename_lower = filename.lower()

        # 检查安全敏感关键词
        keyword_matches = 0
        for keyword in self.security_keywords:
            if keyword in filename_lower:
                keyword_matches += 1
                # 每个关键词增加0.1分，最多0.5分
                score = min(score + 0.1, 0.5)

        # 检查常见配置文件名
        config_patterns = ['config', 'setting', 'env', 'environment', 'secret', 'key']
        for pattern in config_patterns:
            if pattern in filename_lower:
                score = min(score + 0.3, 0.8)
                break

        # 检查API相关文件名
        api_patterns = ['api', 'endpoint', 'route', 'controller']
        for pattern in api_patterns:
            if pattern in filename_lower:
                score = min(score + 0.2, 0.7)
                break

        # 检查认证相关文件名
        auth_patterns = ['auth', 'login', 'user', 'permission']
        for pattern in auth_patterns:
            if pattern in filename_lower:
                score = min(score + 0.2, 0.7)
                break

        return score

    def _evaluate_extension(self, extension: str) -> float:
        """评估文件扩展名

        Args:
            extension: 文件扩展名

        Returns:
            评分 (0-1)
        """
        if extension in self.high_priority_extensions:
            return 0.8
        elif extension in self.low_priority_extensions:
            return 0.2
        else:
            return 0.5

    def _evaluate_directory(self, directory: Path) -> float:
        """评估目录路径

        Args:
            directory: 目录路径

        Returns:
            评分 (0-1)
        """
        score = 0.5  # 默认分数

        # 检查目录名称
        for part in directory.parts:
            part_lower = part.lower()
            for dir_name, weight in self.directory_weights.items():
                if dir_name in part_lower:
                    score = max(score, weight)
                    break

        return score

    def should_perform_ai_analysis(self, file_path: Path) -> bool:
        """判断是否应该对文件执行AI分析

        Args:
            file_path: 文件路径

        Returns:
            是否应该执行AI分析
        """
        _, priority = self.evaluate_file_priority(file_path)
        return priority in ['high', 'medium']

    def prioritize_files(self, files: List[Path]) -> List[Tuple[Path, float, str]]:
        """对文件列表进行优先级排序

        Args:
            files: 文件路径列表

        Returns:
            排序后的文件列表，包含(文件路径, 优先级分数, 优先级级别)
        """
        prioritized = []
        for file_path in files:
            score, priority = self.evaluate_file_priority(file_path)
            prioritized.append((file_path, score, priority))

        # 按优先级分数降序排序
        prioritized.sort(key=lambda x: x[1], reverse=True)
        return prioritized

    def get_high_priority_files(self, files: List[Path]) -> List[Path]:
        """获取高优先级文件

        Args:
            files: 文件路径列表

        Returns:
            高优先级文件列表
        """
        high_priority = []
        for file_path in files:
            _, priority = self.evaluate_file_priority(file_path)
            if priority == 'high':
                high_priority.append(file_path)
        return high_priority

    def get_medium_priority_files(self, files: List[Path]) -> List[Path]:
        """获取中优先级文件

        Args:
            files: 文件路径列表

        Returns:
            中优先级文件列表
        """
        medium_priority = []
        for file_path in files:
            _, priority = self.evaluate_file_priority(file_path)
            if priority == 'medium':
                medium_priority.append(file_path)
        return medium_priority

    def get_low_priority_files(self, files: List[Path]) -> List[Path]:
        """获取低优先级文件

        Args:
            files: 文件路径列表

        Returns:
            低优先级文件列表
        """
        low_priority = []
        for file_path in files:
            _, priority = self.evaluate_file_priority(file_path)
            if priority == 'low':
                low_priority.append(file_path)
        return low_priority

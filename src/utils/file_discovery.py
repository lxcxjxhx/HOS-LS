"""文件发现引擎模块

智能发现和过滤项目中的文件，支持多种文件类型识别和规则过滤。
"""

import fnmatch
import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union


class FileType(Enum):
    """文件类型"""

    SOURCE = "source"
    CONFIG = "config"
    DOCUMENTATION = "documentation"
    TEST = "test"
    BUILD = "build"
    DEPENDENCY = "dependency"
    OTHER = "other"


class Language(Enum):
    """编程语言"""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CPP = "cpp"
    C = "c"
    GO = "go"
    RUST = "rust"
    RUBY = "ruby"
    PHP = "php"
    CSHARP = "csharp"
    SWIFT = "swift"
    KOTLIN = "kotlin"
    UNKNOWN = "unknown"


@dataclass
class FileInfo:
    """文件信息"""

    path: Path
    size: int
    language: Language
    file_type: FileType
    extension: str
    encoding: str = "utf-8"
    line_count: int = 0
    hash: str = ""
    last_modified: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "path": str(self.path),
            "size": self.size,
            "language": self.language.value,
            "file_type": self.file_type.value,
            "extension": self.extension,
            "encoding": self.encoding,
            "line_count": self.line_count,
            "hash": self.hash,
            "last_modified": self.last_modified.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class DiscoveryConfig:
    """发现配置"""

    include_patterns: List[str] = field(
        default_factory=lambda: [
            "*.py",
            "*.js",
            "*.ts",
            "*.jsx",
            "*.tsx",
            "*.java",
            "*.cpp",
            "*.c",
            "*.h",
            "*.hpp",
            "*.go",
            "*.rs",
            "*.rb",
            "*.php",
            "*.cs",
            "*.swift",
            "*.kt",
            "*.yaml",
            "*.yml",
            "*.json",
            "*.toml",
            "*.ini",
            "*.cfg",
            "*.conf",
            "*.xml",
            "*.sh",
            "*.bash",
            "*.cmd",
            "*.bat",
            "*.ps1",
            "*.env",
            "*.env.local",
            "*.env.development",
            "*.env.production",
        ]
    )
    exclude_patterns: List[str] = field(
        default_factory=lambda: [
            "node_modules/**",
            "__pycache__/**",
            "*.pyc",
            "*.pyo",
            "*.pyd",
            ".git/**",
            ".svn/**",
            ".hg/**",
            ".venv/**",
            "venv/**",
            "env/**",
            "dist/**",
            "build/**",
            "*.min.js",
            "*.min.css",
            "*.bundle.js",
            "coverage/**",
            ".coverage/**",
            "*.egg-info/**",
            ".eggs/**",
            ".tox/**",
            ".pytest_cache/**",
            ".mypy_cache/**",
            "*.log",
            "*.tmp",
            "*.bak",
            "*.swp",
            "*.swo",
            "*~",
            ".DS_Store",
            "Thumbs.db",
        ]
    )
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    min_file_size: int = 0
    follow_symlinks: bool = False
    max_depth: int = 100
    exclude_hidden: bool = True


class FileDiscoveryEngine:
    """文件发现引擎

    智能发现和过滤项目中的文件。
    """

    LANGUAGE_MAP: Dict[str, Language] = {
        ".py": Language.PYTHON,
        ".js": Language.JAVASCRIPT,
        ".ts": Language.TYPESCRIPT,
        ".jsx": Language.JAVASCRIPT,
        ".tsx": Language.TYPESCRIPT,
        ".java": Language.JAVA,
        ".cpp": Language.CPP,
        ".cxx": Language.CPP,
        ".cc": Language.CPP,
        ".c": Language.C,
        ".h": Language.C,
        ".hpp": Language.CPP,
        ".hxx": Language.CPP,
        ".go": Language.GO,
        ".rs": Language.RUST,
        ".rb": Language.RUBY,
        ".php": Language.PHP,
        ".cs": Language.CSHARP,
        ".swift": Language.SWIFT,
        ".kt": Language.KOTLIN,
        ".kts": Language.KOTLIN,
        ".sh": Language.UNKNOWN,
        ".bash": Language.UNKNOWN,
        ".cmd": Language.UNKNOWN,
        ".bat": Language.UNKNOWN,
        ".ps1": Language.UNKNOWN,
        ".yaml": Language.UNKNOWN,
        ".yml": Language.UNKNOWN,
        ".json": Language.UNKNOWN,
        ".toml": Language.UNKNOWN,
        ".ini": Language.UNKNOWN,
        ".cfg": Language.UNKNOWN,
        ".conf": Language.UNKNOWN,
        ".xml": Language.UNKNOWN,
        ".env": Language.UNKNOWN,
    }

    FILE_TYPE_MAP: Dict[str, FileType] = {
        "test": FileType.TEST,
        "tests": FileType.TEST,
        "spec": FileType.TEST,
        "__tests__": FileType.TEST,
        "__test__": FileType.TEST,
        "docs": FileType.DOCUMENTATION,
        "doc": FileType.DOCUMENTATION,
        "documentation": FileType.DOCUMENTATION,
        "config": FileType.CONFIG,
        "configs": FileType.CONFIG,
        "build": FileType.BUILD,
        "dist": FileType.BUILD,
        "node_modules": FileType.DEPENDENCY,
        "vendor": FileType.DEPENDENCY,
        "third_party": FileType.DEPENDENCY,
    }

    def __init__(self, config: Optional[DiscoveryConfig] = None):
        """初始化文件发现引擎

        Args:
            config: 发现配置
        """
        self.config = config or DiscoveryConfig()
        self._file_cache: Dict[str, FileInfo] = {}

    def discover_files(
        self,
        root_path: Union[str, Path],
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        max_file_size: Optional[int] = None,
    ) -> List[FileInfo]:
        """发现文件

        Args:
            root_path: 根目录路径
            include_patterns: 包含模式列表
            exclude_patterns: 排除模式列表
            max_file_size: 最大文件大小

        Returns:
            发现的文件信息列表
        """
        root = Path(root_path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"路径不存在: {root}")

        if not root.is_dir():
            raise NotADirectoryError(f"不是目录: {root}")

        include = include_patterns or self.config.include_patterns
        exclude = exclude_patterns or self.config.exclude_patterns
        max_size = max_file_size or self.config.max_file_size

        files: List[FileInfo] = []
        visited: Set[str] = set()

        for current_root, dirs, filenames in os.walk(
            root, followlinks=self.config.follow_symlinks
        ):
            current_path = Path(current_root)

            if self._should_skip_directory(current_path, exclude, visited):
                dirs[:] = []
                continue

            depth = len(current_path.relative_to(root).parts)
            if depth > self.config.max_depth:
                dirs[:] = []
                continue

            for filename in filenames:
                file_path = current_path / filename

                if self._should_skip_file(file_path, exclude):
                    continue

                if not self._matches_patterns(file_path, include):
                    continue

                try:
                    file_info = self.get_file_metadata(file_path)

                    if file_info.size > max_size:
                        continue

                    if file_info.size < self.config.min_file_size:
                        continue

                    files.append(file_info)
                except (OSError, PermissionError, UnicodeDecodeError):
                    continue

        return files

    def filter_by_language(
        self,
        files: List[FileInfo],
        languages: List[Union[Language, str]],
    ) -> List[FileInfo]:
        """按语言过滤文件

        Args:
            files: 文件列表
            languages: 语言列表

        Returns:
            过滤后的文件列表
        """
        language_set: Set[Language] = set()
        for lang in languages:
            if isinstance(lang, str):
                try:
                    language_set.add(Language(lang.lower()))
                except ValueError:
                    continue
            else:
                language_set.add(lang)

        return [f for f in files if f.language in language_set]

    def filter_by_type(
        self,
        files: List[FileInfo],
        file_types: List[Union[FileType, str]],
    ) -> List[FileInfo]:
        """按文件类型过滤

        Args:
            files: 文件列表
            file_types: 文件类型列表

        Returns:
            过滤后的文件列表
        """
        type_set: Set[FileType] = set()
        for ft in file_types:
            if isinstance(ft, str):
                try:
                    type_set.add(FileType(ft.lower()))
                except ValueError:
                    continue
            else:
                type_set.add(ft)

        return [f for f in files if f.file_type in type_set]

    def filter_by_size(
        self,
        files: List[FileInfo],
        min_size: int = 0,
        max_size: Optional[int] = None,
    ) -> List[FileInfo]:
        """按文件大小过滤

        Args:
            files: 文件列表
            min_size: 最小文件大小
            max_size: 最大文件大小

        Returns:
            过滤后的文件列表
        """
        result = [f for f in files if f.size >= min_size]

        if max_size is not None:
            result = [f for f in result if f.size <= max_size]

        return result

    def filter_by_custom(
        self,
        files: List[FileInfo],
        predicate: Callable[[FileInfo], bool],
    ) -> List[FileInfo]:
        """自定义过滤

        Args:
            files: 文件列表
            predicate: 过滤谓词

        Returns:
            过滤后的文件列表
        """
        return [f for f in files if predicate(f)]

    def get_file_metadata(self, file_path: Union[str, Path]) -> FileInfo:
        """获取文件元数据

        Args:
            file_path: 文件路径

        Returns:
            文件信息
        """
        path = Path(file_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {path}")

        if not path.is_file():
            raise ValueError(f"不是文件: {path}")

        stat = path.stat()
        extension = path.suffix.lower()
        language = self._detect_language(extension)
        file_type = self._detect_file_type(path)

        line_count = 0
        encoding = "utf-8"
        file_hash = ""

        try:
            with open(path, "rb") as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()

                try:
                    text = content.decode("utf-8")
                    encoding = "utf-8"
                    line_count = text.count("\n") + 1
                except UnicodeDecodeError:
                    try:
                        text = content.decode("latin-1")
                        encoding = "latin-1"
                        line_count = text.count("\n") + 1
                    except UnicodeDecodeError:
                        encoding = "binary"
                        line_count = 0
        except (OSError, PermissionError):
            pass

        return FileInfo(
            path=path,
            size=stat.st_size,
            language=language,
            file_type=file_type,
            extension=extension,
            encoding=encoding,
            line_count=line_count,
            hash=file_hash,
            last_modified=datetime.fromtimestamp(stat.st_mtime),
        )

    def group_by_language(self, files: List[FileInfo]) -> Dict[Language, List[FileInfo]]:
        """按语言分组

        Args:
            files: 文件列表

        Returns:
            按语言分组的文件字典
        """
        groups: Dict[Language, List[FileInfo]] = {}
        for file_info in files:
            if file_info.language not in groups:
                groups[file_info.language] = []
            groups[file_info.language].append(file_info)
        return groups

    def group_by_type(self, files: List[FileInfo]) -> Dict[FileType, List[FileInfo]]:
        """按文件类型分组

        Args:
            files: 文件列表

        Returns:
            按文件类型分组的文件字典
        """
        groups: Dict[FileType, List[FileInfo]] = {}
        for file_info in files:
            if file_info.file_type not in groups:
                groups[file_info.file_type] = []
            groups[file_info.file_type].append(file_info)
        return groups

    def get_statistics(self, files: List[FileInfo]) -> Dict[str, Any]:
        """获取统计信息

        Args:
            files: 文件列表

        Returns:
            统计信息字典
        """
        if not files:
            return {
                "total_files": 0,
                "total_size": 0,
                "total_lines": 0,
                "by_language": {},
                "by_type": {},
                "avg_size": 0,
                "avg_lines": 0,
            }

        total_size = sum(f.size for f in files)
        total_lines = sum(f.line_count for f in files)

        by_language: Dict[str, int] = {}
        for lang, group in self.group_by_language(files).items():
            by_language[lang.value] = len(group)

        by_type: Dict[str, int] = {}
        for ft, group in self.group_by_type(files).items():
            by_type[ft.value] = len(group)

        return {
            "total_files": len(files),
            "total_size": total_size,
            "total_lines": total_lines,
            "by_language": by_language,
            "by_type": by_type,
            "avg_size": total_size / len(files),
            "avg_lines": total_lines / len(files),
        }

    def _detect_language(self, extension: str) -> Language:
        """检测语言

        Args:
            extension: 文件扩展名

        Returns:
            语言类型
        """
        return self.LANGUAGE_MAP.get(extension, Language.UNKNOWN)

    def _detect_file_type(self, file_path: Path) -> FileType:
        """检测文件类型

        Args:
            file_path: 文件路径

        Returns:
            文件类型
        """
        path_str = str(file_path).lower()

        for keyword, file_type in self.FILE_TYPE_MAP.items():
            if keyword in path_str:
                return file_type

        if "test" in file_path.stem.lower() or "spec" in file_path.stem.lower():
            return FileType.TEST

        if file_path.suffix.lower() in [".md", ".rst", ".txt", ".adoc"]:
            return FileType.DOCUMENTATION

        if file_path.suffix.lower() in [
            ".yaml",
            ".yml",
            ".json",
            ".toml",
            ".ini",
            ".cfg",
            ".conf",
            ".xml",
        ]:
            return FileType.CONFIG

        if file_path.suffix.lower() in [".py", ".js", ".ts", ".java", ".cpp", ".c", ".go", ".rs"]:
            return FileType.SOURCE

        return FileType.OTHER

    def _should_skip_directory(
        self,
        dir_path: Path,
        exclude_patterns: List[str],
        visited: Set[str],
    ) -> bool:
        """判断是否跳过目录

        Args:
            dir_path: 目录路径
            exclude_patterns: 排除模式列表
            visited: 已访问路径集合

        Returns:
            是否跳过
        """
        try:
            real_path = str(dir_path.resolve())

            if real_path in visited:
                return True

            visited.add(real_path)

            if self.config.exclude_hidden and dir_path.name.startswith("."):
                return True

            dir_name = dir_path.name
            for pattern in exclude_patterns:
                if pattern.endswith("/**"):
                    if fnmatch.fnmatch(dir_name, pattern[:-3]):
                        return True
                elif fnmatch.fnmatch(dir_name, pattern):
                    return True

            return False
        except (OSError, PermissionError):
            return True

    def _should_skip_file(
        self,
        file_path: Path,
        exclude_patterns: List[str],
    ) -> bool:
        """判断是否跳过文件

        Args:
            file_path: 文件路径
            exclude_patterns: 排除模式列表

        Returns:
            是否跳过
        """
        if self.config.exclude_hidden and file_path.name.startswith("."):
            return True

        for pattern in exclude_patterns:
            if fnmatch.fnmatch(file_path.name, pattern):
                return True

            if "/" in pattern:
                rel_path = str(file_path)
                if fnmatch.fnmatch(rel_path, pattern):
                    return True

        return False

    def _matches_patterns(
        self,
        file_path: Path,
        patterns: List[str],
    ) -> bool:
        """判断文件是否匹配模式

        Args:
            file_path: 文件路径
            patterns: 模式列表

        Returns:
            是否匹配
        """
        if not patterns:
            return True

        for pattern in patterns:
            if fnmatch.fnmatch(file_path.name, pattern):
                return True

            if "/" in pattern:
                rel_path = str(file_path)
                if fnmatch.fnmatch(rel_path, pattern):
                    return True

        return False

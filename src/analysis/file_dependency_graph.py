"""文件依赖图模块

构建和分析项目文件的依赖关系图，支持跨文件漏洞检测。
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FileNode:
    """文件节点"""
    path: str
    name: str
    extension: str
    imports: List[str] = field(default_factory=list)
    imported_by: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    line_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class FileDependencyGraph:
    """文件依赖图

    构建项目的文件依赖关系图，支持：
    - 解析各种语言的 import/require/include 语句
    - 查找文件调用链
    - 查找相关文件
    - 支持跨文件漏洞分析
    """

    LANGUAGE_PATTERNS = {
        'python': {
            'import': r'^(?:from\s+([^\s;]+)\s+)?import\s+(.+)$',
            'require': r'^require\s+[\'"]([^\'"]+)[\'"]',
        },
        'javascript': {
            'import': r'^import\s+.*?from\s+[\'"]([^\'"]+)[\'"]',
            'require': r'^const\s+\w+\s+=\s+require\s*\([\'"]([^\'"]+)[\'"]\)',
            'dynamic_import': r'import\s*\([\'"]([^\'"]+)[\'"]\)',
        },
        'typescript': {
            'import': r'^import\s+.*?from\s+[\'"]([^\'"]+)[\'"]',
            'require': r'^const\s+\w+\s+=\s+require\s*\([\'"]([^\'"]+)[\'"]\)',
            'export': r'^export\s+(?:default\s+)?(?:const|let|var|function|class)\s+(\w+)',
        },
        'java': {
            'import': r'^import\s+([\w.]+);',
            'package': r'^package\s+([\w.]+);',
        },
        'go': {
            'import': r'^import\s+(?:\([\s\S]*?\)|[\'"]([^\'"]+)[\'"])',
        },
        'rust': {
            'use': r'^use\s+([\w:]+)',
            'mod': r'^mod\s+(\w+)',
        },
        'csharp': {
            'using': r'^using\s+([\w.]+);',
            'import': r'^using\s+[\w.]+\s*=\s*[\w.]+;',
        },
    }

    SINK_PATTERNS = {
        'python': ['eval', 'exec', 'compile', 'open', 'os.system', 'os.popen', 'subprocess'],
        'javascript': ['eval', 'Function', 'setTimeout', 'setInterval', 'document.write', 'innerHTML'],
        'java': ['exec', 'Runtime.exec', 'ProcessBuilder', 'Class.forName', 'ScriptEngine'],
    }

    def __init__(self, project_root: str):
        """初始化文件依赖图

        Args:
            project_root: 项目根目录
        """
        self.project_root = Path(project_root)
        self.nodes: Dict[str, FileNode] = {}
        self.edges: List[Tuple[str, str]] = []
        self._import_patterns = self._get_language_patterns()

    def _get_language_patterns(self) -> Dict[str, re.Pattern]:
        """获取当前项目的语言模式"""
        patterns = {}
        for lang, lang_patterns in self.LANGUAGE_PATTERNS.items():
            patterns[lang] = {}
            for pattern_type, pattern_str in lang_patterns.items():
                patterns[lang][pattern_type] = re.compile(pattern_str, re.MULTILINE)
        return patterns

    def detect_language(self, file_path: str) -> str:
        """检测文件语言

        Args:
            file_path: 文件路径

        Returns:
            语言类型
        """
        ext = Path(file_path).suffix.lower()
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rs': 'rust',
            '.cs': 'csharp',
        }
        return lang_map.get(ext, 'unknown')

    def parse_imports(self, file_path: str, content: str) -> List[str]:
        """解析文件中的导入语句

        Args:
            file_path: 文件路径
            content: 文件内容

        Returns:
            导入的模块/文件列表
        """
        imports = []
        lang = self.detect_language(file_path)

        if lang not in self._import_patterns:
            return imports

        patterns = self._import_patterns[lang]

        for pattern_type, pattern in patterns.items():
            matches = pattern.findall(content)
            for match in matches:
                if isinstance(match, tuple):
                    for m in match:
                        if m and not m.startswith('_'):
                            imports.append(m)
                elif match and not match.startswith('_'):
                    imports.append(match)

        return imports

    def add_file(self, file_path: str, content: str = "") -> FileNode:
        """添加文件到依赖图

        Args:
            file_path: 文件路径
            content: 文件内容

        Returns:
            文件节点
        """
        path = Path(file_path)
        node = FileNode(
            path=str(path),
            name=path.name,
            extension=path.suffix,
            imports=self.parse_imports(file_path, content) if content else [],
            line_count=len(content.splitlines()) if content else 0,
        )
        self.nodes[str(path)] = node
        return node

    def build_edges(self) -> None:
        """构建依赖边"""
        self.edges = []
        for node_path, node in self.nodes.items():
            for imported in node.imports:
                resolved = self._resolve_import(node_path, imported)
                if resolved and resolved in self.nodes:
                    self.edges.append((node_path, resolved))
                    node.imported_by.append(resolved)

    def _resolve_import(self, from_file: str, import_stmt: str) -> Optional[str]:
        """解析导入语句到实际文件路径

        Args:
            from_file: 源文件路径
            import_stmt: 导入语句

        Returns:
            解析后的文件路径
        """
        from_path = Path(from_file)
        base_dir = from_path.parent

        import_name = import_stmt.split('.')[0]

        candidates = [
            base_dir / f"{import_name}.py",
            base_dir / import_name / "__init__.py",
            self.project_root / "src" / f"{import_name}.py",
            self.project_root / import_name / "__init__.py",
        ]

        for candidate in candidates:
            if candidate.exists() and str(candidate) in self.nodes:
                return str(candidate)

        return None

    def get_related_files(self, file_path: str, depth: int = 1) -> List[str]:
        """获取相关文件

        Args:
            file_path: 文件路径
            depth: 查找深度

        Returns:
            相关文件路径列表
        """
        if file_path not in self.nodes:
            return []

        related = set()
        to_visit = [(file_path, 0)]
        visited = set()

        while to_visit:
            current, current_depth = to_visit.pop(0)
            if current in visited or current_depth > depth:
                continue
            visited.add(current)

            node = self.nodes.get(current)
            if not node:
                continue

            for imported in node.imports:
                resolved = self._resolve_import(current, imported)
                if resolved and resolved not in visited:
                    related.add(resolved)
                    to_visit.append((resolved, current_depth + 1))

            for importer in node.imported_by:
                if importer not in visited:
                    related.add(importer)
                    to_visit.append((importer, current_depth + 1))

        return list(related)

    def get_call_chain(self, source: str, sink: str, max_length: int = 10) -> List[str]:
        """获取两个文件之间的调用链

        Args:
            source: 源文件路径
            sink: 目标文件路径
            max_length: 最大链长度

        Returns:
            调用链路径
        """
        if source not in self.nodes or sink not in self.nodes:
            return []

        visited = set()
        queue = [(source, [source])]

        while queue:
            current, path = queue.pop(0)
            if current == sink:
                return path
            if len(path) > max_length:
                continue
            if current in visited:
                continue
            visited.add(current)

            node = self.nodes.get(current)
            if not node:
                continue

            for imported in node.imports:
                resolved = self._resolve_import(current, imported)
                if resolved and resolved not in visited:
                    new_path = path + [resolved]
                    queue.append((resolved, new_path))

        return []

    def find_cross_file_vulnerability(self, entry_file: str, sink_patterns: List[str] = None) -> Dict[str, Any]:
        """查找跨文件漏洞模式

        Args:
            entry_file: 入口文件
            sink_patterns: 危险函数模式列表

        Returns:
            跨文件漏洞信息
        """
        if entry_file not in self.nodes:
            return {}

        chain = self.get_call_chain(entry_file, "")
        if not chain:
            return {}

        vulnerability = {
            'entry_file': entry_file,
            'chain': chain,
            'chain_length': len(chain),
            'involved_files': chain,
        }

        return vulnerability

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'project_root': str(self.project_root),
            'nodes': {
                path: {
                    'name': node.name,
                    'extension': node.extension,
                    'imports': node.imports,
                    'imported_by': node.imported_by,
                    'functions': node.functions,
                    'classes': node.classes,
                    'line_count': node.line_count,
                }
                for path, node in self.nodes.items()
            },
            'edges': [{'source': s, 'target': t} for s, t in self.edges],
        }


def build_file_dependency_graph(project_root: str, files: List[Tuple[str, str]]) -> FileDependencyGraph:
    """构建文件依赖图

    Args:
        project_root: 项目根目录
        files: 文件列表 [(file_path, content), ...]

    Returns:
        FileDependencyGraph 实例
    """
    graph = FileDependencyGraph(project_root)

    for file_path, content in files:
        graph.add_file(file_path, content)

    graph.build_edges()
    return graph

"""文件索引模块

管理代码索引，支持函数级 chunk 存储和增量更新。
"""

import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import re

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CodeChunk:
    """代码块"""
    chunk_id: str
    file_path: str
    function_name: str
    content: str
    line_start: int
    line_end: int
    language: str
    ast_type: str
    embedding_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chunk_id': self.chunk_id,
            'file_path': self.file_path,
            'function_name': self.function_name,
            'content': self.content,
            'line_start': self.line_start,
            'line_end': self.line_end,
            'language': self.language,
            'ast_type': self.ast_type,
            'embedding_hash': self.embedding_hash
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CodeChunk':
        return cls(
            chunk_id=data['chunk_id'],
            file_path=data['file_path'],
            function_name=data['function_name'],
            content=data['content'],
            line_start=data['line_start'],
            line_end=data['line_end'],
            language=data['language'],
            ast_type=data['ast_type'],
            embedding_hash=data.get('embedding_hash', '')
        )


class FileIndex:
    """文件索引管理器

    管理代码的文件级和函数级索引，支持增量更新。
    """

    FUNCTION_PATTERNS = {
        'python': [
            (r'^def\s+(\w+)\s*\(', 'function'),
            (r'^async\s+def\s+(\w+)\s*\(', 'function'),
            (r'^class\s+(\w+)\s*[\(:]', 'class'),
            (r'^async\s+for\s+', 'async_for'),
            (r'^async\s+with\s+', 'async_with'),
        ],
        'javascript': [
            (r'^function\s+(\w+)\s*\(', 'function'),
            (r'^const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>', 'arrow_function'),
            (r'^class\s+(\w+)', 'class'),
            (r'^async\s+function\s+(\w+)\s*\(', 'async_function'),
        ],
        'java': [
            (r'^(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:void|int|String|Object|\w+)\s+(\w+)\s*\(', 'method'),
            (r'^class\s+(\w+)', 'class'),
            (r'^interface\s+(\w+)', 'interface'),
            (r'^enum\s+(\w+)', 'enum'),
        ],
        'go': [
            (r'^func\s+(\w+)\s*\(', 'function'),
            (r'^func\s+\((\w+)\s+\*?\w+\)\s+(\w+)\s*\(', 'method'),
            (r'^type\s+(\w+)\s+struct', 'struct'),
            (r'^type\s+(\w+)\s+interface', 'interface'),
        ],
    }

    def __init__(self, index_path: Optional[Path] = None):
        """初始化文件索引

        Args:
            index_path: 索引存储路径
        """
        self.index_path = index_path or Path.home() / '.hos_ls' / 'file_index'
        self.index_path.mkdir(parents=True, exist_ok=True)

        self.chunks_file = self.index_path / 'chunks.json'
        self.merkle_file = self.index_path / 'merkle.json'
        self.file_merkle_file = self.index_path / 'file_merkle.json'

        self._chunks: Dict[str, CodeChunk] = {}
        self._file_chunks: Dict[str, List[str]] = {}
        self._merkle_tree: Dict[str, str] = {}
        self._file_merkle: Dict[str, str] = {}

        self._load()

    def _generate_chunk_id(self, file_path: str, line_start: int, content_hash: str) -> str:
        """生成 chunk ID

        Args:
            file_path: 文件路径
            line_start: 开始行号
            content_hash: 内容哈希

        Returns:
            chunk ID
        """
        data = f"{file_path}:{line_start}:{content_hash}"
        return hashlib.md5(data.encode()).hexdigest()[:16]

    def _compute_merkle_leaf(self, chunk: CodeChunk) -> str:
        """计算叶节点 Merkle 值

        Args:
            chunk: 代码块

        Returns:
            Merkle 哈希值
        """
        data = f"{chunk.file_path}:{chunk.line_start}:{chunk.line_end}:{chunk.content}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _compute_merkle_node(self, left: str, right: str) -> str:
        """计算内部节点 Merkle 值

        Args:
            left: 左子节点哈希
            right: 右子节点哈希

        Returns:
            Merkle 哈希值
        """
        data = f"{left}:{right}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _compute_file_merkle(self, file_path: str, chunks: List[CodeChunk]) -> str:
        """计算文件的 Merkle 树根值

        Args:
            file_path: 文件路径
            chunks: 文件的代码块列表

        Returns:
            Merkle 根哈希值
        """
        if not chunks:
            return hashlib.sha256(file_path.encode()).hexdigest()

        chunk_hashes = [self._compute_merkle_leaf(chunk) for chunk in chunks]

        while len(chunk_hashes) > 1:
            if len(chunk_hashes) % 2 == 1:
                chunk_hashes.append(chunk_hashes[-1])

            new_level = []
            for i in range(0, len(chunk_hashes), 2):
                new_level.append(self._compute_merkle_node(chunk_hashes[i], chunk_hashes[i + 1]))
            chunk_hashes = new_level

        return chunk_hashes[0]

    def _compute_content_hash(self, content: str) -> str:
        """计算内容哈希

        Args:
            content: 内容

        Returns:
            哈希值
        """
        return hashlib.sha256(content.encode()).hexdigest()

    def index_file(self, file_path: str, content: str, language: str) -> List[CodeChunk]:
        """索引文件

        Args:
            file_path: 文件路径
            content: 文件内容
            language: 编程语言

        Returns:
            索引的代码块列表
        """
        lines = content.split('\n')
        chunks = self._split_into_chunks(file_path, content, language)

        old_merkle = self._file_merkle.get(file_path, '')
        new_chunks = []

        for chunk in chunks:
            content_hash = self._compute_content_hash(chunk.content)
            chunk.chunk_id = self._generate_chunk_id(file_path, chunk.line_start, content_hash)
            chunk.embedding_hash = content_hash

            self._chunks[chunk.chunk_id] = chunk

            if chunk.file_path not in self._file_chunks:
                self._file_chunks[chunk.file_path] = []
            self._file_chunks[chunk.file_path].append(chunk.chunk_id)

            new_chunks.append(chunk)

        new_merkle = self._compute_file_merkle(file_path, new_chunks)
        self._file_merkle[file_path] = new_merkle
        self._merkle_tree[file_path] = new_merkle

        self._save()

        logger.debug(f"索引文件 {file_path}: {len(new_chunks)} chunks, merkle: {new_merkle[:16]}...")
        return new_chunks

    def _split_into_chunks(self, file_path: str, content: str, language: str) -> List[CodeChunk]:
        """将文件内容分割成代码块

        Args:
            file_path: 文件路径
            content: 文件内容
            language: 编程语言

        Returns:
            代码块列表
        """
        chunks = []
        lines = content.split('\n')

        patterns = self.FUNCTION_PATTERNS.get(language, [])

        function_boundaries = []
        for i, line in enumerate(lines):
            for pattern, ast_type in patterns:
                if re.match(pattern, line.strip()):
                    function_boundaries.append((i + 1, line.strip(), ast_type))
                    break

        if not function_boundaries:
            chunks.append(CodeChunk(
                chunk_id="",
                file_path=file_path,
                function_name="<module>",
                content=content,
                line_start=1,
                line_end=len(lines),
                language=language,
                ast_type="module"
            ))
            return chunks

        for idx, (line_num, line_content, ast_type) in enumerate(function_boundaries):
            start_line = line_num

            if idx + 1 < len(function_boundaries):
                end_line = function_boundaries[idx + 1][0] - 1
            else:
                end_line = len(lines)

            func_lines = lines[start_line - 1:end_line]
            func_content = '\n'.join(func_lines)

            match = re.match(r'^def\s+(\w+)|class\s+(\w+)|function\s+(\w+)', line_content.strip())
            func_name = "anonymous"
            if match:
                func_name = next(g for g in match.groups() if g) if match.groups() else "anonymous"

            chunks.append(CodeChunk(
                chunk_id="",
                file_path=file_path,
                function_name=func_name,
                content=func_content,
                line_start=start_line,
                line_end=end_line,
                language=language,
                ast_type=ast_type
            ))

        return chunks

    def get_file_chunks(self, file_path: str) -> List[CodeChunk]:
        """获取文件的代码块

        Args:
            file_path: 文件路径

        Returns:
            代码块列表
        """
        chunk_ids = self._file_chunks.get(file_path, [])
        return [self._chunks[cid] for cid in chunk_ids if cid in self._chunks]

    def get_chunk(self, chunk_id: str) -> Optional[CodeChunk]:
        """获取代码块

        Args:
            chunk_id: 代码块 ID

        Returns:
            代码块或 None
        """
        return self._chunks.get(chunk_id)

    def has_file_changed(self, file_path: str, content: str) -> Tuple[bool, str]:
        """检查文件是否已变更

        Args:
            file_path: 文件路径
            content: 新内容

        Returns:
            (是否变更, 变更类型)
        """
        if file_path not in self._file_merkle:
            return True, "new"

        chunks = self._split_into_chunks(file_path, content, self._detect_language(file_path))
        new_merkle = self._compute_file_merkle(file_path, chunks)
        old_merkle = self._file_merkle[file_path]

        if new_merkle != old_merkle:
            return True, "modified"

        return False, "unchanged"

    def _detect_language(self, file_path: str) -> str:
        """检测编程语言

        Args:
            file_path: 文件路径

        Returns:
            语言名称
        """
        ext = Path(file_path).suffix.lower()
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.jsx': 'javascript',
            '.tsx': 'javascript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'javascript',
            '.php': 'javascript',
        }
        return lang_map.get(ext, 'python')

    def detect_changes(self, files: List[Tuple[str, str]]) -> Dict[str, str]:
        """检测文件变更

        Args:
            files: (文件路径, 新内容) 列表

        Returns:
            {文件路径: 变更类型} 字典
        """
        changes = {}

        for file_path, content in files:
            is_changed, change_type = self.has_file_changed(file_path, content)
            if is_changed:
                changes[file_path] = change_type

        return changes

    def remove_file(self, file_path: str) -> bool:
        """移除文件索引

        Args:
            file_path: 文件路径

        Returns:
            是否成功移除
        """
        if file_path not in self._file_chunks:
            return False

        chunk_ids = self._file_chunks[file_path]
        for chunk_id in chunk_ids:
            if chunk_id in self._chunks:
                del self._chunks[chunk_id]

        del self._file_chunks[file_path]

        if file_path in self._file_merkle:
            del self._file_merkle[file_path]

        if file_path in self._merkle_tree:
            del self._merkle_tree[file_path]

        self._save()
        return True

    def get_stats(self) -> Dict[str, Any]:
        """获取索引统计

        Returns:
            统计信息字典
        """
        return {
            'total_chunks': len(self._chunks),
            'indexed_files': len(self._file_chunks),
            'total_lines': sum(
                chunk.line_end - chunk.line_start + 1
                for chunk in self._chunks.values()
            )
        }

    def _save(self) -> None:
        """保存索引到磁盘"""
        try:
            chunks_data = {
                chunk_id: chunk.to_dict()
                for chunk_id, chunk in self._chunks.items()
            }

            with open(self.chunks_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'chunks': chunks_data,
                    'file_chunks': self._file_chunks,
                    'file_merkle': self._file_merkle,
                    'merkle_tree': self._merkle_tree
                }, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"保存索引失败: {e}")

    def _load(self) -> None:
        """从磁盘加载索引"""
        try:
            if not self.chunks_file.exists():
                return

            with open(self.chunks_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self._chunks = {
                chunk_id: CodeChunk.from_dict(chunk_data)
                for chunk_id, chunk_data in data.get('chunks', {}).items()
            }

            self._file_chunks = data.get('file_chunks', {})
            self._file_merkle = data.get('file_merkle', {})
            self._merkle_tree = data.get('merkle_tree', {})

            logger.debug(f"加载索引: {len(self._chunks)} chunks, {len(self._file_chunks)} files")

        except Exception as e:
            logger.warning(f"加载索引失败: {e}")
            self._chunks = {}
            self._file_chunks = {}
            self._file_merkle = {}
            self._merkle_tree = {}

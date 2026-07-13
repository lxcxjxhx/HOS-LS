"""分块处理器

实现代码分块处理，提高分析效率和内存使用。
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import hashlib


class ChunkProcessor:
    """分块处理器
    
    将大文件分成小块进行分析，提高分析效率和内存使用。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化分块处理器
        
        Args:
            config: 配置参数
        """
        self.config = config or {}
        self.max_chunk_size = self.config.get('max_chunk_size', 1000)
        self.overlap_size = self.config.get('overlap_size', 100)
        self.min_chunk_size = self.config.get('min_chunk_size', 100)

    def chunk_file(self, file_path: str) -> List[Dict[str, Any]]:
        """将文件分成小块
        
        Args:
            file_path: 文件路径
            
        Returns:
            分块列表，每个分块包含内容和元数据
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            chunks = self.chunk_content(content, file_path)
            return chunks
        except Exception as e:
            return [{
                'content': '',
                'file_path': file_path,
                'start_line': 1,
                'end_line': 1,
                'chunk_id': hashlib.md5(f"{file_path}:1-1".encode()).hexdigest(),
                'error': str(e)
            }]

    def chunk_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """将内容分成小块
        
        Args:
            content: 文件内容
            file_path: 文件路径
            
        Returns:
            分块列表
        """
        lines = content.split('\n')
        total_lines = len(lines)
        chunks = []
        
        start_line = 1
        while start_line <= total_lines:
            end_line = min(start_line + self.max_chunk_size - 1, total_lines)
            
            # 确保分块大小不小于最小阈值
            if end_line - start_line + 1 < self.min_chunk_size and end_line < total_lines:
                end_line = min(start_line + self.min_chunk_size - 1, total_lines)
            
            # 提取分块内容
            chunk_lines = lines[start_line-1:end_line]
            chunk_content = '\n'.join(chunk_lines)
            
            # 生成分块ID
            chunk_id = hashlib.md5(f"{file_path}:{start_line}-{end_line}".encode()).hexdigest()
            
            # 添加分块
            chunks.append({
                'content': chunk_content,
                'file_path': file_path,
                'start_line': start_line,
                'end_line': end_line,
                'chunk_id': chunk_id,
                'total_lines': total_lines,
                'chunk_index': len(chunks)
            })
            
            # 计算下一个分块的起始行（考虑重叠）
            start_line = end_line - self.overlap_size + 1
            
            # 避免无限循环
            if start_line >= end_line:
                start_line = end_line + 1
        
        return chunks

    def merge_results(self, chunk_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """合并分块分析结果
        
        Args:
            chunk_results: 分块分析结果列表
            
        Returns:
            合并后的分析结果
        """
        merged = {
            'findings': [],
            'evidence': [],
            'attack_paths': [],
            'confidence': 0.0,
            'chunk_count': len(chunk_results),
            'metadata': {
                'merged_at': '2026-04-07',  # 实际应用中应该使用当前时间
                'source_chunks': [result.get('chunk_id') for result in chunk_results]
            }
        }
        
        total_confidence = 0.0
        valid_chunks = 0
        
        for result in chunk_results:
            # 合并发现
            if 'findings' in result:
                merged['findings'].extend(result['findings'])
            
            # 合并证据
            if 'evidence' in result:
                merged['evidence'].extend(result['evidence'])
            
            # 合并攻击路径
            if 'attack_paths' in result:
                merged['attack_paths'].extend(result['attack_paths'])
            
            # 计算平均置信度
            if 'confidence' in result:
                total_confidence += result['confidence']
                valid_chunks += 1
        
        # 计算平均置信度
        if valid_chunks > 0:
            merged['confidence'] = total_confidence / valid_chunks
        
        return merged

    def should_chunk(self, file_path: str) -> bool:
        """判断是否需要分块
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否需要分块
        """
        try:
            file_size = Path(file_path).stat().st_size
            # 文件大小超过 100KB 或者行数超过 1000 行时需要分块
            if file_size > 100 * 1024:
                return True
            
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            return len(lines) > 1000
        except Exception:
            return False
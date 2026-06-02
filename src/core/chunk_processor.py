"""分块处理器

实现代码分块处理，提高分析效率和内存使用。
V23优化：智能分块、重叠上下文、去重合并、可配置化
"""

from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import hashlib
import re
from datetime import datetime


class ChunkProcessor:
    """分块处理器
    
    将大文件分成小块进行分析，提高分析效率和内存使用。
    V23优化：智能分块策略、重叠区域上下文传递、分块结果去重合并
    """

    # 代码边界模式（用于智能分块）
    CODE_BOUNDARY_PATTERNS = {
        'java': [
            r'^\s*(public|private|protected|class|interface|enum)\s+',
            r'^\s*@\w+',  # 注解
        ],
        'python': [
            r'^\s*(def|class)\s+\w+',
            r'^\s*@\w+',  # 装饰器
        ],
        'javascript': [
            r'^\s*(function|class|const|let|var)\s+\w+',
            r'^\s*export\s+(default|function|class|const|let|var)\s+',
        ],
        'typescript': [
            r'^\s*(function|class|const|let|var|interface|type|enum)\s+\w+',
            r'^\s*export\s+(default|function|class|const|let|var|interface|type|enum)\s+',
        ],
        'html': [
            r'<script[^>]*>',
            r'<style[^>]*>',
            r'<!--',  # 注释块
        ],
        'css': [
            r'^\s*[.#]?[\w-]+\s*\{',  # 选择器
        ],
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化分块处理器
        
        Args:
            config: 配置参数
                - max_chunk_size: 最大分块行数 (默认1500)
                - overlap_size: 重叠区域行数 (默认100)
                - min_chunk_size: 最小分块行数 (默认100)
                - file_size_threshold: 文件大小阈值KB (默认200)
                - line_count_threshold: 行数阈值 (默认2000)
                - enable_smart_chunk: 是否启用智能分块 (默认True)
        """
        self.config = config or {}
        self.max_chunk_size = self.config.get('max_chunk_size', 1500)
        self.overlap_size = self.config.get('overlap_size', 100)
        self.min_chunk_size = self.config.get('min_chunk_size', 100)
        self.file_size_threshold = self.config.get('file_size_threshold', 200) * 1024
        self.line_count_threshold = self.config.get('line_count_threshold', 2000)
        self.enable_smart_chunk = self.config.get('enable_smart_chunk', True)

    def chunk_file(self, file_path: str) -> List[Dict[str, Any]]:
        """将文件分成小块
        
        Args:
            file_path: 文件路径
            
        Returns:
            分块列表，每个分块包含内容和元数据
        """
        try:
            file_size = Path(file_path).stat().st_size
            if file_size > 5 * 1024 * 1024:  # 5MB以上使用流式读取
                return self._chunk_file_streaming(file_path)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
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

    def _chunk_file_streaming(self, file_path: str) -> List[Dict[str, Any]]:
        """流式读取大文件并分块
        
        Args:
            file_path: 文件路径
            
        Returns:
            分块列表
        """
        chunks = []
        chunk_lines = []
        start_line = 1
        current_line = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    current_line += 1
                    chunk_lines.append(line.rstrip('\n'))
                    
                    if len(chunk_lines) >= self.max_chunk_size:
                        chunk_content = '\n'.join(chunk_lines)
                        chunk_id = hashlib.md5(f"{file_path}:{start_line}-{current_line}".encode()).hexdigest()
                        
                        chunks.append({
                            'content': chunk_content,
                            'file_path': file_path,
                            'start_line': start_line,
                            'end_line': current_line,
                            'chunk_id': chunk_id,
                            'chunk_index': len(chunks),
                            'is_streaming': True
                        })
                        
                        # 保留重叠区域
                        chunk_lines = chunk_lines[-self.overlap_size:]
                        start_line = current_line - self.overlap_size + 1
            
            # 处理最后一块
            if chunk_lines:
                chunk_content = '\n'.join(chunk_lines)
                chunk_id = hashlib.md5(f"{file_path}:{start_line}-{current_line}".encode()).hexdigest()
                chunks.append({
                    'content': chunk_content,
                    'file_path': file_path,
                    'start_line': start_line,
                    'end_line': current_line,
                    'chunk_id': chunk_id,
                    'chunk_index': len(chunks),
                    'is_streaming': True
                })
                
        except Exception as e:
            return [{
                'content': '',
                'file_path': file_path,
                'start_line': 1,
                'end_line': 1,
                'chunk_id': hashlib.md5(f"{file_path}:1-1".encode()).hexdigest(),
                'error': str(e)
            }]
        
        return chunks

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
        
        # 判断是否需要分块
        if total_lines <= self.line_count_threshold:
            return [{
                'content': content,
                'file_path': file_path,
                'start_line': 1,
                'end_line': total_lines,
                'chunk_id': hashlib.md5(f"{file_path}:1-{total_lines}".encode()).hexdigest(),
                'total_lines': total_lines,
                'chunk_index': 0
            }]
        
        # 根据文件类型选择分块策略
        file_ext = Path(file_path).suffix.lower().lstrip('.')
        if self.enable_smart_chunk and file_ext in self.CODE_BOUNDARY_PATTERNS:
            return self._smart_chunk_content(lines, file_path, file_ext)
        else:
            return self._simple_chunk_content(lines, file_path)

    def _smart_chunk_content(self, lines: List[str], file_path: str, file_ext: str) -> List[Dict[str, Any]]:
        """智能分块：按代码边界分割
        
        Args:
            lines: 文件行列表
            file_path: 文件路径
            file_ext: 文件扩展名
            
        Returns:
            分块列表
        """
        patterns = self.CODE_BOUNDARY_PATTERNS.get(file_ext, [])
        boundary_lines = []
        
        # 找到所有代码边界行
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.match(pattern, line):
                    boundary_lines.append(i)
                    break
        
        # 如果没有找到边界，回退到简单分块
        if not boundary_lines:
            return self._simple_chunk_content(lines, file_path)
        
        chunks = []
        start_idx = 0
        chunk_index = 0
        
        for boundary_idx in boundary_lines:
            # 如果当前块已经达到最小大小，且遇到新的边界
            if boundary_idx - start_idx >= self.min_chunk_size:
                end_idx = min(boundary_idx, start_idx + self.max_chunk_size)
                
                # 创建分块
                chunk_lines = lines[start_idx:end_idx]
                chunk_content = '\n'.join(chunk_lines)
                chunk_id = hashlib.md5(f"{file_path}:{start_idx+1}-{end_idx}".encode()).hexdigest()
                
                chunks.append({
                    'content': chunk_content,
                    'file_path': file_path,
                    'start_line': start_idx + 1,
                    'end_line': end_idx,
                    'chunk_id': chunk_id,
                    'total_lines': len(lines),
                    'chunk_index': chunk_index,
                    'is_smart_chunk': True
                })
                chunk_index += 1
                
                # 计算下一个起始位置（考虑重叠）
                start_idx = max(end_idx - self.overlap_size, boundary_idx)
        
        # 处理最后一块
        if start_idx < len(lines):
            chunk_lines = lines[start_idx:]
            chunk_content = '\n'.join(chunk_lines)
            chunk_id = hashlib.md5(f"{file_path}:{start_idx+1}-{len(lines)}".encode()).hexdigest()
            
            chunks.append({
                'content': chunk_content,
                'file_path': file_path,
                'start_line': start_idx + 1,
                'end_line': len(lines),
                'chunk_id': chunk_id,
                'total_lines': len(lines),
                'chunk_index': chunk_index,
                'is_smart_chunk': True
            })
        
        return chunks

    def _simple_chunk_content(self, lines: List[str], file_path: str) -> List[Dict[str, Any]]:
        """简单分块：按行数分割
        
        Args:
            lines: 文件行列表
            file_path: 文件路径
            
        Returns:
            分块列表
        """
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
        """合并分块分析结果（含去重逻辑）
        
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
                'merged_at': datetime.now().isoformat(),
                'source_chunks': [result.get('chunk_id') for result in chunk_results],
                'deduplicated_count': 0
            }
        }
        
        total_confidence = 0.0
        valid_chunks = 0
        all_findings = []
        
        for result in chunk_results:
            # 合并发现
            if 'findings' in result:
                all_findings.extend(result['findings'])
            
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
        
        # 去重合并漏洞
        merged['findings'] = self._deduplicate_findings(all_findings)
        merged['metadata']['deduplicated_count'] = len(all_findings) - len(merged['findings'])
        
        # 计算平均置信度
        if valid_chunks > 0:
            merged['confidence'] = total_confidence / valid_chunks
        
        return merged

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """去重合并漏洞
        
        同一文件、同一行号范围（±3行）、同一类型的漏洞合并为一条
        
        Args:
            findings: 漏洞列表
            
        Returns:
            去重后的漏洞列表
        """
        if not findings:
            return []
        
        # 按文件+位置+类型分组
        groups: Dict[str, List[Dict[str, Any]]] = {}
        
        for finding in findings:
            # 提取关键信息
            file_path = finding.get('file_path', finding.get('location', {}).get('file', ''))
            location = finding.get('location', {})
            if isinstance(location, str):
                # 解析位置字符串
                parts = location.rsplit(':', 1)
                line = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 0
            else:
                line = location.get('line', 0)
            
            vuln_type = finding.get('rule_id', finding.get('type', ''))
            severity = finding.get('severity', 'info')
            confidence = finding.get('confidence', 0.0)
            
            # 生成去重键（行号按±3行分组）
            line_group = (line // 10) * 10  # 每10行一组
            dedup_key = f"{file_path}:{line_group}:{vuln_type}"
            
            if dedup_key not in groups:
                groups[dedup_key] = []
            groups[dedup_key].append(finding)
        
        # 合并每组漏洞
        merged_findings = []
        for dedup_key, group in groups.items():
            if len(group) == 1:
                merged_findings.append(group[0])
            else:
                # 合并多条漏洞
                merged = group[0].copy()
                # 保留最高风险等级和最高置信度
                severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                max_severity = max(group, key=lambda f: severity_order.get(f.get('severity', 'info'), 0))
                max_confidence = max(group, key=lambda f: f.get('confidence', 0.0))
                
                merged['severity'] = max_severity.get('severity', 'info')
                merged['confidence'] = max_confidence.get('confidence', 0.0)
                
                # 合并证据
                all_evidence = []
                for f in group:
                    if 'evidence' in f:
                        all_evidence.extend(f['evidence'])
                if all_evidence:
                    merged['evidence'] = all_evidence
                
                # 添加合并备注
                merged['merge_note'] = f"合并了 {len(group)} 条同类发现"
                merged['merged_count'] = len(group)
                
                merged_findings.append(merged)
        
        return merged_findings

    def should_chunk(self, file_path: str) -> bool:
        """判断是否需要分块
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否需要分块
        """
        try:
            file_size = Path(file_path).stat().st_size
            # 文件大小超过阈值或者行数超过阈值时需要分块
            if file_size > self.file_size_threshold:
                return True
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            return len(lines) > self.line_count_threshold
        except Exception:
            return False

    def get_chunk_for_rescan(self, chunk_results: List[Dict[str, Any]], target_chunk_id: str) -> Optional[Dict[str, Any]]:
        """获取指定分块用于重扫
        
        Args:
            chunk_results: 分块结果列表
            target_chunk_id: 目标分块ID
            
        Returns:
            目标分块信息，包含文件路径、起始行、结束行等
        """
        for result in chunk_results:
            if result.get('chunk_id') == target_chunk_id:
                return {
                    'file_path': result.get('file_path'),
                    'start_line': result.get('start_line'),
                    'end_line': result.get('end_line'),
                    'chunk_id': result.get('chunk_id'),
                    'chunk_index': result.get('chunk_index')
                }
        return None
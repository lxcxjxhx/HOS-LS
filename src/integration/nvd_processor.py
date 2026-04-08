"""NVD数据处理模块

实现NVD JSON数据的流式处理、拆分和清洗，为混合RAG架构准备数据。
"""

import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CVEChunk:
    """CVE数据块"""
    cve_id: str
    chunk_id: str  # 唯一标识，格式：CVE-XXXX#field#index
    chunk_type: str  # description, impact, solution, references, configurations
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CVEStructuredData:
    """CVE结构化数据"""
    cve_id: str
    description: str
    cwe: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_vector: Optional[str] = None
    attack_vector: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    cpe_list: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)


class NVDProcessor:
    """NVD数据处理器"""

    def __init__(self):
        """初始化NVD处理器"""
        # 字段长度限制
        self.max_description_length = 4000  # 限制描述长度，避免OOM
        self.max_reference_length = 1000
        self.max_chunk_content_length = 2000
        self.max_text_length = 4096  # 最大文本长度，避免OOM
        self.max_embedding_length = 512  # 最大embedding文本长度，避免OOM
        # Chunk参数
        self.CHUNK_SIZE = 400
        self.CHUNK_OVERLAP = 80
        pass

    def clean_text(self, text: str) -> str:
        """清洗文本，去除特殊字符和多余空格

        Args:
            text: 原始文本

        Returns:
            清洗后的文本
        """
        if not text:
            return ""
        text = text.replace('\x00', '')
        text = ' '.join(text.split())
        return text.strip()

    def truncate_field(self, text: str, max_length: int) -> str:
        """截断字段长度

        Args:
            text: 原始文本
            max_length: 最大长度

        Returns:
            截断后的文本
        """
        if text and len(text) > max_length:
            return text[:max_length] + "..."
        return text

    def limit_text_length(self, text: str) -> str:
        """限制文本长度，避免OOM

        Args:
            text: 原始文本

        Returns:
            限制长度后的文本
        """
        if text and len(text) > self.max_text_length:
            logger.warning(f"文本长度超过限制，截断到 {self.max_text_length} 字符")
            return text[:self.max_text_length] + "..."
        return text

    def split_long_description(self, description: str, cve_id: str) -> List[CVEChunk]:
        """对长描述进行分段处理，生成多个数据块

        Args:
            description: 长描述文本
            cve_id: CVE ID

        Returns:
            数据块列表
        """
        # 首先限制文本长度
        description = self.limit_text_length(description)
        chunks = []
        if not description:
            return chunks

        # 按句子分割描述
        sentences = description.split('. ')
        current_chunk = []
        current_length = 0
        chunk_index = 1

        for sentence in sentences:
            sentence += '. '
            sentence_length = len(sentence)

            if current_length + sentence_length > self.max_chunk_content_length:
                # 生成当前数据块
                if current_chunk:
                    chunk_content = ''.join(current_chunk)
                    chunk = CVEChunk(
                        cve_id=cve_id,
                        chunk_type='description',
                        content=f"CVE ID: {cve_id}\nDescription (part {chunk_index}): {chunk_content}",
                        metadata={
                            'type': 'description',
                            'cve_id': cve_id,
                            'part': chunk_index
                        }
                    )
                    chunks.append(chunk)
                    current_chunk = [sentence]
                    current_length = sentence_length
                    chunk_index += 1
            else:
                current_chunk.append(sentence)
                current_length += sentence_length

        # 处理最后一个数据块
        if current_chunk:
            chunk_content = ''.join(current_chunk)
            chunk = CVEChunk(
                cve_id=cve_id,
                chunk_type='description',
                content=f"CVE ID: {cve_id}\nDescription (part {chunk_index}): {chunk_content}",
                metadata={
                    'type': 'description',
                    'cve_id': cve_id,
                    'part': chunk_index
                }
            )
            chunks.append(chunk)

        logger.info(f"长描述分段完成，生成 {len(chunks)} 个数据块")
        return chunks

    def split_long_text(self, text: str, cve_id: str, chunk_type: str) -> List[CVEChunk]:
        """对长文本进行分段处理，生成多个数据块

        Args:
            text: 长文本
            cve_id: CVE ID
            chunk_type: 数据块类型

        Returns:
            数据块列表
        """
        # 首先限制文本长度
        text = self.limit_text_length(text)
        chunks = []
        if not text:
            return chunks

        # 按句子分割文本
        sentences = text.split('. ')
        current_chunk = []
        current_length = 0
        chunk_index = 1

        for sentence in sentences:
            sentence += '. '
            sentence_length = len(sentence)

            if current_length + sentence_length > self.max_chunk_content_length:
                # 生成当前数据块
                if current_chunk:
                    chunk_content = ''.join(current_chunk)
                    chunk = CVEChunk(
                        cve_id=cve_id,
                        chunk_type=chunk_type,
                        content=f"CVE ID: {cve_id}\n{chunk_type.capitalize()} (part {chunk_index}): {chunk_content}",
                        metadata={
                            'type': chunk_type,
                            'cve_id': cve_id,
                            'part': chunk_index
                        }
                    )
                    chunks.append(chunk)
                    current_chunk = [sentence]
                    current_length = sentence_length
                    chunk_index += 1
            else:
                current_chunk.append(sentence)
                current_length += sentence_length

        # 处理最后一个数据块
        if current_chunk:
            chunk_content = ''.join(current_chunk)
            chunk = CVEChunk(
                cve_id=cve_id,
                chunk_type=chunk_type,
                content=f"CVE ID: {cve_id}\n{chunk_type.capitalize()} (part {chunk_index}): {chunk_content}",
                metadata={
                    'type': chunk_type,
                    'cve_id': cve_id,
                    'part': chunk_index
                }
            )
            chunks.append(chunk)

        logger.info(f"长文本分段完成，生成 {len(chunks)} 个数据块")
        return chunks

    def split_text_for_embedding(self, text: str, chunk_size: int = None, chunk_overlap: int = None) -> List[str]:
        """将长文本切分为指定大小的片段，用于embedding

        Args:
            text: 长文本
            chunk_size: 块大小，默认400
            chunk_overlap: 块重叠，默认80

        Returns:
            切分后的文本片段列表
        """
        if not text:
            return []

        # 使用默认值
        if chunk_size is None:
            chunk_size = self.CHUNK_SIZE
        if chunk_overlap is None:
            chunk_overlap = self.CHUNK_OVERLAP

        # 首先清洗文本
        text = self.clean_text(text)
        
        # 如果文本长度小于等于chunk_size，直接返回
        if len(text) <= chunk_size:
            return [text]

        # 按语义切分（优先按句子）
        sentences = text.split('. ')
        chunks = []
        current_chunk = []
        current_length = 0

        for sentence in sentences:
            sentence += '. '
            sentence_length = len(sentence)

            if current_length + sentence_length > chunk_size:
                # 生成当前数据块
                if current_chunk:
                    chunk_content = ''.join(current_chunk).strip()
                    if chunk_content:
                        chunks.append(chunk_content)
                    # 计算重叠部分
                    overlap_text = ''.join(current_chunk[-2:]) if len(current_chunk) >= 2 else ''
                    current_chunk = [overlap_text + sentence]
                    current_length = len(overlap_text + sentence)
            else:
                current_chunk.append(sentence)
                current_length += sentence_length

        # 处理最后一个数据块
        if current_chunk:
            chunk_content = ''.join(current_chunk).strip()
            if chunk_content:
                chunks.append(chunk_content)

        # 如果按语义切分后仍然有超长片段，按字符切分
        final_chunks = []
        for chunk in chunks:
            if len(chunk) > chunk_size:
                # 按字符切分，保持重叠
                for i in range(0, len(chunk), chunk_size - chunk_overlap):
                    end = min(i + chunk_size, len(chunk))
                    final_chunks.append(chunk[i:end])
            else:
                final_chunks.append(chunk)

        logger.info(f"文本切分完成，生成 {len(final_chunks)} 个embedding片段")
        return final_chunks

    def detect_format(self, data: Dict[str, Any]) -> str:
        """检测NVD数据格式

        Args:
            data: NVD数据

        Returns:
            格式类型: v1.1, v2.0, unknown
        """
        # 检测 v1.1 格式
        if 'cve' in data:
            cve_data = data.get('cve', {})
            if 'CVE_data_meta' in cve_data:
                return 'v1.1'
        
        # 检测 v2.0 格式
        if 'id' in data and 'descriptions' in data:
            return 'v2.0'
        
        # 检测 CVE_Items 格式（包含多个CVE的集合）
        if 'CVE_Items' in data:
            return 'v1.1_collection'
        
        # 检测其他可能的NVD格式
        if 'CVE_data_type' in data or 'CVE_data_format' in data:
            return 'v1.1'
        
        # 检测单个CVE的其他格式
        if any(key in data for key in ['cveMetadata', 'containers', 'references']):
            return 'v2.0'
        
        return 'unknown'

    def parse_nvd_v2(self, data: Dict[str, Any]) -> Optional[Tuple[CVEStructuredData, List[CVEChunk]]]:
        """解析NVD v2.0数据

        Args:
            data: NVD v2.0格式数据

        Returns:
            (结构化数据, 数据块列表) 或 None
        """
        try:
            cve_id = data.get('id', '')
            if not cve_id:
                return None
            
            # 解析描述
            description = ''
            for desc in data.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    description = self.truncate_field(description, self.max_description_length)
                    description = self.limit_text_length(description)
                    break
            
            # 解析CVSS
            cvss_v3_score = None
            cvss_v3_vector = None
            cvss_v2_score = None
            cvss_v2_vector = None
            attack_vector = None
            
            metrics = data.get('metrics', {})
            
            cvss_v3_metrics = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
            if cvss_v3_metrics:
                cvss_data = cvss_v3_metrics[0].get('cvssData', {})
                cvss_v3_score = cvss_data.get('baseScore')
                cvss_v3_vector = cvss_data.get('vectorString')
                attack_vector = cvss_data.get('attackVector')
            
            cvss_v2_metrics = metrics.get('cvssMetricV2', [])
            if cvss_v2_metrics:
                cvss_data = cvss_v2_metrics[0].get('cvssData', {})
                cvss_v2_score = cvss_data.get('baseScore')
                cvss_v2_vector = cvss_data.get('vectorString')
                if not attack_vector:
                    attack_vector = cvss_data.get('accessVector')
            
            # 解析CWE
            cwe = None
            weaknesses = data.get('weaknesses', [])
            for weakness in weaknesses:
                if weakness.get('type') == 'Primary':
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            cwe_val = desc.get('value', '')
                            if cwe_val.startswith('CWE-'):
                                cwe = cwe_val
                            break
                    break
            
            # 解析CPE
            cpe_list = []
            configurations = data.get('configurations', [])
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for cpe_match in cpe_matches:
                        criteria = cpe_match.get('criteria', '')
                        if criteria:
                            cpe_list.append(criteria)
            
            # 解析引用
            references = []
            for ref in data.get('references', []):
                references.append({
                    'url': self.truncate_field(ref.get('url', ''), self.max_reference_length),
                    'name': self.truncate_field(ref.get('source', ''), self.max_reference_length),
                })
            
            # 解析日期
            published_date = None
            last_modified_date = None
            try:
                published_str = data.get('published')
                if published_str:
                    published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
            except Exception as e:
                logger.warning(f"解析发布日期失败: {e}")
            
            try:
                modified_str = data.get('lastModified')
                if modified_str:
                    last_modified_date = datetime.fromisoformat(modified_str.replace('Z', '+00:00'))
            except Exception as e:
                logger.warning(f"解析修改日期失败: {e}")
            
            # 生成标签
            tags = []
            if cwe:
                tags.append(cwe)
            if attack_vector:
                tags.append(attack_vector.lower())
            
            vuln_status = data.get('vulnStatus', '')
            if vuln_status:
                tags.append(f'status:{vuln_status.lower()}')
            
            # 构建结构化数据
            structured_data = CVEStructuredData(
                cve_id=cve_id,
                description=description,
                cwe=cwe,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_vector=cvss_v3_vector,
                cvss_v2_score=cvss_v2_score,
                cvss_v2_vector=cvss_v2_vector,
                attack_vector=attack_vector,
                tags=tags,
                published_date=published_date,
                last_modified_date=last_modified_date,
                cpe_list=cpe_list,
                references=references
            )
            
            # 生成数据块
            chunks = []
            
            # 字段级语义切块
            fields_to_chunk = {
                'description': description,
                'references': '\n'.join([f"{ref.get('url', '')} ({ref.get('name', '')})" for ref in references[:10]]),
                'configurations': '\n'.join(cpe_list[:10])
            }
            
            for field_name, field_content in fields_to_chunk.items():
                if field_content:
                    # 清洗文本
                    field_content = self.clean_text(field_content)
                    # 字段级切块
                    field_chunks = self.split_text_for_embedding(field_content)
                    for i, chunk_content in enumerate(field_chunks, 1):
                        chunk_id = f"{cve_id}#{field_name}#{i}"
                        chunk = CVEChunk(
                            cve_id=cve_id,
                            chunk_id=chunk_id,
                            chunk_type=field_name,
                            content=chunk_content,
                            metadata={
                                'type': field_name,
                                'cve_id': cve_id,
                                'part': i,
                                'total_parts': len(field_chunks)
                            }
                        )
                        chunks.append(chunk)
            
            return structured_data, chunks
        except Exception as e:
            logger.error(f"解析NVD v2.0数据失败: {e}")
            return None

    def parse_nvd_v1(self, data: Dict[str, Any]) -> Optional[Tuple[CVEStructuredData, List[CVEChunk]]]:
        """解析NVD v1.1数据

        Args:
            data: NVD v1.1格式数据

        Returns:
            (结构化数据, 数据块列表) 或 None
        """
        try:
            cve_data = data.get('cve', {})
            cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
            
            if not cve_id:
                return None
            
            # 解析描述
            description = ''
            desc_data = cve_data.get('description', {}).get('description_data', [])
            if desc_data:
                description = desc_data[0].get('value', '')
                description = self.truncate_field(description, self.max_description_length)
                description = self.limit_text_length(description)
            
            # 解析CVSS
            cvss_v3_score = None
            cvss_v3_vector = None
            cvss_v2_score = None
            cvss_v2_vector = None
            
            impact = data.get('impact', {})
            base_metric_v3 = impact.get('baseMetricV3', {})
            if base_metric_v3:
                cvss_v3 = base_metric_v3.get('cvssV3', {})
                cvss_v3_score = cvss_v3.get('baseScore')
                cvss_v3_vector = cvss_v3.get('vectorString')
            
            base_metric_v2 = impact.get('baseMetricV2', {})
            if base_metric_v2:
                cvss_v2 = base_metric_v2.get('cvssV2', {})
                cvss_v2_score = cvss_v2.get('baseScore')
                cvss_v2_vector = cvss_v2.get('vectorString')
            
            # 解析CWE
            cwe = None
            problem_type = cve_data.get('problemtype', {}).get('problemtype_data', [])
            if problem_type:
                descriptions = problem_type[0].get('description', [])
                if descriptions:
                    cwe = descriptions[0].get('value')
            
            # 解析CPE
            cpe_list = []
            configurations = data.get('configurations', {})
            nodes = configurations.get('nodes', [])
            for node in nodes:
                cpe_match = node.get('cpe_match', [])
                for cpe in cpe_match:
                    cpe_uri = cpe.get('cpe23Uri', '')
                    if cpe_uri:
                        cpe_list.append(cpe_uri)
            
            # 解析引用
            references = []
            ref_data = cve_data.get('references', {}).get('reference_data', [])
            for ref in ref_data:
                references.append({
                    'url': self.truncate_field(ref.get('url', ''), self.max_reference_length),
                    'name': self.truncate_field(ref.get('name', ''), self.max_reference_length),
                })
            
            # 解析攻击向量
            attack_vector = None
            if cvss_v3_vector:
                if 'AV:N' in cvss_v3_vector:
                    attack_vector = 'NETWORK'
                elif 'AV:A' in cvss_v3_vector:
                    attack_vector = 'ADJACENT_NETWORK'
                elif 'AV:L' in cvss_v3_vector:
                    attack_vector = 'LOCAL'
                elif 'AV:P' in cvss_v3_vector:
                    attack_vector = 'PHYSICAL'
            
            # 生成标签
            tags = []
            if cwe:
                tags.append(cwe)
            if attack_vector:
                tags.append(attack_vector.lower())
            
            # 解析日期
            published_date = None
            last_modified_date = None
            try:
                published_str = data.get('publishedDate')
                if published_str:
                    published_date = datetime.strptime(published_str, "%Y-%m-%dT%H:%MZ")
            except Exception as e:
                logger.warning(f"解析发布日期失败: {e}")
            
            try:
                modified_str = data.get('lastModifiedDate')
                if modified_str:
                    last_modified_date = datetime.strptime(modified_str, "%Y-%m-%dT%H:%MZ")
            except Exception as e:
                logger.warning(f"解析修改日期失败: {e}")
            
            # 构建结构化数据
            structured_data = CVEStructuredData(
                cve_id=cve_id,
                description=description,
                cwe=cwe,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_vector=cvss_v3_vector,
                cvss_v2_score=cvss_v2_score,
                cvss_v2_vector=cvss_v2_vector,
                attack_vector=attack_vector,
                tags=tags,
                published_date=published_date,
                last_modified_date=last_modified_date,
                cpe_list=cpe_list,
                references=references
            )
            
            # 生成数据块
            chunks = []
            
            # 字段级语义切块
            fields_to_chunk = {
                'description': description,
                'references': '\n'.join([f"{ref.get('url', '')} ({ref.get('name', '')})" for ref in references[:10]]),
                'configurations': '\n'.join(cpe_list[:10])
            }
            
            for field_name, field_content in fields_to_chunk.items():
                if field_content:
                    # 清洗文本
                    field_content = self.clean_text(field_content)
                    # 字段级切块
                    field_chunks = self.split_text_for_embedding(field_content)
                    for i, chunk_content in enumerate(field_chunks, 1):
                        chunk_id = f"{cve_id}#{field_name}#{i}"
                        chunk = CVEChunk(
                            cve_id=cve_id,
                            chunk_id=chunk_id,
                            chunk_type=field_name,
                            content=chunk_content,
                            metadata={
                                'type': field_name,
                                'cve_id': cve_id,
                                'part': i,
                                'total_parts': len(field_chunks)
                            }
                        )
                        chunks.append(chunk)
            
            return structured_data, chunks
        except Exception as e:
            logger.error(f"解析NVD v1.1数据失败: {e}")
            return None

    def parse_nvd(self, data: Dict[str, Any], file_path: Optional[str] = None) -> Optional[Tuple[CVEStructuredData, List[CVEChunk]]]:
        """解析NVD数据

        Args:
            data: NVD数据
            file_path: 文件路径，用于日志记录

        Returns:
            (结构化数据, 数据块列表) 或 None
        """
        format_type = self.detect_format(data)
        file_info = f" (文件: {file_path})" if file_path else ""
        
        if format_type == 'v2.0':
            logger.debug(f"检测到v2.0格式{file_info}")
            return self.parse_nvd_v2(data)
        elif format_type == 'v1.1':
            logger.debug(f"检测到v1.1格式{file_info}")
            return self.parse_nvd_v1(data)
        elif format_type == 'v1.1_collection':
            # 对于CVE_Items集合，我们不在这里处理，而是在process_zip_file和process_directory中处理
            logger.debug(f"检测到CVE_Items集合格式{file_info}，将在外部处理")
            return None
        else:
            # 尝试所有可能的格式解析
            logger.warning(f"未知的NVD数据格式{file_info}，尝试所有可能的解析方法")
            
            # 记录数据的前几个键，便于分析格式
            if data:
                first_keys = list(data.keys())[:5]  # 只取前5个键
                logger.warning(f"数据前几个键: {first_keys}{file_info}")
            
            # 尝试v2.0解析
            result = self.parse_nvd_v2(data)
            if result:
                logger.info(f"使用v2.0解析成功{file_info}")
                return result
            
            # 尝试v1.1解析
            result = self.parse_nvd_v1(data)
            if result:
                logger.info(f"使用v1.1解析成功{file_info}")
                return result
            
            logger.error(f"所有解析方法都失败{file_info}")
            return None

    def process_zip_file(self, zip_path: Path) -> List[Tuple[CVEStructuredData, List[CVEChunk]]]:
        """处理NVD ZIP文件

        Args:
            zip_path: ZIP文件路径

        Returns:
            处理结果列表
        """
        results = []
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # 过滤出JSON文件
                json_files = [member for member in zf.infolist() 
                            if member.filename.endswith('.json') and not member.is_dir()]
                
                logger.info(f"发现 {len(json_files)} 个JSON文件")
                
                for member in json_files:
                    try:
                        with zf.open(member) as f:
                            data = json.load(f)
                            
                            # 检查是否是CVE集合
                            if 'CVE_Items' in data:
                                cve_items = data.get('CVE_Items', [])
                                logger.info(f"处理文件 {member.filename}，包含 {len(cve_items)} 个CVE")
                                
                                for item in cve_items:
                                    result = self.parse_nvd(item, str(member.filename))
                                    if result:
                                        results.append(result)
                            else:
                                # 单个CVE文件
                                result = self.parse_nvd(data, str(member.filename))
                                if result:
                                    results.append(result)
                    except Exception as e:
                        logger.error(f"处理文件 {member.filename} 失败: {e}")
                        continue
        except Exception as e:
            logger.error(f"处理ZIP文件失败: {e}")
        
        logger.info(f"处理完成，成功解析 {len(results)} 个CVE")
        return results

    def process_directory(self, directory: Path) -> List[Tuple[CVEStructuredData, List[CVEChunk]]]:
        """处理NVD目录

        Args:
            directory: 目录路径

        Returns:
            处理结果列表
        """
        results = []
        
        try:
            json_files = list(directory.rglob('*.json'))
            logger.info(f"发现 {len(json_files)} 个JSON文件")
            
            for json_file in json_files:
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        # 检查是否是CVE集合
                        if 'CVE_Items' in data:
                            cve_items = data.get('CVE_Items', [])
                            logger.info(f"处理文件 {json_file.name}，包含 {len(cve_items)} 个CVE")
                            
                            for item in cve_items:
                                result = self.parse_nvd(item, str(json_file))
                                if result:
                                    results.append(result)
                        else:
                            # 单个CVE文件
                            result = self.parse_nvd(data, str(json_file))
                            if result:
                                results.append(result)
                except Exception as e:
                    logger.error(f"处理文件 {json_file} 失败: {e}")
                    continue
        except Exception as e:
            logger.error(f"处理目录失败: {e}")
        
        logger.info(f"处理完成，成功解析 {len(results)} 个CVE")
        return results
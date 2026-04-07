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
    chunk_type: str  # description, attack_chain, reference
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
        pass

    def detect_format(self, data: Dict[str, Any]) -> str:
        """检测NVD数据格式

        Args:
            data: NVD数据

        Returns:
            格式类型: v1.1, v2.0, unknown
        """
        if 'cve' in data and 'CVE_data_meta' in data.get('cve', {}):
            return 'v1.1'
        elif 'id' in data and 'descriptions' in data:
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
                    'url': ref.get('url', ''),
                    'name': ref.get('source', ''),
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
            
            # 描述块
            description_chunk = CVEChunk(
                cve_id=cve_id,
                chunk_type='description',
                content=f"CVE ID: {cve_id}\nDescription: {description}",
                metadata={
                    'type': 'description',
                    'cve_id': cve_id
                }
            )
            chunks.append(description_chunk)
            
            # 攻击链块（基于描述和引用生成）
            attack_chain_content = f"CVE ID: {cve_id}\n"
            attack_chain_content += f"Description: {description}\n"
            if references:
                attack_chain_content += "References:\n"
                for ref in references[:3]:  # 只取前3个引用
                    attack_chain_content += f"- {ref.get('url', '')}\n"
            
            attack_chain_chunk = CVEChunk(
                cve_id=cve_id,
                chunk_type='attack_chain',
                content=attack_chain_content,
                metadata={
                    'type': 'attack_chain',
                    'cve_id': cve_id,
                    'attack_vector': attack_vector
                }
            )
            chunks.append(attack_chain_chunk)
            
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
                    'url': ref.get('url', ''),
                    'name': ref.get('name', ''),
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
            
            # 描述块
            description_chunk = CVEChunk(
                cve_id=cve_id,
                chunk_type='description',
                content=f"CVE ID: {cve_id}\nDescription: {description}",
                metadata={
                    'type': 'description',
                    'cve_id': cve_id
                }
            )
            chunks.append(description_chunk)
            
            # 攻击链块
            attack_chain_content = f"CVE ID: {cve_id}\n"
            attack_chain_content += f"Description: {description}\n"
            if references:
                attack_chain_content += "References:\n"
                for ref in references[:3]:
                    attack_chain_content += f"- {ref.get('url', '')}\n"
            
            attack_chain_chunk = CVEChunk(
                cve_id=cve_id,
                chunk_type='attack_chain',
                content=attack_chain_content,
                metadata={
                    'type': 'attack_chain',
                    'cve_id': cve_id,
                    'attack_vector': attack_vector
                }
            )
            chunks.append(attack_chain_chunk)
            
            return structured_data, chunks
        except Exception as e:
            logger.error(f"解析NVD v1.1数据失败: {e}")
            return None

    def parse_nvd(self, data: Dict[str, Any]) -> Optional[Tuple[CVEStructuredData, List[CVEChunk]]]:
        """解析NVD数据

        Args:
            data: NVD数据

        Returns:
            (结构化数据, 数据块列表) 或 None
        """
        format_type = self.detect_format(data)
        if format_type == 'v2.0':
            return self.parse_nvd_v2(data)
        elif format_type == 'v1.1':
            return self.parse_nvd_v1(data)
        else:
            logger.warning(f"未知的NVD数据格式")
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
                                    result = self.parse_nvd(item)
                                    if result:
                                        results.append(result)
                            else:
                                # 单个CVE文件
                                result = self.parse_nvd(data)
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
                                result = self.parse_nvd(item)
                                if result:
                                    results.append(result)
                        else:
                            # 单个CVE文件
                            result = self.parse_nvd(data)
                            if result:
                                results.append(result)
                except Exception as e:
                    logger.error(f"处理文件 {json_file} 失败: {e}")
                    continue
        except Exception as e:
            logger.error(f"处理目录失败: {e}")
        
        logger.info(f"处理完成，成功解析 {len(results)} 个CVE")
        return results
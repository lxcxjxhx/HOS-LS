"""NVD漏洞库更新模块

用于手动更新NVD漏洞库，解压nvd-json-data-feeds-main.zip并同步到本地RAG库
"""

import hashlib
import json
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Optional, List

from src.learning.self_learning import Knowledge, KnowledgeType
from src.utils.logger import get_logger

logger = get_logger(__name__)

FILTERED_PATHS = {
    '.github/workflows',
    'LICENSES',
    '_scripts',
    'README.md',
    '_state.csv'
}


@dataclass
class CVE:
    cve_id: str = ""
    description: str = ""
    cwe: str = None
    cvss_v3_score: float = None
    cvss_v3_vector: str = None
    cvss_v2_score: float = None
    cvss_v2_vector: str = None
    cpe: list = field(default_factory=list)
    exploit: bool = False
    exploit_refs: list = field(default_factory=list)
    patch_refs: list = field(default_factory=list)
    attack_vector: str = None
    tags: list = field(default_factory=list)
    published_date: datetime = None
    last_modified_date: datetime = None
    affected_products: list = field(default_factory=list)
    references: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cwe": self.cwe,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v3_vector": self.cvss_v3_vector,
            "cvss_v2_score": self.cvss_v2_score,
            "cvss_v2_vector": self.cvss_v2_vector,
            "cpe": self.cpe,
            "exploit": self.exploit,
            "exploit_refs": self.exploit_refs,
            "patch_refs": self.patch_refs,
            "attack_vector": self.attack_vector,
            "tags": self.tags,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified_date": self.last_modified_date.isoformat() if self.last_modified_date else None,
            "affected_products": self.affected_products,
            "references": self.references,
            "metadata": self.metadata,
        }


def detect_format(data):
    if 'cve' in data and 'CVE_data_meta' in data.get('cve', {}):
        return 'v1.1'
    elif 'id' in data and 'descriptions' in data:
        return 'v2.0'
    return 'unknown'


def parse_nvd_v2(data):
    try:
        cve_id = data.get('id', '')
        if not cve_id:
            return None
        
        description = ''
        for desc in data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
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
        
        references = []
        for ref in data.get('references', []):
            references.append({
                'url': ref.get('url', ''),
                'name': ref.get('source', ''),
            })
        
        published_date = None
        last_modified_date = None
        try:
            published_str = data.get('published')
            if published_str:
                published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
        except:
            pass
        
        try:
            modified_str = data.get('lastModified')
            if modified_str:
                last_modified_date = datetime.fromisoformat(modified_str.replace('Z', '+00:00'))
        except:
            pass
        
        tags = []
        if cwe:
            tags.append(cwe)
        if attack_vector:
            tags.append(attack_vector.lower())
        
        vuln_status = data.get('vulnStatus', '')
        if vuln_status:
            tags.append(f'status:{vuln_status.lower()}')
        
        return CVE(
            cve_id=cve_id,
            description=description,
            cwe=cwe,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_score=cvss_v2_score,
            cvss_v2_vector=cvss_v2_vector,
            cpe=cpe_list,
            exploit=False,
            exploit_refs=[],
            patch_refs=[],
            attack_vector=attack_vector,
            tags=tags,
            published_date=published_date,
            last_modified_date=last_modified_date,
            affected_products=[],
            references=references,
            metadata={'vuln_status': vuln_status}
        )
    except Exception as e:
        logger.error(f"解析NVD v2.0数据失败: {e}")
        return None


def parse_nvd_v1(data):
    try:
        cve_data = data.get('cve', {})
        cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
        
        if not cve_id:
            return None
        
        description = ''
        desc_data = cve_data.get('description', {}).get('description_data', [])
        if desc_data:
            description = desc_data[0].get('value', '')
        
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
        
        cwe = None
        problem_type = cve_data.get('problemtype', {}).get('problemtype_data', [])
        if problem_type:
            descriptions = problem_type[0].get('description', [])
            if descriptions:
                cwe = descriptions[0].get('value')
        
        cpe_list = []
        configurations = data.get('configurations', {})
        nodes = configurations.get('nodes', [])
        for node in nodes:
            cpe_match = node.get('cpe_match', [])
            for cpe in cpe_match:
                cpe_uri = cpe.get('cpe23Uri', '')
                if cpe_uri:
                    cpe_list.append(cpe_uri)
        
        references = []
        ref_data = cve_data.get('references', {}).get('reference_data', [])
        for ref in ref_data:
            references.append({
                'url': ref.get('url', ''),
                'name': ref.get('name', ''),
            })
        
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
        
        tags = []
        if cwe:
            tags.append(cwe)
        if attack_vector:
            tags.append(attack_vector.lower())
        
        return CVE(
            cve_id=cve_id,
            description=description,
            cwe=cwe,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_score=cvss_v2_score,
            cvss_v2_vector=cvss_v2_vector,
            cpe=cpe_list,
            exploit=False,
            exploit_refs=[],
            patch_refs=[],
            attack_vector=attack_vector,
            tags=tags,
            published_date=None,
            last_modified_date=None,
            affected_products=[],
            references=references,
        )
    except Exception as e:
        logger.error(f"解析NVD v1.1数据失败: {e}")
        return None


def parse_nvd(data):
    format_type = detect_format(data)
    if format_type == 'v2.0':
        return parse_nvd_v2(data)
    elif format_type == 'v1.1':
        return parse_nvd_v1(data)
    else:
        logger.warning(f"未知的NVD数据格式")
        return None


def should_skip_path(path):
    path_parts = Path(path).parts
    for filtered in FILTERED_PATHS:
        filtered_parts = Path(filtered).parts
        if len(path_parts) >= len(filtered_parts):
            match = True
            for i in range(len(filtered_parts)):
                if path_parts[i] != filtered_parts[i]:
                    match = False
                    break
            if match:
                return True
    return False


def cve_to_knowledge(cve):
    content_parts = [f"CVE ID: {cve.cve_id}"]
    if cve.description:
        content_parts.append(f"Description: {cve.description}")
    if cve.cvss_v3_score is not None:
        content_parts.append(f"CVSS v3 Score: {cve.cvss_v3_score}")
    if cve.cvss_v3_vector:
        content_parts.append(f"CVSS v3 Vector: {cve.cvss_v3_vector}")
    if cve.cwe:
        content_parts.append(f"CWE: {cve.cwe}")
    if cve.attack_vector:
        content_parts.append(f"Attack Vector: {cve.attack_vector}")
    if cve.cpe:
        content_parts.append(f"Affected CPEs: {', '.join(cve.cpe[:5])}")
        if len(cve.cpe) > 5:
            content_parts.append(f"... and {len(cve.cpe) - 5} more")
    
    content = '\n'.join(content_parts)
    
    knowledge_id = hashlib.sha256(f"nvd_{cve.cve_id}".encode()).hexdigest()[:16]
    
    tags = list(cve.tags)
    tags.append('nvd')
    if cve.cvss_v3_score is not None:
        if cve.cvss_v3_score >= 9.0:
            tags.append('severity:critical')
        elif cve.cvss_v3_score >= 7.0:
            tags.append('severity:high')
        elif cve.cvss_v3_score >= 4.0:
            tags.append('severity:medium')
        else:
            tags.append('severity:low')
    
    confidence = 0.95 if cve.cvss_v3_score is not None else 0.8
    
    return Knowledge(
        id=knowledge_id,
        knowledge_type=KnowledgeType.VULNERABILITY,
        content=content,
        source='NVD',
        confidence=confidence,
        tags=tags,
        metadata={
            'cve_id': cve.cve_id,
            'cvss_v3_score': cve.cvss_v3_score,
            'cvss_v3_vector': cve.cvss_v3_vector,
            'cwe': cve.cwe,
            'published_date': cve.published_date.isoformat() if cve.published_date else None,
            'last_modified_date': cve.last_modified_date.isoformat() if cve.last_modified_date else None,
        }
    )


def run_update(zip_path, rag_base=None, limit=None, batch_size=1000):
    temp_dir = None
    stats = {
        'total_files': 0,
        'parsed_success': 0,
        'parsed_failed': 0,
        'imported_to_rag': 0,
        'skipped': 0
    }
    
    try:
        logger.info("=" * 60)
        logger.info("NVD手动更新脚本启动")
        logger.info("=" * 60)
        
        logger.info(f"开始解压: {zip_path}")
        temp_dir = Path(tempfile.mkdtemp(prefix='nvd_update_'))
        logger.info(f"临时目录: {temp_dir}")
        
        cve_files = []
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                if should_skip_path(member.filename):
                    continue
                
                if member.is_dir():
                    continue
                
                if not member.filename.endswith('.json'):
                    continue
                
                zf.extract(member, temp_dir)
                extracted_path = temp_dir / member.filename
                cve_files.append(extracted_path)
        
        stats['total_files'] = len(cve_files)
        logger.info(f"解压完成，找到 {len(cve_files)} 个CVE JSON文件")
        
        if limit:
            cve_files = cve_files[:limit]
            logger.info(f"限制处理前 {limit} 个文件")
        
        logger.info(f"开始处理 {len(cve_files)} 个文件...")
        
        for i, file_path in enumerate(cve_files):
            if i > 0 and i % batch_size == 0:
                logger.info(f"已处理 {i}/{len(cve_files)} 文件...")
                logger.info(f"  解析成功: {stats['parsed_success']}")
                logger.info(f"  解析失败: {stats['parsed_failed']}")
                logger.info(f"  已导入RAG: {stats['imported_to_rag']}")
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                cve = parse_nvd(data)
                if cve:
                    stats['parsed_success'] += 1
                    if rag_base:
                        try:
                            knowledge = cve_to_knowledge(cve)
                            rag_base.add_knowledge(knowledge)
                            stats['imported_to_rag'] += 1
                        except Exception as e:
                            logger.error(f"导入到RAG失败 {cve.cve_id}: {e}")
                            stats['skipped'] += 1
                    else:
                        stats['skipped'] += 1
                else:
                    stats['parsed_failed'] += 1
            except Exception as e:
                logger.error(f"解析文件失败 {file_path}: {e}")
                stats['parsed_failed'] += 1
        
        logger.info("=" * 60)
        logger.info("更新完成！")
        logger.info("=" * 60)
        logger.info(f"总文件数: {stats['total_files']}")
        logger.info(f"解析成功: {stats['parsed_success']}")
        logger.info(f"解析失败: {stats['parsed_failed']}")
        logger.info(f"导入RAG: {stats['imported_to_rag']}")
        logger.info(f"跳过: {stats['skipped']}")
        
        return stats.copy()
        
    finally:
        if temp_dir and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"已清理临时目录: {temp_dir}")
            except Exception as e:
                logger.warning(f"清理临时目录失败: {e}")

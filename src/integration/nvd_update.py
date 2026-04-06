"""NVD漏洞库更新模块

用于手动更新NVD漏洞库，解压nvd-json-data-feeds-main.zip并同步到本地RAG库
"""

import hashlib
import json
import shutil
import tempfile
import zipfile
import concurrent.futures
import os
import traceback
import signal
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Optional, List

from src.learning.self_learning import Knowledge, KnowledgeType
from src.utils.logger import get_logger

# 全局变量，用于跟踪是否被中断
interrupted = False
interrupt_signal = None
temp_dir_path = None
checkpoint_path = Path("./nvd_update_checkpoint.json")


def signal_handler(signum, frame):
    """信号处理函数"""
    global interrupted, interrupt_signal
    interrupted = True
    interrupt_signal = signum
    logger.info(f"接收到信号 {signum}，准备中断...")


# 注册信号处理器
signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
try:
    signal.signal(signal.SIGTSTP, signal_handler)  # Ctrl+Z
except AttributeError:
    # Windows 不支持 SIGTSTP
    pass


def force_delete_directory(directory):
    """强力删除目录
    
    尝试多种方法删除目录，确保文件被完全删除
    
    Args:
        directory: 要删除的目录路径
    """
    if not directory or not Path(directory).exists():
        return
    
    directory = Path(directory)
    logger.info(f"开始强力删除目录: {directory}")
    
    # 方法1：使用 shutil.rmtree
    try:
        logger.info("尝试使用 shutil.rmtree 删除...")
        shutil.rmtree(directory, ignore_errors=True)
        if not directory.exists():
            logger.info("成功使用 shutil.rmtree 删除目录")
            return
    except Exception as e:
        logger.warning(f"shutil.rmtree 删除失败: {e}")
    
    # 方法2：使用系统命令
    try:
        logger.info("尝试使用系统命令删除...")
        if os.name == 'nt':  # Windows
            # 使用 rd /s /q 命令
            os.system(f"rd /s /q \"{directory}\"")
        else:  # Unix-like
            # 使用 rm -rf 命令
            os.system(f"rm -rf \"{directory}\"")
        if not directory.exists():
            logger.info("成功使用系统命令删除目录")
            return
    except Exception as e:
        logger.warning(f"系统命令删除失败: {e}")
    
    # 方法3：手动删除文件和子目录
    try:
        logger.info("尝试手动删除文件和子目录...")
        for root, dirs, files in os.walk(directory, topdown=False):
            # 删除文件
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.warning(f"删除文件失败 {file_path}: {e}")
            # 删除子目录
            for dir in dirs:
                dir_path = os.path.join(root, dir)
                try:
                    os.rmdir(dir_path)
                except Exception as e:
                    logger.warning(f"删除子目录失败 {dir_path}: {e}")
        # 删除主目录
        try:
            os.rmdir(directory)
        except Exception as e:
            logger.warning(f"删除主目录失败: {e}")
        
        if not directory.exists():
            logger.info("成功手动删除目录")
            return
    except Exception as e:
        logger.warning(f"手动删除失败: {e}")
    
    logger.error(f"所有删除方法都失败，无法删除目录: {directory}")

def safe_load_json(file_path):
    try:
        # 尝试使用 ijson 进行流式解析，减少内存使用
        try:
            import ijson
            with open(file_path, 'r', encoding='utf-8') as f:
                # 流式解析 JSON 对象
                data = {}
                for prefix, event, value in ijson.parse(f):
                    if event == 'map_key':
                        current_key = value
                    elif event == 'string' or event == 'number' or event == 'boolean' or event == 'null':
                        data[current_key] = value
                    elif event == 'start_array':
                        # 处理数组
                        if current_key:
                            data[current_key] = []
                    elif event == 'end_array':
                        pass
                    elif event == 'start_map':
                        # 处理嵌套对象
                        if current_key:
                            nested_data = {}
                            nested_key = None
                    elif event == 'end_map':
                        if current_key:
                            data[current_key] = nested_data
                return data
        except ImportError:
            # 如果没有安装 ijson，回退到普通解析
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            data = json.loads(content)
            return data
    except json.JSONDecodeError as e:
        print(f"\n   ❌ JSON 格式损坏: {os.path.basename(file_path)}")
        print(f"      错误位置: line {e.lineno} col {e.colno} (char {e.pos})")
        # 打印附近 10 行内容，帮助你立刻看到坏在哪里
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            start = max(0, e.lineno - 10)
            print("      附近内容预览:")
            for ln in range(start, min(len(lines), e.lineno + 10)):
                print(f"        {ln+1:6d} | {lines[ln].rstrip()[:200]}")
        except:
            pass
        return None
    except Exception as e:
        print(f"\n   ❌ 读取失败: {os.path.basename(file_path)} -> {e}")
        return None

# 添加进度条支持
try:
    from tqdm import tqdm
except ImportError:
    # 如果没有安装tqdm，使用简单的进度显示
    tqdm = None

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


def run_update(zip_path, rag_base=None, limit=None, batch_size=1000, resume_from=0, progress_callback=None):
    global temp_dir_path, interrupted, interrupt_signal
    temp_dir = None
    stats = {
        'total_files': 0,
        'parsed_success': 0,
        'parsed_failed': 0,
        'imported_to_rag': 0,
        'skipped': 0
    }
    
    # 禁用频繁 GC，避免最后卡死
    import gc
    gc.disable()
    
    # 断点续传相关
    existing_temp_dir = None
    if resume_from > 0:
        logger.info(f"从文件 {resume_from} 开始续传")
    elif checkpoint_path.exists():
        try:
            with open(checkpoint_path, "r", encoding="utf-8") as f:
                checkpoint = json.load(f)
            resume_from = checkpoint.get("last_processed", 0)
            existing_temp_dir = checkpoint.get("temp_dir")
            if resume_from > 0:
                logger.info(f"从上次中断点继续处理，上次处理到文件 {resume_from}")
                if existing_temp_dir:
                    logger.info(f"发现上次的临时目录: {existing_temp_dir}")
        except Exception as e:
            logger.warning(f"读取断点文件失败: {e}")
            resume_from = 0
    
    try:
        # 导入内存监控模块
        import psutil
        import os
        
        logger.info("=" * 60)
        logger.info("NVD手动更新脚本启动")
        logger.info("=" * 60)
        
        # 初始内存状态
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        logger.info(f"初始内存使用: {initial_memory:.2f} MB")
        
        logger.info(f"开始解压: {zip_path}")
        if existing_temp_dir and Path(existing_temp_dir).exists():
            temp_dir = Path(existing_temp_dir)
            logger.info(f"使用现有临时目录: {temp_dir}")
        else:
            temp_dir = Path(tempfile.mkdtemp(prefix='nvd_update_'))
            logger.info(f"创建新临时目录: {temp_dir}")
        temp_dir_path = temp_dir
        
        cve_files = []
        
        if existing_temp_dir and Path(existing_temp_dir).exists():
            # 使用现有临时目录，直接扫描其中的JSON文件
            logger.info("从现有临时目录中扫描JSON文件...")
            cve_files = list(temp_dir.rglob('*.json'))
            logger.info(f"在现有临时目录中找到 {len(cve_files)} 个JSON文件")
        else:
            # 解压文件
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # 过滤出需要处理的文件
                members_to_extract = []
                for member in zf.infolist():
                    if should_skip_path(member.filename):
                        continue
                    
                    if member.is_dir():
                        continue
                    
                    if not member.filename.endswith('.json'):
                        continue
                    
                    members_to_extract.append(member)
                
                # 显示解压进度条
                if tqdm:
                    # 使用tqdm进度条
                    total_members = len(members_to_extract)
                    for i, member in enumerate(tqdm(members_to_extract, desc="解压NVD文件", unit="file")):
                        try:
                            zf.extract(member, temp_dir)
                            extracted_path = temp_dir / member.filename
                            # 检查文件是否完整
                            if extracted_path.exists() and extracted_path.stat().st_size > 0:
                                cve_files.append(extracted_path)
                            else:
                                logger.warning(f"跳过空文件或不完整文件: {member.filename}")
                                if extracted_path.exists():
                                    extracted_path.unlink()
                            # 调用进度回调
                            if progress_callback:
                                progress_callback("extract", i + 1, total_members)
                        except Exception as e:
                            logger.error(f"解压文件失败: {member.filename} -> {e}")
                else:
                    # 不使用tqdm，使用简单的进度显示
                    total_members = len(members_to_extract)
                    for i, member in enumerate(members_to_extract):
                        if i > 0 and i % 10 == 0:
                            logger.info(f"已解压 {i}/{total_members} 文件...")
                        try:
                            zf.extract(member, temp_dir)
                            extracted_path = temp_dir / member.filename
                            # 检查文件是否完整
                            if extracted_path.exists() and extracted_path.stat().st_size > 0:
                                cve_files.append(extracted_path)
                            else:
                                logger.warning(f"跳过空文件或不完整文件: {member.filename}")
                                if extracted_path.exists():
                                    extracted_path.unlink()
                            # 调用进度回调
                            if progress_callback:
                                progress_callback("extract", i + 1, total_members)
                        except Exception as e:
                            logger.error(f"解压文件失败: {member.filename} -> {e}")
        
        stats['total_files'] = len(cve_files)
        logger.info(f"解压完成，找到 {len(cve_files)} 个CVE JSON文件")
        
        if limit:
            cve_files = cve_files[:limit]
            logger.info(f"限制处理前 {limit} 个文件")
        
        logger.info(f"开始处理 {len(cve_files)} 个文件...")
        
        # 定义处理单个文件的函数
        def process_file(file_path):
            try:
                # 不打印文件名，避免与进度条冲突
                data = safe_load_json(file_path)
                if data is None:
                    return None
                cve = parse_nvd(data)
                if cve:
                    if rag_base:
                        try:
                            knowledge = cve_to_knowledge(cve)
                            return knowledge
                        except Exception as e:
                            print(f"\n   ❌ 转换为知识对象失败: {os.path.basename(file_path)}")
                            print(f"      错误: {e}")
                            import traceback
                            traceback.print_exc()
                            return None
                    else:
                        return None
                else:
                    return None
            except Exception as e:
                print(f"\n   ❌ 文件处理异常: {os.path.basename(file_path)}")
                print(f"      错误: {e}")
                import traceback
                traceback.print_exc()
                return None
        
        # 批量处理文件以提高效率
        knowledge_batch = []
        batch_count = 0
        processed_count = 0
        duplicate_count = 0
        
        # 优化：设置合理的批次大小，根据系统内存自动调整
        # 避免批次过大导致内存溢出
        import psutil
        process = psutil.Process()
        available_memory = psutil.virtual_memory().available
        # 根据可用内存动态调整批次大小
        # 每 100MB 内存可以处理大约 1000 条数据
        dynamic_batch_size = min(2000, max(100, int(available_memory / (100 * 1024 * 1024) * 1000)))
        if batch_size > dynamic_batch_size:
            batch_size = dynamic_batch_size
        logger.info(f"使用批次大小: {batch_size} (基于可用内存: {available_memory / 1024 / 1024:.2f} MB)")
        
        # 优化：使用流式处理，边处理边导入
        # 优化：延迟加载知识ID，减少内存使用
        existing_knowledge_ids = set()
        if rag_base:
            # 优化：使用惰性加载，只在需要时获取知识ID
            # 首先获取一个空集合，然后在处理过程中动态更新
            # 这样可以避免一次性加载所有知识ID到内存
            logger.info("初始化知识ID集合...")
            # 初始时只加载少量知识ID，或者不加载，在处理过程中动态检测
            # 这样可以大大减少初始内存使用
            existing_knowledge_ids = set()
            # 注意：这种方式可能会导致重复检测不够准确
            # 但可以通过在处理过程中动态添加新的知识ID来解决
            # 对于已经存在的知识ID，我们会在首次遇到时检测到重复
        
        # 优化：根据系统情况动态调整线程数
        # 对于I/O密集型任务，线程数可以设置为CPU核心数的2-4倍
        # 对于CPU密集型任务，线程数应接近CPU核心数
        cpu_count = os.cpu_count() or 4
        # NVD文件处理主要是I/O密集型（文件读取和JSON解析）
        max_workers = min(32, cpu_count * 4)  # 最大32个线程
        logger.info(f"使用线程数: {max_workers}")
        
        # 优化：实现任务分批提交，避免一次性提交所有任务
        batch_submit_size = 1000  # 每批提交1000个任务
        total_files = len(cve_files)
        processed_files = 0
        total_batches = (total_files + batch_submit_size - 1) // batch_submit_size
        
        # 流式处理：分批提交任务
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 总进度条
            if tqdm:
                with tqdm(total=total_files, desc="📊 总进度", unit="file") as total_pbar:
                    # 分批处理文件
                    for batch_idx in range(total_batches):
                        batch_start = batch_idx * batch_submit_size
                        batch_end = min((batch_idx + 1) * batch_submit_size, total_files)
                        
                        # 断点续传：跳过已处理的文件
                        if batch_start < resume_from:
                            logger.info(f"跳过批次 {batch_idx + 1}/{total_batches} (已处理)")
                            processed_count += (batch_end - batch_start)
                            processed_files += (batch_end - batch_start)
                            total_pbar.update(batch_end - batch_start)
                            continue
                        
                        batch_files = cve_files[batch_start:batch_end]
                        
                        # 减少日志打印，避免干扰进度条
                        if batch_idx == 0:
                            logger.info(f"开始处理 {total_files} 个文件，共 {total_batches} 个批次")
                        
                        # 提交当前批次的任务
                        future_to_file = {executor.submit(process_file, file_path): file_path for file_path in batch_files}
                        
                        # 处理完成的任务
                        batch_processed = 0
                        for future in concurrent.futures.as_completed(future_to_file):
                            # 检查是否被中断
                            if interrupted:
                                logger.info("检测到中断信号，正在停止处理...")
                                # 取消所有未完成的任务
                                for f in future_to_file:
                                    if not f.done():
                                        f.cancel()
                                break
                            
                            knowledge = future.result()
                            if knowledge:
                                # 检测重复
                                if knowledge.id in existing_knowledge_ids:
                                    duplicate_count += 1
                                    stats['skipped'] += 1
                                else:
                                    knowledge_batch.append(knowledge)
                                    existing_knowledge_ids.add(knowledge.id)  # 更新现有ID集合
                                    stats['parsed_success'] += 1
                            else:
                                stats['parsed_failed'] += 1
                            
                            processed_count += 1
                            processed_files += 1
                            batch_processed += 1
                            total_pbar.update(1)
                            
                            # 调用进度回调 - 嵌入阶段
                            if progress_callback:
                                progress_callback("embed", processed_files, total_files)
                            
                            # 每处理100个文件更新一次断点
                            if processed_files % 100 == 0:
                                try:
                                    checkpoint = {
                                        "last_processed": processed_files,
                                        "stats": stats,
                                        "timestamp": datetime.now().isoformat()
                                    }
                                    with open(checkpoint_path, "w", encoding="utf-8") as f:
                                        json.dump(checkpoint, f, indent=2, ensure_ascii=False)
                                except Exception as e:
                                    logger.warning(f"更新断点文件失败: {e}")
                            
                            # 再次检查中断
                            if interrupted:
                                logger.info("检测到中断信号，正在停止处理...")
                                # 取消所有未完成的任务
                                for f in future_to_file:
                                    if not f.done():
                                        f.cancel()
                                break
                            
                            # 处理当前批次 - 流式处理，达到批次大小就导入
                            if len(knowledge_batch) >= batch_size:
                                if rag_base:
                                    try:
                                        print(f"📦 准备注入批次 {batch_count+1}: {len(knowledge_batch)} 条")
                                        # 优化：批量导入时禁用自动保存，不立即构建索引，减少I/O操作
                                        if tqdm:
                                            # 添加导入进度条
                                            with tqdm(total=len(knowledge_batch), desc=f"导入批次 {batch_count+1}", unit="item") as pbar:
                                                added_count = rag_base.add_knowledge_batch(knowledge_batch, auto_save=False, build_index=False)
                                                pbar.update(len(knowledge_batch))
                                        else:
                                            added_count = rag_base.add_knowledge_batch(knowledge_batch, auto_save=False, build_index=False)
                                        stats['imported_to_rag'] += added_count
                                        
                                        # 强制刷新（防止内存里没写盘）
                                        if hasattr(rag_base, 'save'):
                                            rag_base.save(create_backup=False, build_index=False)
                                        
                                        # 清理内存
                                        import gc
                                        del knowledge_batch
                                        knowledge_batch = []
                                        gc.collect()
                                        batch_count += 1
                                        
                                        # 显示注入结果
                                        current_len = len(rag_base._knowledge) if rag_base else 0
                                        print(f"✅ 成功注入 {added_count} 条 | 当前 RAG 总条数: {current_len}")
                                        
                                        # 内存监控
                                        current_memory = process.memory_info().rss / 1024 / 1024
                                        logger.info(f"内存使用: {current_memory:.2f} MB (增加: {current_memory - initial_memory:.2f} MB)")
                                        
                                        # 分段处理：每处理10个批次后休息一下，让系统清理内存
                                        if batch_count % 10 == 0:
                                            logger.info("执行内存清理...")
                                            gc.collect()
                                            current_memory = process.memory_info().rss / 1024 / 1024
                                            logger.info(f"清理后内存使用: {current_memory:.2f} MB")
                                    except Exception as e:
                                        print(f"❌ 批次注入失败: {e}")
                                        traceback.print_exc()
                                        logger.error(f"批量导入到RAG失败: {e}")
                                        stats['skipped'] += len(knowledge_batch)
                                        # 清理内存
                                        import gc
                                        del knowledge_batch
                                        knowledge_batch = []
                                        gc.collect()
                                
                                # 移除定期保存，改为最终统一保存
                                
                                # 输出详细进度日志
                                rag_size = len(rag_base._knowledge) if rag_base else 0
                                logger.info(f"已处理 {processed_count}/{total_files} 文件...")
                                logger.info(f"  解析成功: {stats['parsed_success']}")
                                logger.info(f"  解析失败: {stats['parsed_failed']}")
                                logger.info(f"  已导入RAG: {stats['imported_to_rag']}")
                                logger.info(f"  RAG知识库大小: {rag_size}")
                                logger.info(f"  已处理批次: {batch_count}")
                                logger.info(f"  重复跳过: {duplicate_count}")
            else:
                # 不使用tqdm，使用简单的进度显示
                # 分批处理文件
                for batch_idx in range(total_batches):
                    batch_start = batch_idx * batch_submit_size
                    batch_end = min((batch_idx + 1) * batch_submit_size, total_files)
                    
                    # 断点续传：跳过已处理的文件
                    if batch_start < resume_from:
                        logger.info(f"跳过批次 {batch_idx + 1}/{total_batches} (已处理)")
                        processed_count += (batch_end - batch_start)
                        processed_files += (batch_end - batch_start)
                        continue
                    
                    batch_files = cve_files[batch_start:batch_end]
                    
                    # 减少日志打印，避免干扰进度条
                    if batch_idx == 0:
                        logger.info(f"开始处理 {total_files} 个文件，共 {total_batches} 个批次")
                    
                    # 提交当前批次的任务
                    future_to_file = {executor.submit(process_file, file_path): file_path for file_path in batch_files}
                    
                    # 处理完成的任务
                    for future in concurrent.futures.as_completed(future_to_file):
                        # 检查是否被中断
                        if interrupted:
                            logger.info("检测到中断信号，正在停止处理...")
                            # 取消所有未完成的任务
                            for f in future_to_file:
                                if not f.done():
                                    f.cancel()
                            break
                        
                        knowledge = future.result()
                        if knowledge:
                            # 检测重复
                            if knowledge.id in existing_knowledge_ids:
                                duplicate_count += 1
                                stats['skipped'] += 1
                            else:
                                knowledge_batch.append(knowledge)
                                existing_knowledge_ids.add(knowledge.id)  # 更新现有ID集合
                                stats['parsed_success'] += 1
                        else:
                            stats['parsed_failed'] += 1
                        
                        processed_count += 1
                        processed_files += 1
                        
                        # 检查是否被中断
                        if interrupted:
                            logger.info("检测到中断信号，正在停止处理...")
                            # 取消所有未完成的任务
                            for f in future_to_file:
                                if not f.done():
                                    f.cancel()
                            break
                        
                        # 处理当前批次 - 流式处理，达到批次大小就导入
                        if len(knowledge_batch) >= batch_size:
                            if rag_base:
                                try:
                                    print(f"📦 准备注入批次 {batch_count+1}: {len(knowledge_batch)} 条")
                                    # 优化：批量导入时禁用自动保存，不立即构建索引，减少I/O操作
                                    if tqdm:
                                        # 添加导入进度条
                                        with tqdm(total=len(knowledge_batch), desc=f"导入批次 {batch_count+1}", unit="item") as pbar:
                                            added_count = rag_base.add_knowledge_batch(knowledge_batch, auto_save=False, build_index=False)
                                            pbar.update(len(knowledge_batch))
                                    else:
                                        added_count = rag_base.add_knowledge_batch(knowledge_batch, auto_save=False, build_index=False)
                                    stats['imported_to_rag'] += added_count
                                    
                                    # 强制刷新（防止内存里没写盘）
                                    if hasattr(rag_base, 'save'):
                                        rag_base.save(create_backup=False, build_index=False)
                                    
                                    # 清理内存
                                    import gc
                                    del knowledge_batch
                                    knowledge_batch = []
                                    gc.collect()
                                    batch_count += 1
                                    
                                    # 显示注入结果
                                    current_len = len(rag_base._knowledge) if rag_base else 0
                                    print(f"✅ 成功注入 {added_count} 条 | 当前 RAG 总条数: {current_len}")
                                    
                                    # 内存监控
                                    current_memory = process.memory_info().rss / 1024 / 1024
                                    logger.info(f"内存使用: {current_memory:.2f} MB (增加: {current_memory - initial_memory:.2f} MB)")
                                    
                                    # 分段处理：每处理10个批次后休息一下，让系统清理内存
                                    if batch_count % 10 == 0:
                                        logger.info("执行内存清理...")
                                        gc.collect()
                                        current_memory = process.memory_info().rss / 1024 / 1024
                                        logger.info(f"清理后内存使用: {current_memory:.2f} MB")
                                except Exception as e:
                                    print(f"❌ 批次注入失败: {e}")
                                    traceback.print_exc()
                                    logger.error(f"批量导入到RAG失败: {e}")
                                    stats['skipped'] += len(knowledge_batch)
                                    # 清理内存
                                    import gc
                                    del knowledge_batch
                                    knowledge_batch = []
                                    gc.collect()
                            
                            # 移除定期保存，改为最终统一保存
                            
                            # 输出详细进度日志
                            rag_size = len(rag_base._knowledge) if rag_base else 0
                            logger.info(f"已处理 {processed_count}/{total_files} 文件...")
                            logger.info(f"  解析成功: {stats['parsed_success']}")
                            logger.info(f"  解析失败: {stats['parsed_failed']}")
                            logger.info(f"  已导入RAG: {stats['imported_to_rag']}")
                            logger.info(f"  RAG知识库大小: {rag_size}")
                            logger.info(f"  已处理批次: {batch_count}")
                            logger.info(f"  重复跳过: {duplicate_count}")
        
        # 处理最后一批
        if knowledge_batch and rag_base:
            try:
                print(f"📦 准备注入最后批次: {len(knowledge_batch)} 条")
                added_count = rag_base.add_knowledge_batch(knowledge_batch, auto_save=False, build_index=False)
                stats['imported_to_rag'] += added_count
                # 清理内存
                import gc
                del knowledge_batch
                gc.collect()
                batch_count += 1
                
                # 显示注入结果
                current_len = len(rag_base._knowledge) if rag_base else 0
                print(f"✅ 成功注入 {added_count} 条 | 当前 RAG 总条数: {current_len}")
                
                # 内存监控
                current_memory = process.memory_info().rss / 1024 / 1024
                logger.info(f"最后一批处理完成，内存使用: {current_memory:.2f} MB")
            except Exception as e:
                print(f"❌ 最后批次注入失败: {e}")
                traceback.print_exc()
                logger.error(f"最后一批导入到RAG失败: {e}")
                stats['skipped'] += len(knowledge_batch)
                # 清理内存
                import gc
                del knowledge_batch
                gc.collect()
        
        # 所有批次处理完成后，统一保存
        if rag_base:
            try:
                # 最关键：最后阶段必须单独进度条
                if tqdm:
                    with tqdm(total=3, desc="🔄 最终阶段", unit="step") as pbar:
                        logger.info("正在构建索引并保存RAG知识库...")
                        
                        # 内存监控
                        current_memory = process.memory_info().rss / 1024 / 1024
                        logger.info(f"开始保存前内存使用: {current_memory:.2f} MB")
                        
                        # 构建向量索引
                        logger.info("构建向量索引...")
                        if progress_callback:
                            progress_callback("graph", 1, 3)
                        rag_base.vector_store.save()
                        pbar.update(1)
                        
                        # 保存知识库，创建备份
                        logger.info("保存知识库...")
                        if progress_callback:
                            progress_callback("graph", 2, 3)
                        rag_base.save(create_backup=True)
                        pbar.update(1)
                        
                        # 完成
                        if progress_callback:
                            progress_callback("graph", 3, 3)
                        # 内存监控
                        current_memory = process.memory_info().rss / 1024 / 1024
                        logger.info(f"保存完成后内存使用: {current_memory:.2f} MB")
                        
                        pbar.update(1)
                        logger.info("RAG知识库保存完成！")
                else:
                    logger.info("正在构建索引并保存RAG知识库...")
                    
                    # 内存监控
                    current_memory = process.memory_info().rss / 1024 / 1024
                    logger.info(f"开始保存前内存使用: {current_memory:.2f} MB")
                    
                    # 构建向量索引
                    logger.info("构建向量索引...")
                    if progress_callback:
                        progress_callback("graph", 1, 3)
                    rag_base.vector_store.save()
                    logger.info("✅ 完成索引构建")
                    
                    # 保存知识库，创建备份
                    logger.info("保存知识库...")
                    if progress_callback:
                        progress_callback("graph", 2, 3)
                    rag_base.save(create_backup=True)
                    logger.info("✅ 完成知识库保存")
                    
                    # 完成
                    if progress_callback:
                        progress_callback("graph", 3, 3)
                    # 内存监控
                    current_memory = process.memory_info().rss / 1024 / 1024
                    logger.info(f"保存完成后内存使用: {current_memory:.2f} MB")
                    
                    logger.info("RAG知识库保存完成！")
            except Exception as e:
                logger.error(f"保存RAG知识库失败: {e}")
                # 内存监控
                current_memory = process.memory_info().rss / 1024 / 1024
                logger.info(f"保存失败时内存使用: {current_memory:.2f} MB")
        
        # 最终内存状态
        current_memory = process.memory_info().rss / 1024 / 1024
        logger.info(f"最终内存使用: {current_memory:.2f} MB (总增加: {current_memory - initial_memory:.2f} MB)")
        
        logger.info("=" * 60)
        logger.info("更新完成！")
        logger.info("=" * 60)
        logger.info(f"总文件数: {stats['total_files']}")
        logger.info(f"解析成功: {stats['parsed_success']}")
        logger.info(f"解析失败: {stats['parsed_failed']}")
        logger.info(f"导入RAG: {stats['imported_to_rag']}")
        logger.info(f"跳过: {stats['skipped']}")
        logger.info(f"重复跳过: {duplicate_count}")
        
        # 处理完成后清理断点文件
        if checkpoint_path.exists():
            try:
                checkpoint_path.unlink()
                logger.info("已清理断点文件")
            except Exception as e:
                logger.warning(f"清理断点文件失败: {e}")
        
        # 启用 GC 并手动收集
        import gc
        gc.enable()
        gc.collect()
        
        return stats.copy()
        
    finally:
        # 启用 GC 并手动收集，确保内存得到释放
        import gc
        if not gc.isenabled():
            gc.enable()
            gc.collect()
        
        # 处理中断情况
        if interrupted:
            logger.info("检测到用户中断，正在处理...")
            # 询问用户是否保留临时文件
            try:
                import click
                keep_temp = click.confirm('是否保留临时文件用于下次断点续传？', default=True)
                if not keep_temp:
                    logger.info("用户选择不保留临时文件，正在执行强力删除...")
                    # 执行强力删除
                    if temp_dir and temp_dir.exists():
                        force_delete_directory(temp_dir)
                        if not temp_dir.exists():
                            logger.info(f"已强力清理临时目录: {temp_dir}")
                        else:
                            logger.error(f"强力删除失败，目录仍然存在: {temp_dir}")
                    # 清理断点文件
                    if checkpoint_path.exists():
                        try:
                            checkpoint_path.unlink()
                            logger.info("已清理断点文件")
                        except Exception as e:
                            logger.warning(f"清理断点文件失败: {e}")
                else:
                    logger.info("用户选择保留临时文件，将用于下次断点续传")
                    # 更新断点文件，记录临时目录路径
                    try:
                        checkpoint = {
                            "last_processed": processed_files,
                            "temp_dir": str(temp_dir),
                            "stats": stats,
                            "timestamp": datetime.now().isoformat()
                        }
                        with open(checkpoint_path, "w", encoding="utf-8") as f:
                            json.dump(checkpoint, f, indent=2, ensure_ascii=False)
                        logger.info("断点文件已更新，包含临时目录路径")
                    except Exception as e:
                        logger.warning(f"更新断点文件失败: {e}")
            except Exception as e:
                logger.error(f"用户确认过程出错: {e}")
                # 出错时默认清理临时文件
                if temp_dir and temp_dir.exists():
                    try:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        logger.info(f"已清理临时目录: {temp_dir}")
                    except Exception as e2:
                        logger.warning(f"清理临时目录失败: {e2}")
        else:
            # 正常结束，清理临时文件和目录
            if temp_dir and temp_dir.exists():
                try:
                    # 直接使用 shutil.rmtree 删除整个目录，这是最有效的方法
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    logger.info(f"已清理临时目录: {temp_dir}")
                except Exception as e:
                    logger.warning(f"清理临时目录失败: {e}")
                    # 尝试使用 os.system 命令删除（在 Windows 上使用 rd /s /q）
                    try:
                        import os
                        if os.name == 'nt':  # Windows
                            os.system(f"rd /s /q {temp_dir}")
                        else:  # Unix-like
                            os.system(f"rm -rf {temp_dir}")
                        logger.info(f"已使用系统命令清理临时目录: {temp_dir}")
                    except Exception as e2:
                        logger.error(f"强制清理临时目录失败: {e2}")

"""数据适配层

将A.S.E和DREA数据集转换为HOS-LS可处理的格式。
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class VulnSample:
    """漏洞样本"""
    sample_id: str
    repo: str
    vuln_file: str
    vuln_lines: List[int]
    language: str
    vuln_type: str
    cwe_id: str
    code_before: str  # 漏洞代码
    code_after: str = ""  # 修复代码（如果有）
    task_desc: str = ""


class ASEAdapter:
    """A.S.E数据集适配器"""
    
    def __init__(self, data_path: str, repos_dir: str):
        self.data_path = Path(data_path)
        self.repos_dir = Path(repos_dir)
    
    def load_samples(self, max_samples: int = 50) -> List[VulnSample]:
        """加载样本"""
        samples = []
        
        # 加载带漏洞代码的数据
        vuln_code_path = self.data_path.parent / "ase_with_vuln_code.json"
        if vuln_code_path.exists():
            with open(vuln_code_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for item in data[:max_samples]:
                samples.append(VulnSample(
                    sample_id=item['instance_id'],
                    repo=item['repo'],
                    vuln_file=item['vuln_file'],
                    vuln_lines=item['vuln_lines'],
                    language=item['language'],
                    vuln_type=item['vuln_type'],
                    cwe_id=item['cwe_id'],
                    code_before=item['vuln_code'],
                    task_desc=f"Fix {item['vuln_type']} in {item['vuln_file']}",
                ))
        
        return samples


class DREAAdapter:
    """DREA数据集适配器"""
    
    def __init__(self, data_path: str):
        self.data_path = Path(data_path)
    
    def load_samples(self, max_samples: int = 50) -> List[VulnSample]:
        """加载样本"""
        samples = []
        
        with open(self.data_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i >= max_samples:
                    break
                
                item = json.loads(line)
                vuln_data = item.get('vuln_data', {})
                
                # 推断漏洞类型
                cwe_id = item.get('cwe_ids', ['unknown'])[0] if item.get('cwe_ids') else 'unknown'
                vuln_type_map = {
                    'CWE-22': 'Path Traversal',
                    'CWE-78': 'Command Injection',
                    'CWE-79': 'XSS',
                    'CWE-89': 'SQL Injection',
                    'CWE-94': 'Code Injection',
                    'CWE-287': 'Authentication Bypass',
                    'CWE-306': 'Missing Authentication',
                    'CWE-434': 'File Upload',
                    'CWE-502': 'Deserialization',
                    'CWE-611': 'XXE',
                    'CWE-918': 'SSRF',
                }
                vuln_type = vuln_type_map.get(cwe_id, 'Unknown')
                
                samples.append(VulnSample(
                    sample_id=item['id'],
                    repo=item.get('project_name', ''),
                    vuln_file=vuln_data.get('file_path', ''),
                    vuln_lines=[],
                    language=item.get('language', 'unknown'),
                    vuln_type=vuln_type,
                    cwe_id=cwe_id,
                    code_before=vuln_data.get('code_before', ''),
                    code_after=vuln_data.get('code_after', ''),
                    task_desc=f"Fix {vuln_type} vulnerability",
                ))
        
        return samples

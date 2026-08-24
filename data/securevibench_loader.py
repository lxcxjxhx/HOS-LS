"""SecureVibeBench数据加载器

加载SecureVibeBench数据集，转换为统一格式。
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from data.schema import (
    SampleData, SampleMetadata, CodeChange,
    DatasetType, VulnerabilityType
)


class SecureVibeBenchLoader:
    """SecureVibeBench数据加载器
    
    SecureVibeBench数据集格式：
    - 105个C/C++任务
    - 来自41个OSS-Fuzz项目
    - 包含漏洞引入场景
    """
    
    def __init__(self, dataset_path: str):
        """
        Args:
            dataset_path: 数据集路径（目录或JSONL文件）
        """
        self.dataset_path = Path(dataset_path)
    
    def load(self) -> List[SampleData]:
        """加载数据集
        
        Returns:
            样本数据列表
        """
        samples = []
        
        # 检查是目录还是文件
        if self.dataset_path.is_dir():
            # 目录模式：加载所有JSONL文件
            for jsonl_file in self.dataset_path.glob("*.jsonl"):
                samples.extend(self._load_jsonl(jsonl_file))
        elif self.dataset_path.suffix == ".jsonl":
            # 单个JSONL文件
            samples.extend(self._load_jsonl(self.dataset_path))
        else:
            # 尝试作为JSON加载
            samples.extend(self._load_json(self.dataset_path))
        
        return samples
    
    def _load_jsonl(self, file_path: Path) -> List[SampleData]:
        """加载JSONL文件"""
        samples = []
        
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    sample = self._parse_sample(data)
                    if sample:
                        samples.append(sample)
                except json.JSONDecodeError as e:
                    print(f"Warning: Failed to parse line {line_num}: {e}")
                except Exception as e:
                    print(f"Warning: Failed to process line {line_num}: {e}")
        
        return samples
    
    def _load_json(self, file_path: Path) -> List[SampleData]:
        """加载JSON文件"""
        samples = []
        
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # 支持列表或字典格式
        if isinstance(data, list):
            for item in data:
                sample = self._parse_sample(item)
                if sample:
                    samples.append(sample)
        elif isinstance(data, dict):
            # 可能是包含samples字段的字典
            items = data.get("samples", data.get("data", [data]))
            for item in items:
                sample = self._parse_sample(item)
                if sample:
                    samples.append(sample)
        
        return samples
    
    def _parse_sample(self, data: Dict[str, Any]) -> Optional[SampleData]:
        """解析单个样本"""
        try:
            # 提取元数据
            sample_id = data.get("id", data.get("sample_id", ""))
            project_name = data.get("project_name", data.get("project", ""))
            
            # 提取漏洞信息
            vuln_data = data.get("vuln_data", data.get("vulnerability", {}))
            
            # 提取代码变更
            code_before = vuln_data.get("code_before", vuln_data.get("vulnerable_code", ""))
            code_after = vuln_data.get("code_after", vuln_data.get("patched_code", ""))
            file_path = vuln_data.get("file_path", vuln_data.get("file", ""))
            
            # 构建diff
            delta_ai = self._build_diff(file_path, code_before, code_after)
            
            # 提取CVE和CWE
            cve_ids = data.get("cve_ids", data.get("cve", []))
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            
            cwe_ids = data.get("cwe_ids", data.get("cwe", []))
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            
            # 确定漏洞类型
            vuln_type = self._determine_vulnerability_type(cwe_ids, data)
            
            # 构建元数据
            metadata = SampleMetadata(
                sample_id=sample_id,
                dataset=DatasetType.SECUREVIBEBENCH,
                project_name=project_name,
                repo_url=data.get("repo_url", ""),
                commit_hash=data.get("commit_hash", ""),
                language=data.get("language", "c"),
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                vulnerability_type=vuln_type,
                severity=data.get("severity", "HIGH"),
                description=data.get("description", ""),
                is_vulnerable=True,
            )
            
            # 构建代码变更
            code_change = CodeChange(
                file_path=file_path,
                function_name=self._extract_function_name(code_before),
                change_type="modified",
                code_before=code_before,
                code_after=code_after,
                diff=delta_ai,
            )
            
            # 构建样本数据
            return SampleData(
                metadata=metadata,
                r_before="",  # 需要从仓库重建
                task_desc=data.get("task_description", data.get("description", "")),
                delta_ai=delta_ai,
                code_changes=[code_change],
                modified_functions=[f"{file_path}:{code_change.function_name}"],
            )
        
        except Exception as e:
            print(f"Error parsing sample: {e}")
            return None
    
    def _build_diff(self, file_path: str, code_before: str, code_after: str) -> str:
        """构建Unified Diff"""
        if not code_before or not code_after:
            return ""
        
        lines_before = code_before.split("\n")
        lines_after = code_after.split("\n")
        
        diff_lines = [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
            f"@@ -1,{len(lines_before)} +1,{len(lines_after)} @@",
        ]
        
        # 简单的diff构建（实际应该使用difflib）
        for line in lines_before:
            diff_lines.append(f"-{line}")
        for line in lines_after:
            diff_lines.append(f"+{line}")
        
        return "\n".join(diff_lines)
    
    def _extract_function_name(self, code: str) -> str:
        """从代码中提取函数名"""
        # 简单的启发式提取
        for line in code.split("\n"):
            line = line.strip()
            # C/C++函数定义
            if "(" in line and ")" in line and "{" in line:
                # 提取函数名
                parts = line.split("(")[0].split()
                if parts:
                    return parts[-1]
            # Python函数定义
            if line.startswith("def "):
                return line.split("(")[0].replace("def ", "").strip()
        
        return "unknown"
    
    def _determine_vulnerability_type(
        self, cwe_ids: List[str], data: Dict[str, Any]
    ) -> VulnerabilityType:
        """确定漏洞类型"""
        # 基于CWE ID确定漏洞类型
        cwe_mapping = {
            "CWE-89": VulnerabilityType.SQL_INJECTION,
            "CWE-78": VulnerabilityType.COMMAND_INJECTION,
            "CWE-22": VulnerabilityType.PATH_TRAVERSAL,
            "CWE-79": VulnerabilityType.XSS,
            "CWE-918": VulnerabilityType.SSRF,
            "CWE-287": VulnerabilityType.AUTH_BYPASS,
            "CWE-502": VulnerabilityType.DESERIALIZATION,
            "CWE-94": VulnerabilityType.TEMPLATE_INJECTION,
            "CWE-362": VulnerabilityType.RACE_CONDITION,
        }
        
        for cwe in cwe_ids:
            if cwe in cwe_mapping:
                return cwe_mapping[cwe]
        
        # 基于描述确定
        description = data.get("description", "").lower()
        if "sql" in description or "injection" in description:
            return VulnerabilityType.SQL_INJECTION
        elif "command" in description or "exec" in description:
            return VulnerabilityType.COMMAND_INJECTION
        elif "path" in description or "traversal" in description:
            return VulnerabilityType.PATH_TRAVERSAL
        elif "xss" in description or "cross-site" in description:
            return VulnerabilityType.XSS
        
        return VulnerabilityType.OTHER
    
    def load_with_repos(self, repos_dir: str) -> List[SampleData]:
        """加载数据集并重建仓库
        
        Args:
            repos_dir: 仓库目录
            
        Returns:
            样本数据列表（包含仓库路径）
        """
        samples = self.load()
        
        repos_path = Path(repos_dir)
        for sample in samples:
            project_name = sample.metadata.project_name
            repo_path = repos_path / project_name
            
            if repo_path.exists():
                sample.r_before = str(repo_path)
        
        return samples

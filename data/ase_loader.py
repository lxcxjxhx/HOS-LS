"""A.S.E (AICGSecEval) 数据加载器

加载A.S.E数据集，转换为统一格式。
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from data.schema import (
    SampleData, SampleMetadata, CodeChange,
    DatasetType, VulnerabilityType
)


class ASELoader:
    """A.S.E数据加载器
    
    A.S.E数据集格式：
    - 仓库级AI生成代码安全评测基准
    - 由Tencent Wukong Code Security Team开发
    - 包含多种编程语言和漏洞类型
    """
    
    def __init__(self, dataset_path: str):
        """
        Args:
            dataset_path: 数据集路径（目录或JSON文件）
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
            # 目录模式：加载所有JSON文件
            for json_file in self.dataset_path.glob("**/*.json"):
                samples.extend(self._load_json(json_file))
        elif self.dataset_path.suffix == ".json":
            # 单个JSON文件
            samples.extend(self._load_json(self.dataset_path))
        elif self.dataset_path.suffix == ".jsonl":
            # JSONL文件
            samples.extend(self._load_jsonl(self.dataset_path))
        
        return samples
    
    def _load_json(self, file_path: Path) -> List[SampleData]:
        """加载JSON文件"""
        samples = []
        
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # 支持多种格式
        if isinstance(data, list):
            for item in data:
                sample = self._parse_sample(item)
                if sample:
                    samples.append(sample)
        elif isinstance(data, dict):
            # 检查是否有samples字段
            if "samples" in data:
                for item in data["samples"]:
                    sample = self._parse_sample(item)
                    if sample:
                        samples.append(sample)
            elif "data" in data:
                for item in data["data"]:
                    sample = self._parse_sample(item)
                    if sample:
                        samples.append(sample)
            else:
                # 单个样本
                sample = self._parse_sample(data)
                if sample:
                    samples.append(sample)
        
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
    
    def _parse_sample(self, data: Dict[str, Any]) -> Optional[SampleData]:
        """解析单个样本"""
        try:
            # 提取元数据
            sample_id = data.get("id", data.get("sample_id", ""))
            project_name = data.get("project_name", data.get("project", ""))
            
            # 提取漏洞信息
            vuln_info = data.get("vulnerability", data.get("vuln_info", {}))
            
            # 提取代码变更
            code_changes = self._extract_code_changes(data)
            
            # 构建diff
            delta_ai = self._build_delta_ai(code_changes)
            
            # 提取CVE和CWE
            cve_ids = data.get("cve_ids", vuln_info.get("cve", []))
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            
            cwe_ids = data.get("cwe_ids", vuln_info.get("cwe", []))
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            
            # 确定漏洞类型
            vuln_type = self._determine_vulnerability_type(cwe_ids, data)
            
            # 提取修改的函数
            modified_functions = self._extract_modified_functions(code_changes)
            
            # 构建元数据
            metadata = SampleMetadata(
                sample_id=sample_id,
                dataset=DatasetType.ASE,
                project_name=project_name,
                repo_url=data.get("repo_url", ""),
                commit_hash=data.get("commit_hash", ""),
                language=data.get("language", "python"),
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                vulnerability_type=vuln_type,
                severity=vuln_info.get("severity", "HIGH"),
                description=vuln_info.get("description", data.get("description", "")),
                is_vulnerable=data.get("is_vulnerable", True),
            )
            
            # 构建样本数据
            return SampleData(
                metadata=metadata,
                r_before="",  # 需要从仓库重建
                task_desc=data.get("task_description", data.get("task_desc", "")),
                delta_ai=delta_ai,
                code_changes=code_changes,
                modified_functions=modified_functions,
            )
        
        except Exception as e:
            print(f"Error parsing sample: {e}")
            return None
    
    def _extract_code_changes(self, data: Dict[str, Any]) -> List[CodeChange]:
        """提取代码变更"""
        changes = []
        
        # 尝试从不同字段提取
        code_changes = data.get("code_changes", data.get("changes", []))
        
        for change in code_changes:
            if isinstance(change, dict):
                changes.append(CodeChange(
                    file_path=change.get("file_path", change.get("file", "")),
                    function_name=change.get("function_name", change.get("function", "")),
                    line_number=change.get("line_number", change.get("line", 0)),
                    change_type=change.get("change_type", change.get("type", "modified")),
                    code_before=change.get("code_before", change.get("before", "")),
                    code_after=change.get("code_after", change.get("after", "")),
                    diff=change.get("diff", ""),
                ))
        
        # 如果没有code_changes，尝试从vulnerability字段提取
        if not changes:
            vuln_info = data.get("vulnerability", {})
            code_before = vuln_info.get("code_before", vuln_info.get("vulnerable_code", ""))
            code_after = vuln_info.get("code_after", vuln_info.get("patched_code", ""))
            file_path = vuln_info.get("file_path", vuln_info.get("file", ""))
            
            if code_before or code_after:
                changes.append(CodeChange(
                    file_path=file_path,
                    function_name=self._extract_function_name(code_before),
                    change_type="modified",
                    code_before=code_before,
                    code_after=code_after,
                ))
        
        return changes
    
    def _build_delta_ai(self, code_changes: List[CodeChange]) -> str:
        """构建Unified Diff"""
        if not code_changes:
            return ""
        
        diff_parts = []
        for change in code_changes:
            if change.diff:
                diff_parts.append(change.diff)
            elif change.code_before and change.code_after:
                # 构建简单的diff
                lines_before = change.code_before.split("\n")
                lines_after = change.code_after.split("\n")
                
                diff_lines = [
                    f"--- a/{change.file_path}",
                    f"+++ b/{change.file_path}",
                    f"@@ -1,{len(lines_before)} +1,{len(lines_after)} @@",
                ]
                
                for line in lines_before:
                    diff_lines.append(f"-{line}")
                for line in lines_after:
                    diff_lines.append(f"+{line}")
                
                diff_parts.append("\n".join(diff_lines))
        
        return "\n".join(diff_parts)
    
    def _extract_function_name(self, code: str) -> str:
        """从代码中提取函数名"""
        for line in code.split("\n"):
            line = line.strip()
            # Python函数定义
            if line.startswith("def "):
                return line.split("(")[0].replace("def ", "").strip()
            # JavaScript/TypeScript函数定义
            if "function " in line and "(" in line:
                return line.split("(")[0].split("function ")[-1].strip()
            # 类方法定义
            if "(" in line and ")" in line and ":" in line:
                parts = line.split("(")[0].split()
                if parts:
                    return parts[-1]
        
        return "unknown"
    
    def _extract_modified_functions(self, code_changes: List[CodeChange]) -> List[str]:
        """提取修改的函数列表"""
        modified = []
        for change in code_changes:
            if change.function_name:
                modified.append(f"{change.file_path}:{change.function_name}")
        return modified
    
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
        vuln_info = data.get("vulnerability", {})
        vuln_type_str = vuln_info.get("type", "").lower()
        
        if "sql" in description or "sql" in vuln_type_str:
            return VulnerabilityType.SQL_INJECTION
        elif "command" in description or "exec" in description:
            return VulnerabilityType.COMMAND_INJECTION
        elif "path" in description or "traversal" in description:
            return VulnerabilityType.PATH_TRAVERSAL
        elif "xss" in description or "cross-site" in description:
            return VulnerabilityType.XSS
        elif "ssrf" in description:
            return VulnerabilityType.SSRF
        
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

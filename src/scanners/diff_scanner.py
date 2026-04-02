#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
差异化扫描模块

功能：
1. 基于 Git 比较两个版本的代码差异
2. 只扫描发生变化的文件和代码行
3. 支持不同的比较模式（分支、提交、标签）
4. 集成到现有的扫描流程中
5. 提高扫描效率，减少重复扫描
6. 自动检测 Git 仓库，非 Git 仓库时自动降级为全量扫描
"""

import os
import sys
import subprocess
import json
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners import EnhancedSecurityScanner
from scanners.ai_security_detector import AISecurityDetector
from scanners.repository_manager import repository_manager
from utils import ConfigManager


@dataclass
class DiffResult:
    """差异结果数据类"""
    changed_files: List[str]  # 发生变化的文件列表
    added_lines: Dict[str, List[int]]  # 新增的行号
    modified_lines: Dict[str, List[int]]  # 修改的行号
    deleted_lines: Dict[str, List[int]]  # 删除的行号


class DiffScanner:
    """差异化扫描器"""
    
    def __init__(self, target: str, config: Dict[str, Any] = None):
        """初始化差异化扫描器
        
        Args:
            target: 目标路径
            config: 配置字典
        """
        self.target = target
        self.config = config or {}
        self.config_manager = ConfigManager()
        self.base_scanner = EnhancedSecurityScanner(target)
        self.ai_detector = AISecurityDetector()
        
        # 初始化仓库管理器
        repository_manager.initialize(target)
        self.is_git_repo = repository_manager.is_git_repo()
    
    def get_git_diff(self, base_ref: str, head_ref: str) -> DiffResult:
        """获取 Git 差异
        
        Args:
            base_ref: 基准版本（分支、提交、标签）
            head_ref: 目标版本（分支、提交、标签）
            
        Returns:
            DiffResult: 差异结果
        """
        # 检查是否在 Git 仓库中
        if not os.path.exists(os.path.join(self.target, '.git')):
            raise ValueError(f"{self.target} 不是 Git 仓库")
        
        # 运行 git diff 命令
        cmd = f"git -C {self.target} diff --no-index {base_ref} {head_ref}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                # 尝试另一种方式
                cmd = f"git -C {self.target} diff {base_ref}..{head_ref}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception(f"Git diff 命令失败: {result.stderr}")
        except Exception as e:
            raise Exception(f"获取 Git 差异失败: {e}")
        
        # 解析 diff 输出
        return self._parse_git_diff(result.stdout)
    
    def _parse_git_diff(self, diff_output: str) -> DiffResult:
        """解析 Git diff 输出
        
        Args:
            diff_output: Git diff 命令的输出
            
        Returns:
            DiffResult: 差异结果
        """
        changed_files = []
        added_lines = {}
        modified_lines = {}
        deleted_lines = {}
        
        current_file = None
        line_numbers = {}
        line_type = None
        
        for line in diff_output.split('\n'):
            line = line.rstrip()
            
            # 处理文件头
            if line.startswith('diff --git'):
                # 提取文件路径
                parts = line.split(' ')
                if len(parts) >= 4:
                    # 格式: diff --git a/path/to/file b/path/to/file
                    file_path = parts[3].replace('b/', '')
                    current_file = os.path.join(self.target, file_path)
                    changed_files.append(current_file)
                    added_lines[current_file] = []
                    modified_lines[current_file] = []
                    deleted_lines[current_file] = []
            
            # 处理行号信息
            elif line.startswith('@@'):
                # 格式: @@ -1,5 +1,6 @@
                parts = line.split(' ')
                if len(parts) >= 3:
                    # 提取旧文件和新文件的行号范围
                    old_range = parts[1].replace('-', '')
                    new_range = parts[2].replace('+', '')
                    line_numbers['old'] = self._parse_line_range(old_range)
                    line_numbers['new'] = self._parse_line_range(new_range)
            
            # 处理新增行
            elif line.startswith('+') and not line.startswith('+++'):
                if current_file:
                    # 计算新文件的行号
                    if 'new' in line_numbers and line_numbers['new']:
                        line_num = line_numbers['new'][0]
                        added_lines[current_file].append(line_num)
                        line_numbers['new'] = (line_num + 1, line_numbers['new'][1] + 1)
            
            # 处理删除行
            elif line.startswith('-') and not line.startswith('---'):
                if current_file:
                    # 计算旧文件的行号
                    if 'old' in line_numbers and line_numbers['old']:
                        line_num = line_numbers['old'][0]
                        deleted_lines[current_file].append(line_num)
                        line_numbers['old'] = (line_num + 1, line_numbers['old'][1] + 1)
            
            # 处理未修改行
            elif line.startswith(' '):
                if current_file:
                    # 计算行号
                    if 'old' in line_numbers and line_numbers['old']:
                        line_numbers['old'] = (line_numbers['old'][0] + 1, line_numbers['old'][1] + 1)
                    if 'new' in line_numbers and line_numbers['new']:
                        line_numbers['new'] = (line_numbers['new'][0] + 1, line_numbers['new'][1] + 1)
        
        return DiffResult(
            changed_files=changed_files,
            added_lines=added_lines,
            modified_lines=modified_lines,
            deleted_lines=deleted_lines
        )
    
    def _parse_line_range(self, range_str: str) -> tuple:
        """解析行号范围
        
        Args:
            range_str: 行号范围字符串，格式为 "start,count"
            
        Returns:
            tuple: (start_line, end_line)
        """
        parts = range_str.split(',')
        if len(parts) == 1:
            start = int(parts[0])
            return (start, start)
        else:
            start = int(parts[0])
            count = int(parts[1])
            return (start, start + count - 1)
    
    def scan_diff(self, base_ref: str, head_ref: str) -> Dict[str, Any]:
        """执行差异化扫描
        
        Args:
            base_ref: 基准版本（分支、提交、标签）
            head_ref: 目标版本（分支、提交、标签）
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        # 获取差异
        diff_result = self.get_git_diff(base_ref, head_ref)
        
        # 如果没有变化，返回空结果
        if not diff_result.changed_files:
            return {
                "target": self.target,
                "diff_info": {
                    "base_ref": base_ref,
                    "head_ref": head_ref,
                    "changed_files": [],
                    "added_lines": {},
                    "modified_lines": {},
                    "deleted_lines": {}
                },
                "code_security": [],
                "ai_security": [],
                "injection_security": [],
                "network_security": [],
                "container_security": [],
                "cloud_security": [],
                "privacy_security": [],
                "permission_security": [],
                "dependency_security": [],
                "config_security": [],
                "supply_chain_security": [],
                "compliance_governance": []
            }
        
        # 执行扫描
        results = {
            "target": self.target,
            "diff_info": {
                "base_ref": base_ref,
                "head_ref": head_ref,
                "changed_files": diff_result.changed_files,
                "added_lines": diff_result.added_lines,
                "modified_lines": diff_result.modified_lines,
                "deleted_lines": diff_result.deleted_lines
            },
            "code_security": [],
            "ai_security": [],
            "injection_security": [],
            "network_security": [],
            "container_security": [],
            "cloud_security": [],
            "privacy_security": [],
            "permission_security": [],
            "dependency_security": [],
            "config_security": [],
            "supply_chain_security": [],
            "compliance_governance": []
        }
        
        # 扫描每个变化的文件
        for file_path in diff_result.changed_files:
            if os.path.exists(file_path):
                # 读取文件内容
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 扫描文件
                    file_results = self._scan_file(file_path, content, diff_result)
                    
                    # 合并结果
                    for category, issues in file_results.items():
                        if category in results:
                            results[category].extend(issues)
                except Exception as e:
                    print(f"扫描文件 {file_path} 失败: {e}")
        
        return results
    
    def _scan_file(self, file_path: str, content: str, diff_result: DiffResult) -> Dict[str, List[Dict[str, Any]]]:
        """扫描单个文件
        
        Args:
            file_path: 文件路径
            content: 文件内容
            diff_result: 差异结果
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: 扫描结果
        """
        results = {
            "code_security": [],
            "ai_security": [],
            "injection_security": [],
            "network_security": [],
            "container_security": [],
            "cloud_security": [],
            "privacy_security": [],
            "permission_security": [],
            "dependency_security": [],
            "config_security": [],
            "supply_chain_security": [],
            "compliance_governance": []
        }
        
        # 获取变化的行号
        changed_lines = set()
        if file_path in diff_result.added_lines:
            changed_lines.update(diff_result.added_lines[file_path])
        if file_path in diff_result.modified_lines:
            changed_lines.update(diff_result.modified_lines[file_path])
        
        if not changed_lines:
            return results
        
        # 提取变化的代码片段
        lines = content.split('\n')
        changed_code_lines = []
        for line_num in sorted(changed_lines):
            if 1 <= line_num <= len(lines):
                changed_code_lines.append((line_num, lines[line_num - 1]))
        
        # 构建变化的代码片段
        changed_code = '\n'.join([line for _, line in changed_code_lines])
        
        # 使用 AI 安全检测器进行深度分析
        ai_issues = self.ai_detector.detect_ai_security_issues(changed_code, file_path)
        
        # 处理 AI 检测结果
        for issue in ai_issues:
            # 映射到合适的类别
            category = "ai_security"
            if "injection" in issue.issue_type:
                category = "injection_security"
            elif "privacy" in issue.issue_type:
                category = "privacy_security"
            
            # 转换为标准格式
            issue_dict = {
                "file": issue.file_path,
                "line_number": issue.line_number,
                "issue": issue.issue_type,
                "severity": issue.severity,
                "details": issue.details.get('description', ''),
                "code_snippet": issue.code_snippet,
                "detection_method": "ai_diff_scan",
                "confidence": issue.confidence,
                "category": category
            }
            
            # 添加攻击场景和修复建议（如果有）
            if 'exploit_scenario' in issue.details:
                issue_dict['exploit_scenario'] = issue.details['exploit_scenario']
            if 'recommendation' in issue.details:
                issue_dict['recommendation'] = issue.details['recommendation']
            
            if category in results:
                results[category].append(issue_dict)
        
        # 传统模式匹配扫描
        import re
        
        # 检查硬编码的 API 密钥
        api_key_pattern = r'api[_\s]*key[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{30,})["\']'
        matches = re.finditer(api_key_pattern, content, re.IGNORECASE)
        
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            if line_number in changed_lines:
                results["code_security"].append({
                    "file": file_path,
                    "line_number": line_number,
                    "issue": "硬编码的 API 密钥",
                    "severity": "high",
                    "details": f"发现硬编码的 API 密钥: {match.group(1)}",
                    "code_snippet": lines[line_number - 1].strip(),
                    "detection_method": "diff_scan",
                    "confidence": 0.9,
                    "category": "code_security"
                })
        
        # 检查 SQL 注入
        sql_injection_pattern = r'\bSELECT\b.*\bFROM\b.*[\'"].*\{.*\}.*[\'"]'
        matches = re.finditer(sql_injection_pattern, content, re.IGNORECASE)
        
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            if line_number in changed_lines:
                results["injection_security"].append({
                    "file": file_path,
                    "line_number": line_number,
                    "issue": "SQL 注入风险",
                    "severity": "high",
                    "details": "检测到可能的 SQL 注入风险",
                    "code_snippet": lines[line_number - 1].strip(),
                    "detection_method": "diff_scan",
                    "confidence": 0.85,
                    "category": "injection_security"
                })
        
        # 检查命令注入
        command_injection_pattern = r'\bsubprocess\.run\(\s*["\'].*\{.*\}.*["\']'
        matches = re.finditer(command_injection_pattern, content, re.IGNORECASE)
        
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            if line_number in changed_lines:
                results["injection_security"].append({
                    "file": file_path,
                    "line_number": line_number,
                    "issue": "命令注入风险",
                    "severity": "high",
                    "details": "检测到可能的命令注入风险",
                    "code_snippet": lines[line_number - 1].strip(),
                    "detection_method": "diff_scan",
                    "confidence": 0.85,
                    "category": "injection_security"
                })
        
        return results
    
    def scan_branch(self, base_branch: str, head_branch: str) -> Dict[str, Any]:
        """扫描两个分支之间的差异
        
        Args:
            base_branch: 基准分支
            head_branch: 目标分支
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        return self.scan_diff(base_branch, head_branch)
    
    def scan_commit(self, base_commit: str, head_commit: str) -> Dict[str, Any]:
        """扫描两个提交之间的差异
        
        Args:
            base_commit: 基准提交
            head_commit: 目标提交
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        return self.scan_diff(base_commit, head_commit)
    
    def scan_tag(self, base_tag: str, head_tag: str) -> Dict[str, Any]:
        """扫描两个标签之间的差异
        
        Args:
            base_tag: 基准标签
            head_tag: 目标标签
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        return self.scan_diff(base_tag, head_tag)
    
    def scan_staged(self) -> Dict[str, Any]:
        """扫描暂存的更改
        
        Returns:
            Dict[str, Any]: 扫描结果
        """
        return self.scan_diff('HEAD', 'HEAD --cached')
    
    def scan_unstaged(self) -> Dict[str, Any]:
        """扫描未暂存的更改
        
        Returns:
            Dict[str, Any]: 扫描结果
        """
        return self.scan_diff('HEAD --cached', 'HEAD')
    
    def smart_scan(self, extensions=None) -> Dict[str, Any]:
        """智能扫描 - 根据是否是 Git 仓库决定扫描方式
        
        Args:
            extensions: 文件扩展名列表，用于全量扫描时过滤文件
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        if self.is_git_repo:
            # 执行差异扫描
            print("检测到 Git 仓库，执行差异扫描...")
            return self.scan_unstaged()
        else:
            # 执行全量扫描
            print("未检测到 Git 仓库，执行全量扫描...")
            return self._full_scan(extensions)
    
    def _full_scan(self, extensions=None) -> Dict[str, Any]:
        """执行全量扫描
        
        Args:
            extensions: 文件扩展名列表，用于过滤文件
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        # 获取所有文件
        all_files = repository_manager.get_all_files(extensions)
        
        results = {
            "target": self.target,
            "diff_info": {
                "base_ref": "full_scan",
                "head_ref": "full_scan",
                "changed_files": all_files,
                "added_lines": {},
                "modified_lines": {},
                "deleted_lines": {}
            },
            "code_security": [],
            "ai_security": [],
            "injection_security": [],
            "network_security": [],
            "container_security": [],
            "cloud_security": [],
            "privacy_security": [],
            "permission_security": [],
            "dependency_security": [],
            "config_security": [],
            "supply_chain_security": [],
            "compliance_governance": []
        }
        
        # 扫描每个文件
        for file_path in all_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 构建假的差异结果，包含整个文件
                    lines = content.split('\n')
                    changed_lines = set(range(1, len(lines) + 1))
                    
                    # 构建差异结果对象
                    diff_result = DiffResult(
                        changed_files=[file_path],
                        added_lines={file_path: list(changed_lines)},
                        modified_lines={},
                        deleted_lines={}
                    )
                    
                    # 扫描文件
                    file_results = self._scan_file(file_path, content, diff_result)
                    
                    # 合并结果
                    for category, issues in file_results.items():
                        if category in results:
                            results[category].extend(issues)
                except Exception as e:
                    print(f"扫描文件 {file_path} 失败: {e}")
        
        return results


if __name__ == '__main__':
    # 测试差异化扫描功能
    import argparse
    
    parser = argparse.ArgumentParser(description='差异化扫描功能测试')
    parser.add_argument('target', help='目标路径')
    parser.add_argument('--base', required=True, help='基准版本（分支、提交、标签）')
    parser.add_argument('--head', required=True, help='目标版本（分支、提交、标签）')
    parser.add_argument('--output', default='diff_scan_results.json', help='输出文件路径')
    
    args = parser.parse_args()
    
    # 创建差异化扫描器
    scanner = DiffScanner(args.target)
    
    # 执行差异化扫描
    print(f"开始差异化扫描: {args.base} -> {args.head}")
    results = scanner.scan_diff(args.base, args.head)
    
    # 保存结果
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"差异化扫描完成，结果保存到: {args.output}")
    print(f"扫描了 {len(results['diff_info']['changed_files'])} 个变化的文件")
    
    # 打印结果摘要
    for category, issues in results.items():
        if isinstance(issues, list) and issues:
            print(f"{category}: {len(issues)} 个问题")

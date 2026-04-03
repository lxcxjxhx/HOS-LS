#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PR 安全审计脚本
用于 GitHub Action 中的 PR 安全扫描
"""

import os
import json
import requests
from pathlib import Path
from typing import Dict, Any, List, Tuple

class GitHubActionClient:
    """GitHub API 客户端"""
    
    def __init__(self):
        """初始化 GitHub 客户端"""
        self.token = os.environ.get('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GITHUB_TOKEN 环境变量未设置")
        
        self.headers = {
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # 获取排除目录
        exclude_dirs = os.environ.get('EXCLUDE_DIRECTORIES', '')
        self.excluded_dirs = [d.strip() for d in exclude_dirs.split(',') if d.strip()] if exclude_dirs else []
    
    def get_pr_data(self, repo: str, pr_number: int) -> Dict[str, Any]:
        """获取 PR 数据
        
        Args:
            repo: 仓库名称 (owner/repo)
            pr_number: PR 编号
            
        Returns:
            PR 数据
        """
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def get_pr_diff(self, repo: str, pr_number: int) -> str:
        """获取 PR 差异
        
        Args:
            repo: 仓库名称
            pr_number: PR 编号
            
        Returns:
            PR 差异内容
        """
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
        headers = {**self.headers, 'Accept': 'application/vnd.github.diff'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.text
    
    def create_review_comment(self, repo: str, pr_number: int, comments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """创建 PR 评论
        
        Args:
            repo: 仓库名称
            pr_number: PR 编号
            comments: 评论列表
            
        Returns:
            评论结果
        """
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
        data = {
            "event": "COMMENT",
            "body": "## 🔒 HOS-LS Security Scan Results",
            "comments": comments
        }
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def _is_excluded(self, file_path: str) -> bool:
        """检查文件是否在排除目录中
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否排除
        """
        for excluded_dir in self.excluded_dirs:
            if excluded_dir in file_path:
                return True
        return False

def get_environment_config() -> Tuple[str, int]:
    """获取环境配置
    
    Returns:
        (仓库名称, PR 编号)
    """
    repo_name = os.environ.get('GITHUB_REPOSITORY')
    pr_number_str = os.environ.get('PR_NUMBER')
    
    if not repo_name:
        raise ValueError('GITHUB_REPOSITORY 环境变量未设置')
    
    if not pr_number_str:
        raise ValueError('PR_NUMBER 环境变量未设置')
    
    try:
        pr_number = int(pr_number_str)
    except ValueError:
        raise ValueError(f'无效的 PR_NUMBER: {pr_number_str}')
        
    return repo_name, pr_number

def main():
    """主函数"""
    try:
        # 获取环境配置
        repo_name, pr_number = get_environment_config()
        
        # 获取输入参数
        ai_provider = os.environ.get('INPUT_AI-PROVIDER', 'deepseek')
        ai_api_key = os.environ.get('INPUT_AI-API-KEY')
        enable_ai_filter = os.environ.get('INPUT_ENABLE-AI-FILTER') == 'true'
        exclude_directories = os.environ.get('INPUT_EXCLUDE-DIRECTORIES', 'node_modules,venv,.venv')
        
        # 设置排除目录环境变量
        os.environ['EXCLUDE_DIRECTORIES'] = exclude_directories
        
        # 初始化 GitHub 客户端
        github_client = GitHubActionClient()
        
        # 获取 PR 数据
        pr_data = github_client.get_pr_data(repo_name, pr_number)
        pr_diff = github_client.get_pr_diff(repo_name, pr_number)
        
        # 初始化 HOS-LS 扫描器
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        
        from src.scanners.enhanced_scanner import EnhancedSecurityScanner
        from src.utils.findings_filter import FindingsFilter
        
        # 执行扫描
        print(f"开始扫描仓库: {repo_name}")
        scanner = EnhancedSecurityScanner('.', silent=True)
        scan_results = scanner.scan()
        
        # 提取所有发现
        all_findings = []
        for category, findings in scan_results.items():
            if isinstance(findings, list):
                all_findings.extend(findings)
        
        # 过滤误报
        print(f"过滤 {len(all_findings)} 个发现")
        filter = FindingsFilter(use_hard_exclusions=True, use_ai_filtering=enable_ai_filter)
        success, filtered_results, stats = filter.filter_findings(all_findings)
        
        # 生成 PR 评论
        comments = []
        for finding in filtered_results['filtered_findings']:
            file_path = finding.get('file', '')
            if github_client._is_excluded(file_path):
                continue
            
            comments.append({
                "path": file_path,
                "line": finding.get('line_number', 1),
                "body": f"**{finding.get('severity', 'MEDIUM').upper()}**: {finding.get('issue', '')}\n\n{finding.get('details', '')}"
            })
        
        # 发送 PR 评论
        if comments:
            print(f"生成 {len(comments)} 条评论")
            github_client.create_review_comment(repo_name, pr_number, comments)
        else:
            print("未发现需要评论的安全问题")
        
        # 准备输出结果
        output = {
            "repo": repo_name,
            "pr_number": pr_number,
            "findings_count": len(filtered_results['filtered_findings']),
            "findings": filtered_results['filtered_findings'],
            "excluded_count": len(filtered_results['excluded_findings']),
            "summary": filtered_results['analysis_summary']
        }
        
        # 输出结果
        print(json.dumps(output, indent=2, ensure_ascii=False))
        
        # 保存结果到文件
        with open('scan-results.json', 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        # 退出代码
        high_severity_count = len([f for f in filtered_results['filtered_findings'] if f.get('severity', '').lower() == 'high'])
        exit(1 if high_severity_count > 0 else 0)
        
    except Exception as e:
        print(json.dumps({'error': str(e)}, ensure_ascii=False))
        exit(1)

if __name__ == '__main__':
    main()
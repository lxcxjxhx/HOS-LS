#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PR 评论功能模块

功能：
1. 集成 GitHub API 进行 PR 评论
2. 分析扫描结果，生成结构化评论内容
3. 支持评论格式定制
4. 支持评论更新和删除
5. 支持不同代码托管平台（GitHub, GitLab, Gitee）
"""

import os
import sys
import json
import requests
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import ConfigManager


@dataclass
class PRComment:
    """PR 评论数据类"""
    body: str
    path: Optional[str] = None
    line: Optional[int] = None
    side: Optional[str] = None


class PRCommenter:
    """PR 评论器"""
    
    def __init__(self, platform: str = 'github', config: Dict[str, Any] = None):
        """初始化 PR 评论器
        
        Args:
            platform: 代码托管平台 (github, gitlab, gitee)
            config: 配置字典
        """
        self.platform = platform.lower()
        self.config = config or {}
        self.config_manager = ConfigManager()
        
        # 从配置中获取相关设置
        self.token = self.config.get('token') or self.config_manager.get('pr_comment.github_token')
        self.api_url = self.config.get('api_url') or self._get_default_api_url()
        self.repo_owner = self.config.get('repo_owner')
        self.repo_name = self.config.get('repo_name')
        self.pr_number = self.config.get('pr_number')
        
    def _get_default_api_url(self) -> str:
        """获取默认 API URL"""
        if self.platform == 'github':
            return 'https://api.github.com'
        elif self.platform == 'gitlab':
            return 'https://gitlab.com/api/v4'
        elif self.platform == 'gitee':
            return 'https://gitee.com/api/v5'
        else:
            return 'https://api.github.com'
    
    def _get_headers(self) -> Dict[str, str]:
        """获取 API 请求头"""
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers
    
    def generate_comment_body(self, scan_results: Dict[str, Any]) -> str:
        """生成评论内容
        
        Args:
            scan_results: 扫描结果
            
        Returns:
            评论内容
        """
        # 生成风险统计
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        for category, issues in scan_results.items():
            if isinstance(issues, list):
                for issue in issues:
                    severity = issue.get('severity', 'low')
                    if severity == 'high':
                        high_risk += 1
                    elif severity == 'medium':
                        medium_risk += 1
                    else:
                        low_risk += 1
        
        # 生成评论标题
        comment_body = f"## HOS-LS 安全扫描结果\n\n"
        
        # 生成风险摘要
        comment_body += f"### 风险摘要\n"
        comment_body += f"- 高风险: {high_risk}\n"
        comment_body += f"- 中风险: {medium_risk}\n"
        comment_body += f"- 低风险: {low_risk}\n\n"
        
        # 生成风险评估
        if high_risk > 0:
            comment_body += "### 风险评估\n"
            comment_body += "**高风险** - 系统存在严重安全隐患，建议立即处理高风险问题。\n\n"
        elif medium_risk > 3:
            comment_body += "### 风险评估\n"
            comment_body += "**中风险** - 系统存在一定安全风险，建议尽快处理中风险问题。\n\n"
        else:
            comment_body += "### 风险评估\n"
            comment_body += "**低风险** - 系统安全状态良好，建议定期进行安全检查。\n\n"
        
        # 生成详细问题列表
        comment_body += "### 详细问题\n"
        
        # 按严重程度排序的问题
        high_issues = []
        medium_issues = []
        low_issues = []
        
        for category, issues in scan_results.items():
            if isinstance(issues, list):
                for issue in issues:
                    if issue.get('severity') == 'high':
                        high_issues.append(issue)
                    elif issue.get('severity') == 'medium':
                        medium_issues.append(issue)
                    else:
                        low_issues.append(issue)
        
        # 添加高风险问题
        if high_issues:
            comment_body += "#### 高风险问题\n"
            for issue in high_issues:
                file_path = issue.get('file', 'unknown')
                line_number = issue.get('line_number', 'N/A')
                issue_desc = issue.get('issue', 'unknown')
                details = issue.get('details', '')
                
                comment_body += f"- **{file_path}:{line_number}** - {issue_desc}\n"
                if details:
                    comment_body += f"  - 详情: {details}\n"
            comment_body += "\n"
        
        # 添加中风险问题
        if medium_issues:
            comment_body += "#### 中风险问题\n"
            for issue in medium_issues[:5]:  # 只显示前5个
                file_path = issue.get('file', 'unknown')
                line_number = issue.get('line_number', 'N/A')
                issue_desc = issue.get('issue', 'unknown')
                
                comment_body += f"- **{file_path}:{line_number}** - {issue_desc}\n"
            if len(medium_issues) > 5:
                comment_body += f"... 还有 {len(medium_issues) - 5} 个中风险问题\n"
            comment_body += "\n"
        
        # 添加低风险问题
        if low_issues:
            comment_body += "#### 低风险问题\n"
            comment_body += f"发现 {len(low_issues)} 个低风险问题\n\n"
        
        # 生成安全建议
        comment_body += "### 安全建议\n"
        comment_body += "1. 立即处理所有高风险问题\n"
        comment_body += "2. 尽快处理中风险问题\n"
        comment_body += "3. 定期进行安全扫描，保持系统和依赖库的更新\n"
        comment_body += "4. 遵循安全编码最佳实践\n\n"
        
        # 添加报告链接
        comment_body += "### 完整报告\n"
        comment_body += "请查看完整的安全扫描报告以获取更多详细信息。\n"
        
        return comment_body
    
    def create_comment(self, comment_body: str) -> Dict[str, Any]:
        """创建 PR 评论
        
        Args:
            comment_body: 评论内容
            
        Returns:
            API 响应
        """
        if self.platform == 'github':
            return self._create_github_comment(comment_body)
        elif self.platform == 'gitlab':
            return self._create_gitlab_comment(comment_body)
        elif self.platform == 'gitee':
            return self._create_gitee_comment(comment_body)
        else:
            raise ValueError(f"不支持的平台: {self.platform}")
    
    def _create_github_comment(self, comment_body: str) -> Dict[str, Any]:
        """创建 GitHub PR 评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/issues/{self.pr_number}/comments"
        headers = self._get_headers()
        data = {
            'body': comment_body
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"创建 GitHub 评论失败: {e}")
            return {}
    
    def _create_gitlab_comment(self, comment_body: str) -> Dict[str, Any]:
        """创建 GitLab MR 评论"""
        url = f"{self.api_url}/projects/{self.repo_owner}%2F{self.repo_name}/merge_requests/{self.pr_number}/notes"
        headers = self._get_headers()
        data = {
            'body': comment_body
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"创建 GitLab 评论失败: {e}")
            return {}
    
    def _create_gitee_comment(self, comment_body: str) -> Dict[str, Any]:
        """创建 Gitee PR 评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/pulls/{self.pr_number}/comments"
        headers = self._get_headers()
        data = {
            'body': comment_body
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"创建 Gitee 评论失败: {e}")
            return {}
    
    def create_inline_comment(self, comment: PRComment) -> Dict[str, Any]:
        """创建内联评论
        
        Args:
            comment: PRComment 对象
            
        Returns:
            API 响应
        """
        if self.platform == 'github':
            return self._create_github_inline_comment(comment)
        elif self.platform == 'gitlab':
            return self._create_gitlab_inline_comment(comment)
        elif self.platform == 'gitee':
            return self._create_gitee_inline_comment(comment)
        else:
            raise ValueError(f"不支持的平台: {self.platform}")
    
    def _create_github_inline_comment(self, comment: PRComment) -> Dict[str, Any]:
        """创建 GitHub 内联评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/pulls/{self.pr_number}/comments"
        headers = self._get_headers()
        data = {
            'body': comment.body,
            'path': comment.path,
            'line': comment.line,
            'side': comment.side or 'RIGHT'
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"创建 GitHub 内联评论失败: {e}")
            return {}
    
    def _create_gitlab_inline_comment(self, comment: PRComment) -> Dict[str, Any]:
        """创建 GitLab 内联评论"""
        url = f"{self.api_url}/projects/{self.repo_owner}%2F{self.repo_name}/merge_requests/{self.pr_number}/discussions"
        headers = self._get_headers()
        data = {
            'body': comment.body,
            'position': {
                'base_sha': self.config.get('base_sha'),
                'head_sha': self.config.get('head_sha'),
                'start_sha': self.config.get('start_sha'),
                'position_type': 'text',
                'path': comment.path,
                'line': comment.line
            }
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"创建 GitLab 内联评论失败: {e}")
            return {}
    
    def _create_gitee_inline_comment(self, comment: PRComment) -> Dict[str, Any]:
        """创建 Gitee 内联评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/pulls/{self.pr_number}/comments"
        headers = self._get_headers()
        data = {
            'body': comment.body,
            'path': comment.path,
            'line': comment.line,
            'side': comment.side or 'right'
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"创建 Gitee 内联评论失败: {e}")
            return {}
    
    def update_comment(self, comment_id: str, comment_body: str) -> Dict[str, Any]:
        """更新评论
        
        Args:
            comment_id: 评论 ID
            comment_body: 新的评论内容
            
        Returns:
            API 响应
        """
        if self.platform == 'github':
            return self._update_github_comment(comment_id, comment_body)
        elif self.platform == 'gitlab':
            return self._update_gitlab_comment(comment_id, comment_body)
        elif self.platform == 'gitee':
            return self._update_gitee_comment(comment_id, comment_body)
        else:
            raise ValueError(f"不支持的平台: {self.platform}")
    
    def _update_github_comment(self, comment_id: str, comment_body: str) -> Dict[str, Any]:
        """更新 GitHub 评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/issues/comments/{comment_id}"
        headers = self._get_headers()
        data = {
            'body': comment_body
        }
        
        try:
            response = requests.patch(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"更新 GitHub 评论失败: {e}")
            return {}
    
    def _update_gitlab_comment(self, comment_id: str, comment_body: str) -> Dict[str, Any]:
        """更新 GitLab 评论"""
        url = f"{self.api_url}/projects/{self.repo_owner}%2F{self.repo_name}/merge_requests/notes/{comment_id}"
        headers = self._get_headers()
        data = {
            'body': comment_body
        }
        
        try:
            response = requests.put(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"更新 GitLab 评论失败: {e}")
            return {}
    
    def _update_gitee_comment(self, comment_id: str, comment_body: str) -> Dict[str, Any]:
        """更新 Gitee 评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/pulls/comments/{comment_id}"
        headers = self._get_headers()
        data = {
            'body': comment_body
        }
        
        try:
            response = requests.patch(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"更新 Gitee 评论失败: {e}")
            return {}
    
    def delete_comment(self, comment_id: str) -> bool:
        """删除评论
        
        Args:
            comment_id: 评论 ID
            
        Returns:
            是否成功
        """
        if self.platform == 'github':
            return self._delete_github_comment(comment_id)
        elif self.platform == 'gitlab':
            return self._delete_gitlab_comment(comment_id)
        elif self.platform == 'gitee':
            return self._delete_gitee_comment(comment_id)
        else:
            raise ValueError(f"不支持的平台: {self.platform}")
    
    def _delete_github_comment(self, comment_id: str) -> bool:
        """删除 GitHub 评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/issues/comments/{comment_id}"
        headers = self._get_headers()
        
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"删除 GitHub 评论失败: {e}")
            return False
    
    def _delete_gitlab_comment(self, comment_id: str) -> bool:
        """删除 GitLab 评论"""
        url = f"{self.api_url}/projects/{self.repo_owner}%2F{self.repo_name}/merge_requests/notes/{comment_id}"
        headers = self._get_headers()
        
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"删除 GitLab 评论失败: {e}")
            return False
    
    def _delete_gitee_comment(self, comment_id: str) -> bool:
        """删除 Gitee 评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/pulls/comments/{comment_id}"
        headers = self._get_headers()
        
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"删除 Gitee 评论失败: {e}")
            return False
    
    def list_comments(self) -> List[Dict[str, Any]]:
        """列出所有评论
        
        Returns:
            评论列表
        """
        if self.platform == 'github':
            return self._list_github_comments()
        elif self.platform == 'gitlab':
            return self._list_gitlab_comments()
        elif self.platform == 'gitee':
            return self._list_gitee_comments()
        else:
            raise ValueError(f"不支持的平台: {self.platform}")
    
    def _list_github_comments(self) -> List[Dict[str, Any]]:
        """列出 GitHub 评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/issues/{self.pr_number}/comments"
        headers = self._get_headers()
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"列出 GitHub 评论失败: {e}")
            return []
    
    def _list_gitlab_comments(self) -> List[Dict[str, Any]]:
        """列出 GitLab 评论"""
        url = f"{self.api_url}/projects/{self.repo_owner}%2F{self.repo_name}/merge_requests/{self.pr_number}/notes"
        headers = self._get_headers()
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"列出 GitLab 评论失败: {e}")
            return []
    
    def _list_gitee_comments(self) -> List[Dict[str, Any]]:
        """列出 Gitee 评论"""
        url = f"{self.api_url}/repos/{self.repo_owner}/{self.repo_name}/pulls/{self.pr_number}/comments"
        headers = self._get_headers()
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"列出 Gitee 评论失败: {e}")
            return []
    
    def comment_on_pr(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """在 PR 上发表评论
        
        Args:
            scan_results: 扫描结果
            
        Returns:
            API 响应
        """
        # 生成评论内容
        comment_body = self.generate_comment_body(scan_results)
        
        # 创建评论
        return self.create_comment(comment_body)
    
    def comment_on_files(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """在文件上发表内联评论
        
        Args:
            scan_results: 扫描结果
            
        Returns:
            API 响应列表
        """
        responses = []
        
        # 遍历所有问题，创建内联评论
        for category, issues in scan_results.items():
            if isinstance(issues, list):
                for issue in issues:
                    # 只对高风险和中风险问题创建内联评论
                    if issue.get('severity') in ['high', 'medium']:
                        file_path = issue.get('file')
                        line_number = issue.get('line_number')
                        
                        if file_path and line_number:
                            # 生成内联评论内容
                            comment_body = f"**{issue.get('severity').upper()}风险** - {issue.get('issue')}\n"
                            details = issue.get('details')
                            if details:
                                comment_body += f"\n详情: {details}\n"
                            
                            # 添加攻击场景（如果有）
                            exploit_scenario = issue.get('exploit_scenario')
                            if exploit_scenario:
                                comment_body += f"\n**攻击场景**: {exploit_scenario}\n"
                            
                            # 添加修复建议（如果有）
                            recommendation = issue.get('recommendation')
                            if recommendation:
                                comment_body += f"\n**修复建议**: {recommendation}\n"
                            else:
                                comment_body += "\n**建议**: 请修复此安全问题\n"
                            
                            # 添加检测方法
                            detection_method = issue.get('detection_method', 'unknown')
                            comment_body += f"\n**检测方法**: {detection_method}\n"
                            
                            # 添加置信度
                            confidence = issue.get('confidence', 0.0)
                            comment_body += f"**置信度**: {confidence:.2f}\n"
                            
                            # 创建 PRComment 对象
                            comment = PRComment(
                                body=comment_body,
                                path=file_path,
                                line=line_number,
                                side='RIGHT'
                            )
                            
                            # 创建内联评论
                            response = self.create_inline_comment(comment)
                            responses.append(response)
        
        return responses


if __name__ == '__main__':
    # 测试 PR 评论功能
    import argparse
    
    parser = argparse.ArgumentParser(description='PR 评论功能测试')
    parser.add_argument('--platform', default='github', choices=['github', 'gitlab', 'gitee'], help='代码托管平台')
    parser.add_argument('--repo-owner', required=True, help='仓库所有者')
    parser.add_argument('--repo-name', required=True, help='仓库名称')
    parser.add_argument('--pr-number', type=int, required=True, help='PR 编号')
    parser.add_argument('--token', required=True, help='API 令牌')
    parser.add_argument('--scan-result', help='扫描结果文件路径')
    
    args = parser.parse_args()
    
    # 加载扫描结果
    if args.scan_result and os.path.exists(args.scan_result):
        with open(args.scan_result, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
    else:
        # 使用示例扫描结果
        scan_results = {
            "target": "test_ai_security.py",
            "code_security": [
                {
                    "file": "test_ai_security.py",
                    "line_number": 20,
                    "issue": "硬编码的 API 密钥",
                    "severity": "high",
                    "details": "发现硬编码的 API 密钥: sk-1234567890abcdef"
                },
                {
                    "file": "test_ai_security.py",
                    "line_number": 23,
                    "issue": "使用危险函数 exec",
                    "severity": "high",
                    "details": "发现使用危险函数 exec()"
                }
            ],
            "ai_security": [
                {
                    "file": "test_ai_security.py",
                    "line_number": 8,
                    "issue": "Prompt 注入尝试",
                    "severity": "high",
                    "details": "检测到 Prompt 注入尝试: Ignore previous instructions"
                },
                {
                    "file": "test_ai_security.py",
                    "line_number": 11,
                    "issue": "Tool 滥用",
                    "severity": "high",
                    "details": "检测到 Tool 滥用: sudo rm -rf /"
                }
            ]
        }
    
    # 创建 PR 评论器
    commenter = PRCommenter(
        platform=args.platform,
        config={
            'token': args.token,
            'repo_owner': args.repo_owner,
            'repo_name': args.repo_name,
            'pr_number': args.pr_number
        }
    )
    
    # 测试生成评论内容
    comment_body = commenter.generate_comment_body(scan_results)
    print("生成的评论内容:")
    print(comment_body)
    
    # 测试创建评论
    # response = commenter.comment_on_pr(scan_results)
    # print("\n创建评论响应:")
    # print(json.dumps(response, indent=2, ensure_ascii=False))
    
    # 测试创建内联评论
    # responses = commenter.comment_on_files(scan_results)
    # print("\n创建内联评论响应:")
    # for i, response in enumerate(responses):
    #     print(f"内联评论 {i+1}:")
    #     print(json.dumps(response, indent=2, ensure_ascii=False))

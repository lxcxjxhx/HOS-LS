#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告生成器

功能：
1. 生成 HTML 报告
2. 生成 Markdown 报告
3. 生成 JSON 报告
4. 支持带溯源的报告输出
"""

import os
import json
import time
from typing import Dict, Any, Optional
from jinja2 import Template

class ReportGenerator:
    def __init__(self, results: Dict[str, Any], target: str, output_dir: str):
        """
        初始化报告生成器
        
        Args:
            results: 扫描结果
            target: 扫描目标
            output_dir: 输出目录
        """
        self.results = results
        self.target = target
        self.output_dir = output_dir
        self.timestamp = time.time()
    
    def generate_html(self) -> str:
        """
        生成 HTML 报告
        
        Returns:
            报告文件路径
        """
        # 读取 HTML 模板
        template_path = os.path.join(os.path.dirname(__file__), 'templates', 'html_template.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        template = Template(template_content)
        
        # 准备数据
        report_data = self._prepare_report_data()
        
        # 渲染模板
        html_content = template.render(**report_data)
        
        # 生成报告文件名
        report_filename = f"comprehensive_test_report_{time.strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(self.output_dir, report_filename)
        
        # 写入文件
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    def generate_md(self) -> str:
        """
        生成 Markdown 报告
        
        Returns:
            报告文件路径
        """
        # 读取 Markdown 模板
        template_path = os.path.join(os.path.dirname(__file__), 'templates', 'md_template.md')
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        template = Template(template_content)
        
        # 准备数据
        report_data = self._prepare_report_data()
        
        # 渲染模板
        md_content = template.render(**report_data)
        
        # 生成报告文件名
        report_filename = f"comprehensive_test_report_{time.strftime('%Y%m%d_%H%M%S')}.md"
        report_path = os.path.join(self.output_dir, report_filename)
        
        # 写入文件
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return report_path
    
    def generate_json(self) -> str:
        """
        生成 JSON 报告
        
        Returns:
            报告文件路径
        """
        # 准备数据
        report_data = self._prepare_report_data()
        
        # 生成报告文件名
        report_filename = f"comprehensive_test_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(self.output_dir, report_filename)
        
        # 写入文件
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return report_path
    
    def _prepare_report_data(self) -> Dict[str, Any]:
        """
        准备报告数据
        
        Returns:
            报告数据
        """
        # 计算风险统计
        risk_stats = self._calculate_risk_stats()
        
        # 分离MD文件和其他文件
        code_security = self.results.get('code_security', [])
        md_security = []
        other_security = []
        
        # 处理代码安全问题
        for item in code_security:
            # 确保详情字段存在
            if 'details' not in item or not item['details']:
                item['details'] = f"{item.get('issue', '未知问题')} - 请检查相关代码行"
            
            # 检查文件扩展名是否为.md
            file_path = item.get('file', '')
            if file_path.lower().endswith('.md'):
                md_security.append(item)
            else:
                other_security.append(item)
        
        # 处理其他安全类别
        security_categories = ['permission_security', 'network_security', 'dependency_security', 'config_security']
        for category in security_categories:
            items = self.results.get(category, [])
            for item in items:
                if 'details' not in item or not item['details']:
                    item['details'] = f"{item.get('issue', '未知问题')} - 请检查相关配置或代码"

        # 准备报告数据
        report_data = {
            'target': self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp)),
            'risk_stats': risk_stats,
            'results': self.results,
            'ai_suggestions': self.results.get('ai_suggestions', {}),
            'risk_assessment': self.results.get('risk_assessment', {}),
            'risk_report': self.results.get('risk_report', {}),
            'project_type': self.results.get('project_type', 'web_app'),
            'rule_set': self.results.get('rule_set', 'default'),
            'high_risk': risk_stats.get('high', 0),
            'medium_risk': risk_stats.get('medium', 0),
            'low_risk': risk_stats.get('low', 0),
            'overall_risk': 'high' if risk_stats.get('high', 0) > 0 else 'medium' if risk_stats.get('medium', 0) > 0 else 'low',
            'overall_risk_text': '高风险' if risk_stats.get('high', 0) > 0 else '中风险' if risk_stats.get('medium', 0) > 0 else '低风险',
            'security_assessment': f'本次安全扫描共发现 {risk_stats.get("high", 0)} 个高风险问题，{risk_stats.get("medium", 0)} 个中风险问题，{risk_stats.get("low", 0)} 个低风险问题。 ' + ('系统存在严重安全隐患，建议立即处理高风险问题。' if risk_stats.get('high', 0) > 0 else '系统存在一定安全风险，建议尽快处理中风险问题。' if risk_stats.get('medium', 0) > 0 else '系统安全状态良好，建议定期进行安全检查。'),
            'recommendations': [
                {'severity': '高', 'text': '立即处理所有高风险问题，特别是硬编码的敏感信息和后门代码。'},
                {'severity': '中', 'text': '尽快处理中风险问题，如网络访问代码的安全验证和依赖库版本管理。'},
                {'severity': '低', 'text': '使用环境变量存储敏感信息，避免硬编码。'},
                {'severity': '低', 'text': '遵循最小权限原则，限制文件和目录权限。'},
                {'severity': '低', 'text': '定期进行安全扫描，及时发现和处理安全问题。'}
            ],
            'code_security': other_security,
            'md_security': md_security,
            'permission_security': self.results.get('permission_security', []),
            'network_security': self.results.get('network_security', []),
            'dependency_security': self.results.get('dependency_security', []),
            'config_security': self.results.get('config_security', [])
        }
        
        return report_data
    
    def _calculate_risk_stats(self) -> Dict[str, int]:
        """
        计算风险统计
        
        Returns:
            风险统计
        """
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        for category, issues in self.results.items():
            if isinstance(issues, list):
                for issue in issues:
                    severity = issue.get('severity', 'low')
                    if severity == 'high':
                        high_risk += 1
                    elif severity == 'medium':
                        medium_risk += 1
                    else:
                        low_risk += 1
        
        return {
            'high': high_risk,
            'medium': medium_risk,
            'low': low_risk,
            'total': high_risk + medium_risk + low_risk
        }

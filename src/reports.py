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
        
        # 准备报告数据
        report_data = {
            'target': self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp)),
            'risk_stats': risk_stats,
            'results': self.results,
            'ai_suggestions': self.results.get('ai_suggestions', {}),
            'risk_assessment': self.results.get('risk_assessment', {}),
            'risk_report': self.results.get('risk_report', {})
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

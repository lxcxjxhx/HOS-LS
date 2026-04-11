"""报告生成器

生成排查报告，支持多种输出格式。
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """报告生成器
    
    生成排查报告，支持多种输出格式。
    """
    
    def generate(
        self,
        results: List[Any],
        output_path: str,
        format: str = 'json'
    ) -> None:
        """生成报告
        
        Args:
            results: 排查结果列表
            output_path: 输出路径
            format: 输出格式 (json, html, markdown)
        """
        logger.info(f"生成 {format} 格式的排查报告")
        
        # 准备报告数据
        report_data = self._prepare_report_data(results)
        
        # 确保输出目录存在
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 根据格式生成报告
        if format == 'json':
            self._generate_json_report(report_data, output_path)
        elif format == 'html':
            self._generate_html_report(report_data, output_path)
        elif format == 'markdown':
            self._generate_markdown_report(report_data, output_path)
        else:
            logger.error(f"不支持的报告格式: {format}")
            raise ValueError(f"不支持的报告格式: {format}")
        
        logger.info(f"报告生成完成: {output_path}")
    
    def _prepare_report_data(self, results: List[Any]) -> Dict[str, Any]:
        """准备报告数据
        
        Args:
            results: 排查结果列表
            
        Returns:
            报告数据
        """
        # 统计信息
        total_files = len(results)
        high_risk_files = sum(1 for r in results if r.risk_level == 'critical' or r.risk_level == 'high')
        medium_risk_files = sum(1 for r in results if r.risk_level == 'medium')
        low_risk_files = sum(1 for r in results if r.risk_level == 'low')
        
        # 按风险级别排序
        sorted_results = sorted(
            results,
            key=lambda x: ('critical', 'high', 'medium', 'low').index(x.risk_level)
        )
        
        # 提取详细信息
        detailed_results = []
        for result in sorted_results:
            detailed_results.append({
                'file_path': str(result.file_path),
                'priority_score': result.priority_score,
                'priority_level': result.priority_level,
                'risk_level': result.risk_level,
                'vulnerabilities': result.vulnerabilities,
                'test_count': len(result.test_cases),
                'analysis_summary': result.analysis_summary
            })
        
        # 漏洞统计
        vulnerability_stats = {}
        for result in results:
            for vuln in result.vulnerabilities:
                vulnerability_stats[vuln] = vulnerability_stats.get(vuln, 0) + 1
        
        # 优先级统计
        priority_stats = {}
        for result in results:
            priority_stats[result.priority_level] = priority_stats.get(result.priority_level, 0) + 1
        
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_files': total_files,
                'high_risk_files': high_risk_files,
                'medium_risk_files': medium_risk_files,
                'low_risk_files': low_risk_files,
                'vulnerability_stats': vulnerability_stats,
                'priority_stats': priority_stats
            },
            'detailed_results': detailed_results
        }
        
        return report_data
    
    def _generate_json_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """生成JSON格式报告
        
        Args:
            report_data: 报告数据
            output_path: 输出路径
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    def _generate_html_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """生成HTML格式报告
        
        Args:
            report_data: 报告数据
            output_path: 输出路径
        """
        # 使用字符串替换而不是format，避免花括号冲突
        html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>排查报告</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .summary {
            background-color: #f0f8ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border-left: 4px solid #007bff;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        .stat-label {
            font-size: 14px;
            color: #666;
        }
        .file-list {
            margin-top: 20px;
        }
        .file-item {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
            border-left: 4px solid #dc3545;
        }
        .file-item.medium {
            border-left-color: #ffc107;
        }
        .file-item.low {
            border-left-color: #28a745;
        }
        .file-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .file-path {
            font-weight: bold;
            color: #333;
        }
        .risk-level {
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        .risk-critical {
            background-color: #dc3545;
            color: white;
        }
        .risk-high {
            background-color: #fd7e14;
            color: white;
        }
        .risk-medium {
            background-color: #ffc107;
            color: #333;
        }
        .risk-low {
            background-color: #28a745;
            color: white;
        }
        .vulnerabilities {
            margin-top: 10px;
            font-size: 14px;
        }
        .vulnerability-tag {
            display: inline-block;
            background-color: #e9ecef;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            margin-right: 5px;
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>排查报告</h1>
        <p>生成时间: {generated_at}</p>
        
        <div class="summary">
            <h2>摘要</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">{total_files}</div>
                    <div class="stat-label">总文件数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{high_risk_files}</div>
                    <div class="stat-label">高风险文件</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{medium_risk_files}</div>
                    <div class="stat-label">中风险文件</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{low_risk_files}</div>
                    <div class="stat-label">低风险文件</div>
                </div>
            </div>
        </div>
        
        <h2>详细结果</h2>
        <div class="file-list">
        '''
        
        # 填充动态内容
        html = html.replace('{generated_at}', report_data['generated_at'])
        html = html.replace('{total_files}', str(report_data['summary']['total_files']))
        html = html.replace('{high_risk_files}', str(report_data['summary']['high_risk_files']))
        html = html.replace('{medium_risk_files}', str(report_data['summary']['medium_risk_files']))
        html = html.replace('{low_risk_files}', str(report_data['summary']['low_risk_files']))
        
        # 添加文件详细信息
        for item in report_data['detailed_results']:
            risk_class = item['risk_level']
            risk_style = {
                'critical': 'risk-critical',
                'high': 'risk-high',
                'medium': 'risk-medium',
                'low': 'risk-low'
            }.get(risk_class, 'risk-medium')
            
            file_item = f"""
            <div class="file-item {risk_class}">
                <div class="file-header">
                    <div class="file-path">{item['file_path']}</div>
                    <div class="risk-level {risk_style}">{item['risk_level']}</div>
                </div>
                <p>优先级: {item['priority_level']} ({item['priority_score']:.2f})</p>
                <p>分析摘要: {item['analysis_summary']}</p>
                <div class="vulnerabilities">
                    <strong>潜在漏洞:</strong>
                    {''.join([f'<span class="vulnerability-tag">{v}</span>' for v in item['vulnerabilities']])}
                </div>
            </div>
            """
            html += file_item
        
        # 闭合HTML
        html += '''
        </div>
    </div>
</body>
</html>
        '''
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_markdown_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """生成Markdown格式报告
        
        Args:
            report_data: 报告数据
            output_path: 输出路径
        """
        markdown = f"""
# 排查报告

## 基本信息
- 生成时间: {report_data['generated_at']}

## 摘要

### 统计信息
| 项目 | 数量 |
|------|------|
| 总文件数 | {report_data['summary']['total_files']} |
| 高风险文件 | {report_data['summary']['high_risk_files']} |
| 中风险文件 | {report_data['summary']['medium_risk_files']} |
| 低风险文件 | {report_data['summary']['low_risk_files']} |

### 漏洞统计
| 漏洞类型 | 出现次数 |
|---------|---------|
{''.join([f'| {k} | {v} |\n' for k, v in report_data['summary']['vulnerability_stats'].items()])}

### 优先级统计
| 优先级 | 文件数 |
|-------|-------|
{''.join([f'| {k} | {v} |\n' for k, v in report_data['summary']['priority_stats'].items()])}

## 详细结果

"""
        
        # 添加文件详细信息
        for item in report_data['detailed_results']:
            markdown += f"""
### {item['file_path']}

- **风险级别**: {item['risk_level']}
- **优先级**: {item['priority_level']} ({item['priority_score']:.2f})
- **分析摘要**: {item['analysis_summary']}
- **潜在漏洞**: {', '.join(item['vulnerabilities']) if item['vulnerabilities'] else '无'}
- **测试用例数**: {item['test_count']}

"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown)
    
    def generate_report(self, scan_results: List[Any], format: str = 'html', output_path: str = './security-report') -> str:
        """生成安全扫描报告
        
        Args:
            scan_results: 扫描结果列表
            format: 报告格式 (html, json, markdown)
            output_path: 输出路径
            
        Returns:
            生成的报告文件路径
        """
        import os
        
        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        
        # 准备报告数据
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_files': len(scan_results),
                'high_risk_files': 0,
                'medium_risk_files': 0,
                'low_risk_files': 0,
                'vulnerability_stats': {},
                'priority_stats': {}
            },
            'detailed_results': []
        }
        
        # 生成报告
        if format == 'html':
            output_file = f"{output_path}.html"
            html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描报告</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .summary {
            background-color: #f0f8ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border-left: 4px solid #007bff;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        .stat-label {
            font-size: 14px;
            color: #666;
        }
        .footer {
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>安全扫描报告</h1>
        <p>生成时间: {generated_at}</p>
        
        <div class="summary">
            <h2>摘要</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">{total_files}</div>
                    <div class="stat-label">扫描文件数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{findings_count}</div>
                    <div class="stat-label">发现问题数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{high_risk}</div>
                    <div class="stat-label">高风险问题</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{medium_risk}</div>
                    <div class="stat-label">中风险问题</div>
                </div>
            </div>
        </div>
        
        <h2>扫描结果</h2>
        <p>扫描完成，共发现 {findings_count} 个安全问题。</p>
        
        <div class="footer">
            <p>报告由 HOS-LS 安全扫描系统生成</p>
        </div>
    </div>
</body>
</html>
            '''
            
            # 填充数据
            html = html.replace('{generated_at}', report_data['generated_at'])
            html = html.replace('{total_files}', str(report_data['summary']['total_files']))
            html = html.replace('{findings_count}', str(len(scan_results)))
            html = html.replace('{high_risk}', str(report_data['summary']['high_risk_files']))
            html = html.replace('{medium_risk}', str(report_data['summary']['medium_risk_files']))
            
            # 写入文件
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
            
            return output_file
        
        elif format == 'json':
            output_file = f"{output_path}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            return output_file
        
        elif format == 'markdown':
            output_file = f"{output_path}.md"
            markdown = f"""
# 安全扫描报告

## 基本信息
- 生成时间: {report_data['generated_at']}

## 摘要

### 统计信息
| 项目 | 数量 |
|------|------|
| 扫描文件数 | {report_data['summary']['total_files']} |
| 发现问题数 | {len(scan_results)} |
| 高风险问题 | {report_data['summary']['high_risk_files']} |
| 中风险问题 | {report_data['summary']['medium_risk_files']} |
| 低风险问题 | {report_data['summary']['low_risk_files']} |

## 扫描结果
扫描完成，共发现 {len(scan_results)} 个安全问题。

## 备注
报告由 HOS-LS 安全扫描系统生成
"""
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(markdown)
            return output_file
        
        else:
            raise ValueError(f"不支持的报告格式: {format}")
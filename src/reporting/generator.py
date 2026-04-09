"""报告生成器

提供多格式报告生成功能。
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.engine import ScanResult
from src.core.config import Config, get_config

# 尝试导入 Jinja2，如果没有安装则使用简单的字符串替换
try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False


class BaseReportGenerator(ABC):
    """报告生成器基类"""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()

    @abstractmethod
    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成报告

        Args:
            results: 扫描结果列表
            output_path: 输出路径

        Returns:
            报告文件路径
        """
        pass

    @property
    @abstractmethod
    def format(self) -> str:
        """报告格式"""
        pass


class JSONReportGenerator(BaseReportGenerator):
    """JSON 报告生成器"""

    @property
    def format(self) -> str:
        return "json"

    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成 JSON 报告"""
        data = {
            "results": [r.to_dict() for r in results],
            "summary": self._generate_summary(results),
        }

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return str(output_file)

    def _generate_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成摘要"""
        total_findings = sum(len(r.findings) for r in results)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for result in results:
            for finding in result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_scans": len(results),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
        }


class HTMLReportGenerator(BaseReportGenerator):
    """HTML 报告生成器"""

    @property
    def format(self) -> str:
        return "html"

    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成 HTML 报告"""
        html_content = self._generate_html(results)

        output_file = Path(output_path)
        if output_file.suffix != ".html":
            output_file = output_file / "report.html"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(output_file)

    def _get_security_status(self, summary):
        """获取安全状态"""
        total_findings = summary["total_findings"]
        critical = summary["severity_counts"].get("critical", 0)
        high = summary["severity_counts"].get("high", 0)
        medium = summary["severity_counts"].get("medium", 0)
        
        if total_findings == 0:
            return "safe", "安全状态良好"
        elif critical > 0:
            return "critical", "严重安全风险"
        elif high > 0:
            return "high", "高安全风险"
        elif medium > 0:
            return "medium", "中等安全风险"
        else:
            return "low", "低安全风险"

    def _get_scan_duration(self, results):
        """获取扫描总时长"""
        total_duration = 0
        for result in results:
            total_duration += result.duration
        return round(total_duration, 2)

    def _generate_html(self, results: List[ScanResult]) -> str:
        """生成 HTML 内容"""
        summary = self._generate_summary(results)
        status, status_text = self._get_security_status(summary)
        total_duration = self._get_scan_duration(results)

        # 加载模板文件
        template_path = Path(__file__).parent / "templates" / "builtin" / "html" / "default.html"
        if not template_path.exists():
            # 如果模板文件不存在，使用默认模板
            return self._generate_default_html(results, summary, status, status_text, total_duration)

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template_content = f.read()

            if JINJA_AVAILABLE:
                # 使用 Jinja2 渲染模板
                template = Template(template_content)
                html = template.render(
                    summary=summary,
                    results=results,
                    status=status,
                    status_text=status_text,
                    total_duration=total_duration
                )
            else:
                # 简单的字符串替换（如果没有 Jinja2）
                html = template_content
                html = html.replace("{{ status }}", status)
                html = html.replace("{{ status_text }}", status_text)
                html = html.replace("{{ summary.total_scans }}", str(summary["total_scans"]))
                html = html.replace("{{ summary.total_findings }}", str(summary["total_findings"]))
                html = html.replace("{{ total_duration }}", str(total_duration))
                html = html.replace("{{ summary.severity_counts.critical }}", str(summary["severity_counts"].get("critical", 0)))
                html = html.replace("{{ summary.severity_counts.high }}", str(summary["severity_counts"].get("high", 0)))
                html = html.replace("{{ summary.severity_counts.medium }}", str(summary["severity_counts"].get("medium", 0)))
                html = html.replace("{{ summary.severity_counts.low }}", str(summary["severity_counts"].get("low", 0)))
                html = html.replace("{{ summary.severity_counts.info }}", str(summary["severity_counts"].get("info", 0)))

            return html
        except Exception as e:
            # 如果模板渲染失败，使用默认模板
            return self._generate_default_html(results, summary, status, status_text, total_duration)

    def _generate_default_html(self, results, summary, status, status_text, total_duration):
        """生成默认 HTML 内容（当模板文件不存在或渲染失败时使用）"""
        # 简单的默认 HTML 模板
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HOS-LS 安全扫描报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; text-align: center; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; }}
        .severity-critical {{ border-left: 4px solid #dc3545; background-color: #f8d7da; }}
        .severity-high {{ border-left: 4px solid #fd7e14; background-color: #fff3cd; }}
        .severity-medium {{ border-left: 4px solid #ffc107; background-color: #fff3cd; }}
        .severity-low {{ border-left: 4px solid #17a2b8; background-color: #d1ecf1; }}
        .severity-info {{ border-left: 4px solid #6c757d; background-color: #e2e3e5; }}
    </style>
</head>
<body>
    <h1>HOS-LS 安全扫描报告</h1>
    <div class="summary">
        <h2>扫描摘要</h2>
        <p>扫描文件数: {summary["total_scans"]}</p>
        <p>发现问题数: {summary["total_findings"]}</p>
        <p>安全状态: {status_text}</p>
    </div>
    <h2>详细发现</h2>
    """

        for result in results:
            for finding in result.findings:
                # 确保使用正确的字段
                location = getattr(finding, 'location', 'unknown')
                if isinstance(location, dict):
                    location = location.get('file', 'unknown')
                
                description = getattr(finding, 'description', getattr(finding, 'message', '无描述'))
                
                # 处理修复建议
                fix_suggestion = getattr(finding, 'fix_suggestion', '')
                fix_suggestion_html = f"<p><strong>修复建议:</strong> {fix_suggestion}</p>" if fix_suggestion else ""
                
                html += f"""
    <div class="finding severity-{finding.severity.value}">
        <h3>{finding.rule_name} ({finding.rule_id})</h3>
        <p><strong>位置:</strong> {location}</p>
        <p><strong>描述:</strong> {description}</p>
        {fix_suggestion_html}
    </div>
                """

        html += """
</body>
</html>
        """

        return html



    def _generate_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成摘要"""
        total_findings = sum(len(r.findings) for r in results)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for result in results:
            for finding in result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_scans": len(results),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
        }


class MarkdownReportGenerator(BaseReportGenerator):
    """Markdown 报告生成器"""

    @property
    def format(self) -> str:
        return "markdown"

    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成 Markdown 报告"""
        md_content = self._generate_markdown(results)

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md_content)

        return str(output_file)

    def _generate_markdown(self, results: List[ScanResult]) -> str:
        """生成 Markdown 内容"""
        summary = self._generate_summary(results)

        md = f"""# HOS-LS 安全扫描报告

## 摘要

- 扫描文件数: {summary["total_scans"]}
- 发现问题数: {summary["total_findings"]}

### 严重级别分布

| 严重级别 | 数量 |
|---------|------|
| 严重 | {summary["severity_counts"].get("critical", 0)} |
| 高 | {summary["severity_counts"].get("high", 0)} |
| 中 | {summary["severity_counts"].get("medium", 0)} |
| 低 | {summary["severity_counts"].get("low", 0)} |
| 信息 | {summary["severity_counts"].get("info", 0)} |

## 详细发现

"""

        for result in results:
            for finding in result.findings:
                md += self._generate_finding_markdown(finding)

        # 添加攻击链路分析结果
        for result in results:
            if hasattr(result, 'metadata') and 'attack_chain' in result.metadata:
                attack_chain = result.metadata['attack_chain']
                md += """
## 攻击链路分析

### 分析摘要

```
{summary}
```

**总体风险评分:** {risk_score:.2f}

### 高风险攻击路径

{paths}

""".format(
                    summary=attack_chain['summary'],
                    risk_score=attack_chain['risk_score'],
                    paths='\n'.join([f"- {i+1}. {path.description} (风险: {path.risk_score:.2f})" for i, path in enumerate(attack_chain['paths'][:5])])
                )

        return md

    def _generate_finding_markdown(self, finding) -> str:
        """生成单个发现的 Markdown"""
        severity = finding.severity.value
        
        # 构建 POC 部分
        poc_md = ""
        if hasattr(finding, 'poc') and finding.poc:
            poc_md = f"""
**漏洞利用 (POC)**: 
```
{finding.poc}
```
"""
        
        # 构建修复建议部分
        fix_md = ""
        if hasattr(finding, 'fix_suggestion') and finding.fix_suggestion:
            fix_md = f"""
**修复建议**: {finding.fix_suggestion}
"""
        
        # 构建代码片段部分
        code_md = ""
        if hasattr(finding, 'code_snippet') and finding.code_snippet:
            code_md = f"""
```
{finding.code_snippet}
```
"""
        
        return f"""
### {finding.rule_name} ({finding.rule_id})

- **严重级别**: {severity}
- **位置**: {finding.location}
- **描述**: {finding.message}
- **置信度**: {finding.confidence}
{code_md}
{poc_md}
{fix_md}

"""

    def _generate_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成摘要"""
        total_findings = sum(len(r.findings) for r in results)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for result in results:
            for finding in result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_scans": len(results),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
        }


class SARIFReportGenerator(BaseReportGenerator):
    """SARIF 报告生成器"""

    @property
    def format(self) -> str:
        return "sarif"

    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成 SARIF 报告"""
        sarif_content = self._generate_sarif(results)

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif_content, f, indent=2, ensure_ascii=False)

        return str(output_file)

    def _generate_sarif(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成 SARIF 内容"""
        runs = []

        for result in results:
            run = {
                "tool": {
                    "driver": {
                        "name": "HOS-LS",
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": []
            }

            # 添加结果
            for finding in result.findings:
                run["results"].append({
                    "ruleId": finding.rule_id,
                    "message": {
                        "text": finding.message
                    },
                    "severity": finding.severity.value,
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.location.file
                            },
                            "region": {
                                "startLine": finding.location.line if finding.location.line > 0 else 1
                            }
                        }
                    }]
                })

            runs.append(run)

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs
        }


class ReportGenerator:
    """报告生成器工厂"""

    _generators: Dict[str, type] = {
        "json": JSONReportGenerator,
        "html": HTMLReportGenerator,
        "markdown": MarkdownReportGenerator,
        "sarif": SARIFReportGenerator,
    }

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()

    def generate(
        self,
        results: List[ScanResult],
        output_path: str,
        format: Optional[str] = None,
    ) -> str:
        """生成报告

        Args:
            results: 扫描结果列表
            output_path: 输出路径
            format: 报告格式，如果为 None 则使用配置中的格式

        Returns:
            报告文件路径
        """
        fmt = format or self.config.report.format

        generator_class = self._generators.get(fmt)
        if not generator_class:
            raise ValueError(f"不支持的报告格式: {fmt}")

        generator = generator_class(self.config)
        return generator.generate(results, output_path)

    def register_generator(
        self,
        format: str,
        generator_class: type,
    ) -> None:
        """注册报告生成器

        Args:
            format: 报告格式
            generator_class: 生成器类
        """
        self._generators[format] = generator_class

    def list_formats(self) -> List[str]:
        """列出支持的格式"""
        return list(self._generators.keys())

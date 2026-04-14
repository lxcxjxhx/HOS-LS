"""报告模板引擎模块

使用 Jinja2 提供灵活的报告模板定制功能。
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, FileSystemLoader, Template, select_autoescape

from src.core.engine import ScanResult
from src.core.config import Config, get_config


class TemplateEngine:
    """报告模板引擎
    
    支持自定义模板和主题。
    """
    
    def __init__(
        self,
        template_dir: Optional[Union[str, Path]] = None,
        config: Optional[Config] = None,
    ) -> None:
        self.config = config or get_config()
        
        self.template_dir = Path(template_dir) if template_dir else self._get_default_template_dir()
        
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        
        self._register_filters()
        self._register_globals()
    
    def _get_default_template_dir(self) -> Path:
        """获取默认模板目录"""
        return Path(__file__).parent / "templates" / "builtin"
    
    def _register_filters(self) -> None:
        """注册自定义过滤器"""
        self.env.filters["severity_color"] = self._severity_color
        self.env.filters["severity_icon"] = self._severity_icon
        self.env.filters["truncate_code"] = self._truncate_code
        self.env.filters["highlight_code"] = self._highlight_code
    
    def _register_globals(self) -> None:
        """注册全局变量"""
        self.env.globals["theme"] = self._get_theme()
    
    def _severity_color(self, severity: str) -> str:
        """获取严重级别对应的颜色"""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }
        return colors.get(severity.lower(), "#6c757d")
    
    def _severity_icon(self, severity: str) -> str:
        """获取严重级别对应的图标"""
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }
        return icons.get(severity.lower(), "⚪")
    
    def _truncate_code(self, code: str, max_length: int = 200) -> str:
        """截断代码片段"""
        if len(code) <= max_length:
            return code
        return code[:max_length] + "..."
    
    def _highlight_code(self, code: str) -> str:
        """简单代码高亮"""
        keywords = [
            "def", "class", "import", "from", "return", "if", "else", "elif",
            "for", "while", "try", "except", "with", "as", "async", "await",
        ]
        highlighted = code
        for keyword in keywords:
            highlighted = highlighted.replace(
                f" {keyword} ",
                f' <span class="keyword">{keyword}</span> '
            )
        return highlighted
    
    def _get_theme(self) -> Dict[str, Any]:
        """获取主题配置"""
        return {
            "font_family": "'Segoe UI', Arial, sans-serif",
            "primary_color": "#2563eb",
            "background_color": "#f8fafc",
            "text_color": "#1e293b",
            "border_color": "#e2e8f0",
        }
    
    def render(
        self,
        template_name: str,
        results: List[ScanResult],
        **kwargs: Any,
    ) -> str:
        """渲染报告模板
        
        Args:
            template_name: 模板名称
            results: 扫描结果列表
            **kwargs: 额外参数
            
        Returns:
            渲染后的报告内容
        """
        template = self.env.get_template(template_name)
        
        context = {
            "results": results,
            "summary": self._generate_summary(results),
            "config": self.config,
            **kwargs,
        }
        
        return template.render(**context)
    
    def render_string(
        self,
        template_string: str,
        results: List[ScanResult],
        **kwargs: Any,
    ) -> str:
        """从字符串渲染模板
        
        Args:
            template_string: 模板字符串
            results: 扫描结果列表
            **kwargs: 额外参数
            
        Returns:
            渲染后的报告内容
        """
        template = self.env.from_string(template_string)
        
        context = {
            "results": results,
            "summary": self._generate_summary(results),
            "config": self.config,
            **kwargs,
        }
        
        return template.render(**context)
    
    def _generate_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成扫描摘要"""
        total_findings = sum(len(r.findings) for r in results)
        
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for result in results:
            for finding in result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_scans": len(results),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "files_with_findings": sum(1 for r in results if r.findings),
        }
    
    def list_templates(self) -> List[str]:
        """列出可用模板"""
        return self.env.list_templates()
    
    def add_template_path(self, path: Union[str, Path]) -> None:
        """添加模板搜索路径
        
        Args:
            path: 模板目录路径
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Template directory not found: {path}")
        
        current_loader = self.env.loader
        if isinstance(current_loader, FileSystemLoader):
            current_loader.searchpath.append(str(path))
    
    def get_template(self, name: str) -> Template:
        """获取模板对象
        
        Args:
            name: 模板名称
            
        Returns:
            模板对象
        """
        return self.env.get_template(name)

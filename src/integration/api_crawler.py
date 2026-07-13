"""API 爬虫模块

智能 API 端点发现。
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class APIEndpoint:
    """API 端点"""
    
    path: str
    method: str
    file_path: str
    line: int
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    auth_required: bool = False
    description: str = ""


class APICrawler:
    """API 爬虫
    
    从代码中发现 API 端点。
    """
    
    # 常见框架的路由模式
    ROUTE_PATTERNS = {
        "flask": [
            (r'@app\.route\s*\(\s*["\']([^"\']+)["\'].*?\)', ["GET", "POST"]),
            (r'@app\.get\s*\(\s*["\']([^"\']+)["\'].*?\)', ["GET"]),
            (r'@app\.post\s*\(\s*["\']([^"\']+)["\'].*?\)', ["POST"]),
            (r'@app\.put\s*\(\s*["\']([^"\']+)["\'].*?\)', ["PUT"]),
            (r'@app\.delete\s*\(\s*["\']([^"\']+)["\'].*?\)', ["DELETE"]),
        ],
        "fastapi": [
            (r'@app\.get\s*\(\s*["\']([^"\']+)["\'].*?\)', ["GET"]),
            (r'@app\.post\s*\(\s*["\']([^"\']+)["\'].*?\)', ["POST"]),
            (r'@app\.put\s*\(\s*["\']([^"\']+)["\'].*?\)', ["PUT"]),
            (r'@app\.delete\s*\(\s*["\']([^"\']+)["\'].*?\)', ["DELETE"]),
            (r'@app\.patch\s*\(\s*["\']([^"\']+)["\'].*?\)', ["PATCH"]),
        ],
        "django": [
            (r'path\s*\(\s*["\']([^"\']+)["\']', []),
            (r'url\s*\(\s*["\']([^"\']+)["\']', []),
        ],
        "express": [
            (r'app\.get\s*\(\s*["\']([^"\']+)["\']', ["GET"]),
            (r'app\.post\s*\(\s*["\']([^"\']+)["\']', ["POST"]),
            (r'app\.put\s*\(\s*["\']([^"\']+)["\']', ["PUT"]),
            (r'app\.delete\s*\(\s*["\']([^"\']+)["\']', ["DELETE"]),
            (r'router\.get\s*\(\s*["\']([^"\']+)["\']', ["GET"]),
            (r'router\.post\s*\(\s*["\']([^"\']+)["\']', ["POST"]),
        ],
    }
    
    def __init__(self) -> None:
        self.endpoints: List[APIEndpoint] = []
    
    def crawl_file(
        self,
        file_path: str,
        content: str,
        language: str = "python",
    ) -> List[APIEndpoint]:
        """爬取文件中的 API 端点
        
        Args:
            file_path: 文件路径
            content: 文件内容
            language: 语言
            
        Returns:
            发现的 API 端点列表
        """
        endpoints = []
        lines = content.split("\n")
        
        if language == "python":
            endpoints.extend(self._crawl_flask(file_path, lines))
            endpoints.extend(self._crawl_fastapi(file_path, lines))
            endpoints.extend(self._crawl_django(file_path, lines))
        elif language in ["javascript", "typescript"]:
            endpoints.extend(self._crawl_express(file_path, lines))
        
        self.endpoints.extend(endpoints)
        return endpoints
    
    def _crawl_flask(
        self, file_path: str, lines: List[str]
    ) -> List[APIEndpoint]:
        """爬取 Flask 路由"""
        endpoints = []
        
        for i, line in enumerate(lines):
            for pattern, methods in self.ROUTE_PATTERNS["flask"]:
                match = re.search(pattern, line)
                if match:
                    path = match.group(1)
                    # 提取方法
                    if "methods=" in line:
                        methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", line)
                        if methods_match:
                            methods_str = methods_match.group(1)
                            methods = [
                                m.strip().strip("\"'")
                                for m in methods_str.split(",")
                            ]
                    
                    for method in methods:
                        endpoints.append(
                            APIEndpoint(
                                path=path,
                                method=method,
                                file_path=file_path,
                                line=i + 1,
                            )
                        )
        
        return endpoints
    
    def _crawl_fastapi(
        self, file_path: str, lines: List[str]
    ) -> List[APIEndpoint]:
        """爬取 FastAPI 路由"""
        endpoints = []
        
        for i, line in enumerate(lines):
            for pattern, methods in self.ROUTE_PATTERNS["fastapi"]:
                match = re.search(pattern, line)
                if match:
                    path = match.group(1)
                    for method in methods:
                        endpoints.append(
                            APIEndpoint(
                                path=path,
                                method=method,
                                file_path=file_path,
                                line=i + 1,
                            )
                        )
        
        return endpoints
    
    def _crawl_django(
        self, file_path: str, lines: List[str]
    ) -> List[APIEndpoint]:
        """爬取 Django 路由"""
        endpoints = []
        
        for i, line in enumerate(lines):
            for pattern, _ in self.ROUTE_PATTERNS["django"]:
                match = re.search(pattern, line)
                if match:
                    path = match.group(1)
                    endpoints.append(
                        APIEndpoint(
                            path=path,
                            method="GET",  # Django 默认 GET
                            file_path=file_path,
                            line=i + 1,
                        )
                    )
        
        return endpoints
    
    def _crawl_express(
        self, file_path: str, lines: List[str]
    ) -> List[APIEndpoint]:
        """爬取 Express 路由"""
        endpoints = []
        
        for i, line in enumerate(lines):
            for pattern, methods in self.ROUTE_PATTERNS["express"]:
                match = re.search(pattern, line)
                if match:
                    path = match.group(1)
                    for method in methods:
                        endpoints.append(
                            APIEndpoint(
                                path=path,
                                method=method,
                                file_path=file_path,
                                line=i + 1,
                            )
                        )
        
        return endpoints
    
    def crawl_directory(
        self,
        directory: str,
        extensions: Optional[List[str]] = None,
    ) -> List[APIEndpoint]:
        """爬取目录中的所有文件
        
        Args:
            directory: 目录路径
            extensions: 文件扩展名列表
            
        Returns:
            发现的 API 端点列表
        """
        if extensions is None:
            extensions = [".py", ".js", ".ts"]
        
        dir_path = Path(directory)
        endpoints = []
        
        for ext in extensions:
            for file_path in dir_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text(encoding="utf-8")
                    language = "python" if ext == ".py" else "javascript"
                    file_endpoints = self.crawl_file(
                        str(file_path), content, language
                    )
                    endpoints.extend(file_endpoints)
                except Exception:
                    continue
        
        self.endpoints.extend(endpoints)
        return endpoints
    
    def analyze_security(
        self, endpoints: Optional[List[APIEndpoint]] = None
    ) -> Dict[str, Any]:
        """分析 API 安全性
        
        Args:
            endpoints: 端点列表，如果为 None 则使用已发现的端点
            
        Returns:
            安全分析结果
        """
        if endpoints is None:
            endpoints = self.endpoints
        
        analysis = {
            "total_endpoints": len(endpoints),
            "by_method": {},
            "potential_issues": [],
            "recommendations": [],
        }
        
        for endpoint in endpoints:
            # 按方法统计
            method = endpoint.method
            analysis["by_method"][method] = analysis["by_method"].get(method, 0) + 1
            
            # 检查潜在问题
            if "<" in endpoint.path and ">" in endpoint.path:
                analysis["potential_issues"].append({
                    "endpoint": endpoint.path,
                    "issue": "路径参数可能存在注入风险",
                    "severity": "medium",
                })
            
            if not endpoint.auth_required:
                analysis["potential_issues"].append({
                    "endpoint": endpoint.path,
                    "issue": "未标记认证要求",
                    "severity": "low",
                })
        
        # 生成建议
        if analysis["potential_issues"]:
            analysis["recommendations"].append(
                "建议对所有 API 端点进行认证检查"
            )
            analysis["recommendations"].append(
                "建议对路径参数进行严格验证"
            )
        
        return analysis
    
    def get_endpoints_by_method(self, method: str) -> List[APIEndpoint]:
        """按方法获取端点"""
        return [e for e in self.endpoints if e.method == method]
    
    def get_endpoints_by_path_pattern(self, pattern: str) -> List[APIEndpoint]:
        """按路径模式获取端点"""
        import fnmatch
        return [
            e for e in self.endpoints
            if fnmatch.fnmatch(e.path, pattern)
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "endpoints": [
                {
                    "path": e.path,
                    "method": e.method,
                    "file_path": e.file_path,
                    "line": e.line,
                    "auth_required": e.auth_required,
                }
                for e in self.endpoints
            ],
            "total": len(self.endpoints),
        }

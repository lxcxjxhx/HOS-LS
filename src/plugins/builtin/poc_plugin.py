"""POC生成插件

为纯AI模式提供POC生成功能
"""

from pathlib import Path
from typing import Dict, Any, List

from src.plugins.base import ScanPlugin, PluginMetadata, PluginPriority
from src.ai.pure_ai.poc_generator import POCGenerator


class POCPlugin(ScanPlugin):
    """POC生成插件
    
    为确认的漏洞生成可运行的POC
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        metadata = PluginMetadata(
            name="POCGenerator",
            version="1.0.0",
            description="为确认的漏洞生成可运行的POC",
            author="HOS-LS Team",
            priority=PluginPriority.NORMAL,
            enabled=False,  # 默认禁用
            config_schema={
                "enabled": {
                    "type": "boolean",
                    "default": False,
                    "description": "是否启用POC生成"
                },
                "output_dir": {
                    "type": "string",
                    "default": "./generated_pocs",
                    "description": "POC输出目录"
                },
                "severity": {
                    "type": "string",
                    "default": "high",
                    "description": "POC生成的严重级别过滤"
                },
                "max_pocs": {
                    "type": "integer",
                    "default": 10,
                    "description": "最大POC生成数量"
                }
            }
        )
        super().__init__(metadata, config)
        self.poc_generator = None
        self.client = None
    
    def set_client(self, client):
        """设置AI客户端
        
        Args:
            client: AI客户端
        """
        self.client = client
        if client:
            self.poc_generator = POCGenerator(client)
    
    async def scan(self, file_path: Path, content: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """扫描文件并生成POC
        
        Args:
            file_path: 文件路径
            content: 文件内容
            context: 扫描上下文
            
        Returns:
            发现的安全问题列表
        """
        # 此插件不进行实际扫描，只在post_scan阶段生成POC
        return []
    
    async def post_scan(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """扫描后处理
        
        Args:
            results: 扫描结果
            
        Returns:
            处理后的结果
        """
        if not self.is_enabled() or not self.poc_generator:
            return results
        
        # 从结果中提取漏洞发现
        findings = results.get('findings', [])
        if not findings:
            return results
        
        # 收集文件内容
        file_contents = {}
        for finding in findings:
            location = finding.get('location', {})
            file_path = location.get('file')
            if file_path and file_path not in file_contents:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_contents[file_path] = f.read()
                except Exception:
                    pass
        
        # 生成POC
        if file_contents:
            poc_results = await self.poc_generator.generate_all(
                findings,
                file_contents,
                self.config.get('output_dir', './generated_pocs'),
                self.config.get('severity', 'high'),
                self.config.get('max_pocs', 10)
            )
            
            # 将POC信息添加到结果中
            results['poc_results'] = poc_results
        
        return results

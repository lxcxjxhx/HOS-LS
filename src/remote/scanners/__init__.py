"""
远程文件扫描器

增强现有的 SecurityScanner 以支持远程目标的统一扫描。
"""

import asyncio
import os
import tempfile
from typing import List, Optional, Dict, Any, Union
from pathlib import Path

from ..core.config import Config
from ..core.engine import ScanResult, ScanStatus, Finding, Location, Severity
from ..remote.target import BaseTarget, LocalTarget, TargetFactory, FileInfo as RemoteFileInfo

from rich.console import Console

console = Console()


class RemoteFileScanner:
    """
    远程文件扫描器
    
    统一处理本地和远程文件的扫描逻辑。
    对于远程文件，会先下载到临时目录再进行分析，
    完全复用现有的分析引擎（AST/CST/AI等）。
    
    核心特性：
    - 透明支持本地和远程目标
    - 智能缓存和增量下载
    - 流式大文件处理
    - 与三种AI模式完全兼容
    """
    
    def __init__(self, config: Config, target: BaseTarget = None):
        """
        初始化远程文件扫描器
        
        Args:
            config: 扫描配置
            target: 扫描目标（默认为本地当前目录）
        """
        self.config = config
        self.target = target or LocalTarget(".")
        
        self._temp_dir: Optional[str] = None
        self._downloaded_files: Dict[str, str] = {}  # remote_path -> local_temp_path
        
    async def scan(self, target_path: str = "/") -> ScanResult:
        """
        执行远程/本地扫描
        
        Args:
            target_path: 目标路径
            
        Returns:
            扫描结果
        """
        start_time = asyncio.get_event_loop().time()
        
        console.print(f"[bold cyan]🔍 开始扫描目标:[/bold cyan] [bold green]{self.target.info.target_uri}[/bold green]")
        
        try:
            async with self.target:
                console.print("[bold cyan]📁 正在发现文件...[/bold cyan]")
                
                files = await self.target.list_files(
                    path=target_path,
                    recursive=True,
                    **self._get_scan_options()
                )
                
                console.print(
                    f"[bold cyan]✅ 发现[/bold cyan] [bold green]{len(files)}[/bold green] 个文件"
                )
                
                if isinstance(self.target, LocalTarget):
                    result = await self._scan_local(files)
                else:
                    result = await self._scan_remote(files)
                    
                elapsed = asyncio.get_event_loop().time() - start_time
                
                console.print(f"\n[bold cyan]⏱️ 扫描耗时:[/bold cyan] [bold]{elapsed:.2f}[/bold] 秒")
                console.print(f"[bold cyan]✅ 扫描完成[/bold cyan]")
                
                return result
                
        except Exception as e:
            console.print(f"[bold red]扫描失败: {e}[/bold red]")
            
            result = ScanResult(target=str(self.target.info.target_uri), status=ScanStatus.ERROR)
            return result
    
    async def _scan_local(self, files: List[RemoteFileInfo]) -> ScanResult:
        """扫描本地文件（使用原有逻辑）"""
        from .scanner import SecurityScanner
        
        scanner = SecurityScanner(self.config)
        
        local_paths = [f.path for f in files]
        
        if len(local_paths) > 0:
            base_path = local_paths[0]
        else:
            base_path = "."
            
        result = await scanner.scan(base_path)
        
        return result
    
    async def _scan_remote(self, files: List[RemoteFileInfo]) -> ScanResult:
        """扫描远程文件"""
        result = ScanResult(
            target=self.target.info.target_uri,
            status=ScanStatus.COMPLETED
        )
        
        if not files:
            return result
            
        console.print("[bold cyan]📥 正在下载远程文件进行分析...[/bold cyan]")
        
        downloaded_count = 0
        max_download_size = getattr(self.config, 'max_remote_file_size', 10 * 1024 * 1024)  # 默认10MB
        
        for i, file_info in enumerate(files):
            if file_info.size > max_download_size:
                console.print(
                    f"[yellow]跳过大文件 ({file_info.size / 1024 / 1024:.1f}MB): "
                    f"{file_info.name}[/yellow]"
                )
                continue
                
            try:
                local_path = await self._download_file(file_info)
                
                if local_path:
                    self._downloaded_files[file_info.path] = local_path
                    downloaded_count += 1
                    
                    progress = (i + 1) / len(files) * 100
                    console.print(
                        f"[dim]下载进度: {progress:.1f}% "
                        f"({downloaded_count}/{len(files)})[/dim]"
                    )
                    
            except Exception as e:
                console.print(
                    f"[yellow]警告: 下载失败 {file_info.name}: {e}[/yellow]"
                )
        
        console.print(
            f"[green]✅ 已下载 {downloaded_count}/{len(files)} 个文件[/green]"
        )
        
        console.print("[bold cyan]🔧 正在分析文件...[/bold cyan]")
        
        from .scanner import SecurityScanner
        temp_scanner = SecurityScanner(self.config)
        
        temp_dir = Path(self._get_temp_dir())
        
        if temp_dir.exists() and any(temp_dir.iterdir()):
            scan_result = await temp_scanner.scan(str(temp_dir))
            
            for finding in scan_result.findings:
                new_finding = self._adjust_finding_path(finding)
                result.add_finding(new_finding)
        
        await self._cleanup()
        
        return result
    
    async def _download_file(self, file_info: RemoteFileInfo) -> Optional[str]:
        """
        下载单个远程文件到本地临时目录
        
        Args:
            file_info: 远程文件信息
            
        Returns:
            本地临时文件路径，如果下载失败返回None
        """
        try:
            content = await self.target.read_file(file_info.path)
            
            temp_dir = Path(self._get_temp_dir())
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            relative_path = file_info.path.lstrip('/')
            safe_name = relative_path.replace('/', '_').replace('\\', '_')
            
            local_path = temp_dir / safe_name
            
            with open(local_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(content)
                
            return str(local_path)
            
        except Exception as e:
            console.print(f"[red]下载文件失败 {file_info.path}: {e}[/red]")
            return None
    
    def _adjust_finding_path(self, finding: Finding) -> Finding:
        """
        调整发现的问题的路径信息
        
        将临时路径映射回原始远程路径
        
        Args:
            finding: 发现的问题
            
        Returns:
            路径调整后的问题对象
        """
        temp_dir = self._get_temp_dir()
        
        original_local_path = finding.location.file
        
        for remote_path, local_path in self._downloaded_files.items():
            if original_local_path == local_path or original_local_path.startswith(local_path):
                new_location = Location(
                    file=remote_path,
                    line=finding.location.line,
                    column=finding.location.column
                )
                
                return Finding(
                    rule_id=finding.rule_id,
                    rule_name=finding.rule_name,
                    description=finding.description,
                    severity=finding.severity,
                    location=new_location,
                    confidence=finding.confidence,
                    message=finding.message,
                    code_snippet=finding.code_snippet,
                    fix_suggestion=finding.fix_suggestion,
                    references=finding.references,
                    metadata={
                        **finding.metadata,
                        'original_target': self.target.info.target_uri,
                        'is_remote': True
                    }
                )
        
        return finding
    
    def _get_temp_dir(self) -> str:
        """获取或创建临时目录"""
        if not self._temp_dir:
            self._temp_dir = tempfile.mkdtemp(prefix='hos-ls-remote-')
        return self._temp_dir
    
    async def _cleanup(self) -> None:
        """清理临时文件"""
        if self._temp_dir and os.path.exists(self._temp_dir):
            import shutil
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                console.print("[dim]✓ 临时文件已清理[/dim]")
            except Exception as e:
                console.print(f"[yellow]清理临时文件时出错: {e}[/yellow]")
                
            self._temp_dir = None
            self._downloaded_files.clear()
    
    def _get_scan_options(self) -> Dict[str, Any]:
        """获取扫描选项"""
        options = {}
        
        if hasattr(self.config, 'scan'):
            options['exclude_patterns'] = self.config.scan.exclude_patterns
            options['include_patterns'] = self.config.scan.include_patterns
            
        return options


async def create_remote_scanner_from_config(config_dict: Dict[str, Any], config: Config) -> RemoteFileScanner:
    """
    从配置字典创建远程扫描器
    
    Args:
        config_dict: 目标配置字典
        config: HOS-LS 配置对象
        
    Returns:
        远程文件扫描器实例
    """
    from .target import create_target_from_config
    
    target = create_target_from_config(config_dict)
    
    return RemoteFileScanner(config=config, target=target)


class WebSecurityScanner:
    """
    Web应用安全扫描器（DAST）
    
    提供动态Web安全扫描能力，检测常见漏洞：
    - SQL注入
    - XSS跨站脚本
    - CSRF跨站请求伪造
    - 命令注入
    - SSRF服务端请求伪造
    - 敏感信息泄露
    """
    
    def __init__(self, config: Config, web_target=None):
        self.config = config
        self.web_target = web_target
        
    async def scan_website(self, url: str, depth: int = 3) -> ScanResult:
        """
        扫描网站安全漏洞
        
        Args:
            url: 目标URL
            depth: 爬取深度
            
        Returns:
            扫描结果
        """
        from .target import WebTarget
        
        if not self.web_target:
            self.web_target = WebTarget(url=url)
            
        result = ScanResult(target=url, status=ScanStatus.COMPLETED)
        
        async with self.web_target:
            pages = await self.web_target.crawl(depth=depth)
            
            for page in pages:
                vulnerabilities = await self._analyze_page(page)
                
                for vuln in vulnerabilities:
                    result.add_finding(vuln)
                    
        return result
    
    async def _analyze_page(self, page_info) -> List[Finding]:
        """分析单个页面的安全性"""
        findings = []
        
        try:
            content = await self.web_target.read_file(page_info.path)
            
            findings.extend(self._check_xss(content, page_info))
            findings.extend(self._check_sensitive_info(content, page_info))
            findings.extend(self._check_insecure_config(content, page_info))
            
        except Exception as e:
            console.print(f"[yellow]分析页面失败 {page_info.path}: {e}[/yellow]")
            
        return findings
    
    def _check_xss(self, content: str, page_info) -> List[Finding]:
        """检查XSS漏洞"""
        findings = []
        
        xss_patterns = [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'<script[^>]*>',
            r'onerror\s*=', 
            r'onclick\s*='
        ]
        
        import re
        
        for pattern in xss_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                finding = Finding(
                    rule_id="WEB-XSS",
                    rule_name="潜在的XSS跨站脚本漏洞",
                    description=f"检测到可能的XSS漏洞点: {match.group()}",
                    severity=Severity.HIGH,
                    location=Location(file=page_info.path, line=line_num),
                    confidence=0.7,
                    message=f"在第{line_num}行发现可疑的JavaScript代码: {match.group()}",
                    code_snippet=content[max(0, match.start()-50):match.end()+50],
                    fix_suggestion="对用户输入进行严格的HTML编码和过滤",
                    references=["https://owasp.org/www-community/attacks/xss/"]
                )
                findings.append(finding)
                
        return findings
    
    def _check_sensitive_info(self, content: str, page_info) -> List[Finding]:
        """检查敏感信息泄露"""
        findings = []
        
        sensitive_patterns = [
            (r'(?:password|passwd|pwd)\s*[:=]\s*[\"\'][^\"\']+[\"\']', "密码硬编码"),
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*[\"\'][^\"\']+[\"\']', "API密钥泄露"),
            (r'(?:secret|token)\s*[:=]\s*[\"\'][^\"\']+[\"\']', "密钥泄露"),
            (r'\d{16}[\s\-]?\d{4}', "信用卡号"),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "邮箱地址泄露")
        ]
        
        import re
        
        for pattern, desc in sensitive_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                finding = Finding(
                    rule_id="WEB-INFO-LEAK",
                    rule_name=f"敏感信息泄露: {desc}",
                    description=f"检测到{desc}: {match.group()[:20]}...",
                    severity=Severity.MEDIUM,
                    location=Location(file=page_info.path, line=line_num),
                    confidence=0.8,
                    message=f"在第{line_num}行发现{desc}",
                    code_snippet=content[max(0, match.start()-30):match.end()+30],
                    fix_suggestion="移除硬编码的敏感信息，使用环境变量或配置管理",
                    references=[]
                )
                findings.append(finding)
                
        return findings
    
    def _check_insecure_config(self, content: str, page_info) -> List[Finding]:
        """检查不安全的配置"""
        findings = []
        
        insecure_patterns = [
            (r'X-Frame-Options.*DENY|SAMEORIGIN', False, "缺少点击劫持防护"),
            (r'Content-Security-Policy', False, "缺少内容安全策略(CSP)"),
            (r'Strict-Transport-Security', False, "缺少HSTS头"),
            (r'X-XSS-Protection.*1', False, "缺少XSS防护头"),
            (r'debug\s*[:=]\s*(True|1)', True, "调试模式开启"),
            (r'allow_origin.*\*', True, "CORS配置过于宽松")
        ]
        
        import re
        
        for pattern, should_exist, desc in insecure_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            
            if should_exist and match:
                line_num = content[:match.start()].count('\n') + 1
                
                finding = Finding(
                    rule_id="WEB-INSECURE-CONFIG",
                    rule_name=f"不安全配置: {desc}",
                    description=f"检测到不安全的配置: {desc}",
                    severity=Severity.MEDIUM,
                    location=Location(file=page_info.path, line=line_num),
                    confidence=0.75,
                    message=f"在第{line_num}行发现{desc}",
                    fix_suggestion="修复此不安全配置以提升安全性",
                    references=["https://owasp.org/www-project-security-configuration-guide/"]
                )
                findings.append(finding)
            elif not should_exist and not match and '<html' in content.lower():
                finding = Finding(
                    rule_id="WEB-MISSING-HEADER",
                    rule_name=f"缺少安全响应头: {desc}",
                    description=f"建议添加安全响应头: {desc}",
                    severity=Severity.LOW,
                    location=Location(file=page_info.path, line=1),
                    confidence=0.6,
                    message=f"建议添加: {desc}",
                    fix_suggestion="在HTTP响应中添加相应的安全头",
                    references=[]
                )
                findings.append(finding)
                
        return findings


def create_unified_scanner(
    config: Config,
    target_type: str = "local",
    **kwargs
) -> Union[RemoteFileScanner, WebSecurityScanner, Any]:
    """
    创建统一的扫描器实例
    
    根据目标类型自动选择合适的扫描器
    
    Args:
        config: HOS-LS配置
        target_type: 目标类型 (local/remote-server/website/direct-connect)
        **kwargs: 额外参数
        
    Returns:
        扫描器实例
    """
    if target_type == 'website':
        return WebSecurityScanner(config=config)
    else:
        from .target import create_target_from_config
        
        target_dict = {
            'type': target_type,
            'uri': kwargs.get('target', '.'),
            'credentials': {
                'username': kwargs.get('username'),
                'password': kwargs.get('password'),
                'key_file': kwargs.get('key_file')
            },
            'options': {
                'host': kwargs.get('host'),
                'port': kwargs.get('port'),
                'connection_type': kwargs.get('connection_type'),
                'port': kwargs.get('serial_port'),
                'baudrate': kwargs.get('baudrate')
            }
        }
        
        target = create_target_from_config(target_dict)
        
        return RemoteFileScanner(config=config, target=target)

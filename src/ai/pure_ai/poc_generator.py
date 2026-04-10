import asyncio
import json
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from rich.console import Console

from src.ai.models import VulnerabilityFinding, AIRequest
from src.ai.pure_ai.prompt_templates import PromptTemplates

console = Console()

class POCGenerator:
    """POC生成器
    
    为确认的漏洞生成可直接运行的POC脚本
    """
    
    def __init__(self, client, config: Optional[Any] = None):
        """初始化POC生成器
        
        Args:
            client: AI客户端
            config: 配置参数
        """
        self.client = client
        self.config = config
        self.prompt_templates = PromptTemplates()
        self.max_retries = getattr(config, 'max_retries', 3) if config else 3
        self.model = getattr(config, 'model', 'deepseek-reasoner') if config else 'deepseek-reasoner'
        self.language = getattr(config, 'language', 'cn') if config else 'cn'
    
    async def generate_poc(self, finding: VulnerabilityFinding, file_content: str) -> Dict[str, Any]:
        """生成单个漏洞的POC
        
        Args:
            finding: 漏洞发现
            file_content: 文件内容
            
        Returns:
            POC生成结果
        """
        try:
            # 检测目标语言
            file_path = finding.location.get('file', '')
            language = self._detect_language(file_path)
            if language == 'unknown':
                console.print(f"[yellow]⚠ 无法检测文件语言: {file_path}[/yellow]")
                return {}
            
            # 构建POC生成提示词
            prompt = self._build_poc_prompt(finding, file_content, language)
            
            # 生成POC
            response, token_usage = await self._generate_with_retry(prompt, "POC Generator")
            
            # 解析结果
            poc_code = self._extract_poc_code(response)
            
            if not poc_code:
                console.print(f"[yellow]⚠ POC生成失败: 无法提取代码[/yellow]")
                return {}
            
            return {
                'poc_code': poc_code,
                'language': language,
                'token_usage': token_usage
            }
        except Exception as e:
            console.print(f"[red]✗ POC生成失败: {e}[/red]")
            import traceback
            traceback.print_exc()
            return {}
    
    async def generate_all(self, findings: List[VulnerabilityFinding], file_contents: Dict[str, str], 
                         output_dir: str = './generated_pocs', 
                         severity_filter: str = 'high',
                         max_pocs: int = 10) -> List[Dict[str, Any]]:
        """批量生成POC

        Args:
            findings: 漏洞发现列表
            file_contents: 文件路径到内容的映射
            output_dir: 输出目录
            severity_filter: 严重级别过滤
            max_pocs: 最大生成数量
            
        Returns:
            POC生成结果列表
        """
        # 创建输出目录
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # 检查发现列表是否为空
        if not findings:
            console.print(f"[yellow]⚠ 没有发现漏洞，跳过POC生成[/yellow]")
            # 保存空的元数据文件
            metadata_path = Path(output_dir) / 'index.json'
            try:
                with open(metadata_path, 'w', encoding='utf-8') as f:
                    json.dump([], f, ensure_ascii=False, indent=2)
                console.print(f"[green]✓ 元数据保存成功: index.json[/green]")
            except Exception as e:
                console.print(f"[red]✗ 元数据保存失败: {e}[/red]")
            return []
        
        # 过滤漏洞
        filtered_findings = self._filter_findings(findings, severity_filter)
        
        # 检查过滤后的发现列表是否为空
        if not filtered_findings:
            console.print(f"[yellow]⚠ 没有符合条件的漏洞，跳过POC生成[/yellow]")
            # 保存空的元数据文件
            metadata_path = Path(output_dir) / 'index.json'
            try:
                with open(metadata_path, 'w', encoding='utf-8') as f:
                    json.dump([], f, ensure_ascii=False, indent=2)
                console.print(f"[green]✓ 元数据保存成功: index.json[/green]")
            except Exception as e:
                console.print(f"[red]✗ 元数据保存失败: {e}[/red]")
            return []
        
        if len(filtered_findings) > max_pocs:
            filtered_findings = filtered_findings[:max_pocs]
            console.print(f"[yellow]⚠ 限制POC生成数量为: {max_pocs}[/yellow]")
        
        results = []
        metadata = []
        
        for i, finding in enumerate(filtered_findings):
            console.print(f"[cyan]生成POC {i+1}/{len(filtered_findings)}: {finding.rule_name}[/cyan]")
            
            file_path = finding.location.get('file', '')
            file_content = file_contents.get(file_path, '')
            
            if not file_content:
                console.print(f"[yellow]⚠ 缺少文件内容: {file_path}[/yellow]")
                continue
            
            # 生成POC
            poc_result = await self.generate_poc(finding, file_content)
            if not poc_result:
                continue
            
            # 生成文件名
            file_name = self._generate_poc_filename(finding, poc_result['language'])
            file_path = Path(output_dir) / file_name
            
            # 保存POC
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(poc_result['poc_code'])
                console.print(f"[green]✓ POC保存成功: {file_name}[/green]")
            except Exception as e:
                console.print(f"[red]✗ POC保存失败: {e}[/red]")
                continue
            
            # 构建结果
            result = {
                'finding': finding,
                'poc_file': str(file_path),
                'poc_snippet': poc_result['poc_code'][:500] + '...' if len(poc_result['poc_code']) > 500 else poc_result['poc_code'],
                'language': poc_result['language']
            }
            results.append(result)
            
            # 构建元数据
            metadata.append({
                'vulnerability': finding.rule_name,
                'severity': finding.severity,
                'location': finding.location,
                'poc_file': file_name,
                'description': finding.description[:200] + '...' if len(finding.description) > 200 else finding.description
            })
        
        # 保存元数据
        metadata_path = Path(output_dir) / 'index.json'
        try:
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
            console.print(f"[green]✓ 元数据保存成功: index.json[/green]")
        except Exception as e:
            console.print(f"[red]✗ 元数据保存失败: {e}[/red]")
        
        return results
    
    def _build_poc_prompt(self, finding: VulnerabilityFinding, file_content: str, language: str) -> str:
        """构建POC生成提示词
        
        Args:
            finding: 漏洞发现
            file_content: 文件内容
            language: 目标语言
            
        Returns:
            提示词字符串
        """
        system_prompt = f"""
你是一个专业的安全研究员。现在有一个已确认的漏洞：

【漏洞信息】
- 漏洞类型：{finding.rule_name}
- 严重级别：{finding.severity}
- 位置：{finding.location.get('file', '')}:{finding.location.get('line', '')}
- 描述：{finding.description}

【相关代码片段】
{file_content[:2000]}

【生成要求】
请生成一个**完整、可直接运行的POC**（使用{language}语言），必须包含以下内容：

1. **详细注释**：
   - 漏洞描述和影响
   - 代码各部分的功能说明
   - 触发条件和环境要求

2. **触发命令**：
   - 如何运行该POC
   - 必要的参数和环境变量

3. **预期输出**：
   - 运行后应该看到的结果
   - 如何验证漏洞是否被成功触发

4. **安全警告**：
   - 明确标注"仅用于测试环境"
   - 警告不要在生产环境使用

5. **代码要求**：
   - 代码简洁、结构清晰
   - 100%可复现漏洞
   - 只输出POC代码，不要任何解释

【输出格式】
直接输出完整的POC代码，包含所有必要的导入和依赖。
"""
        
        return system_prompt
    
    def _extract_poc_code(self, response: str) -> str:
        """从响应中提取POC代码
        
        Args:
            response: AI响应
            
        Returns:
            提取的代码
        """
        # 清理响应
        cleaned_response = response.strip()
        
        # 尝试提取代码块
        # 匹配 ```language ... ``` 格式
        code_match = re.search(r'```(?:\w+)?\s*([\s\S]*?)```', cleaned_response)
        if code_match:
            return code_match.group(1).strip()
        
        # 直接返回响应（如果看起来是代码）
        if cleaned_response:
            return cleaned_response
        
        return ""
    
    def _detect_language(self, file_path: str) -> str:
        """检测文件语言
        
        Args:
            file_path: 文件路径
            
        Returns:
            语言名称
        """
        ext = Path(file_path).suffix.lower()
        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".swift": "swift",
            ".kt": "kotlin",
            ".rs": "rust",
        }
        return language_map.get(ext, "unknown")
    
    def _generate_poc_filename(self, finding: VulnerabilityFinding, language: str) -> str:
        """生成POC文件名
        
        Args:
            finding: 漏洞发现
            language: 语言
            
        Returns:
            文件名
        """
        # 生成CVE风格的ID
        import time
        timestamp = int(time.time())
        cve_id = f"CVE-2025-{timestamp:05d}"
        
        # 提取函数名
        function_name = "unknown"
        location = finding.location.get('file', '')
        if location:
            # 尝试从位置信息中提取函数名
            match = re.search(r'function\s+(\w+)', finding.description)
            if match:
                function_name = match.group(1)
            else:
                # 使用文件名作为函数名
                function_name = Path(location).stem
        
        # 清理函数名
        function_name = re.sub(r'[^a-zA-Z0-9_]', '_', function_name)
        
        # 生成文件扩展名
        ext_map = {
            "python": ".py",
            "javascript": ".js",
            "typescript": ".ts",
            "java": ".java",
            "cpp": ".cpp",
            "c": ".c",
            "go": ".go",
            "ruby": ".rb",
            "php": ".php",
            "swift": ".swift",
            "kotlin": ".kt",
            "rust": ".rs",
        }
        ext = ext_map.get(language, ".txt")
        
        return f"{cve_id}_func_{function_name}{ext}"
    
    def _filter_findings(self, findings: List[VulnerabilityFinding], severity_filter: str) -> List[VulnerabilityFinding]:
        """过滤漏洞
        
        Args:
            findings: 漏洞发现列表
            severity_filter: 严重级别过滤
            
        Returns:
            过滤后的漏洞列表
        """
        severity_levels = {
            'critical': ['critical'],
            'high': ['critical', 'high'],
            'medium': ['critical', 'high', 'medium'],
            'low': ['critical', 'high', 'medium', 'low']
        }
        
        allowed_levels = severity_levels.get(severity_filter, ['critical', 'high'])
        
        # 过滤出确认的漏洞
        filtered = []
        for finding in findings:
            # 只处理已确认的漏洞
            if finding.severity in allowed_levels:
                filtered.append(finding)
        
        # 按严重级别排序
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        filtered.sort(key=lambda x: severity_order.get(x.severity, 999))
        
        return filtered
    
    async def _generate_with_retry(self, prompt: str, agent_name: str = "unknown", temperature: float = 0.0) -> tuple:
        """带重试的生成
        
        Args:
            prompt: 提示词
            agent_name: Agent名称
            temperature: 温度值
            
        Returns:
            (生成的响应, token使用信息)
        """
        for i in range(self.max_retries):
            try:
                # 创建AIRequest对象
                request = AIRequest(
                    prompt=prompt,
                    model=self.model,
                    temperature=temperature
                )
                
                # 调用客户端生成
                response = await self.client.generate(request)
                
                # 提取token使用信息
                token_usage = {
                    'prompt_tokens': 0,
                    'completion_tokens': 0,
                    'total_tokens': 0
                }
                if hasattr(response, 'usage') and response.usage:
                    token_usage['prompt_tokens'] = response.usage.get('prompt_tokens', 0)
                    token_usage['completion_tokens'] = response.usage.get('completion_tokens', 0)
                    token_usage['total_tokens'] = response.usage.get('total_tokens', 0)
                
                # 返回响应内容和token使用信息
                if hasattr(response, 'content'):
                    return response.content, token_usage
                else:
                    return str(response), token_usage
                    
            except Exception as e:
                console.print(f"[yellow]生成失败 (Agent: {agent_name}, 尝试 {i+1}/{self.max_retries}): {e}[/yellow]")
                if i == self.max_retries - 1:
                    raise
                await asyncio.sleep(1)
        
        return "", {}

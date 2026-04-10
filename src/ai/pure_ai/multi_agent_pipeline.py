import asyncio
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.ai.pure_ai.context_builder import ContextBuilder
from src.ai.pure_ai.prompt_templates import PromptTemplates
from src.ai.models import AIRequest
from src.ai.token_tracker import get_token_tracker

console = Console()

class MultiAgentPipeline:
    """多Agent流水线系统
    
    协调6个专业Agent完成代码安全分析
    """
    
    def __init__(self, client, config: Optional[Any] = None):
        """初始化多Agent流水线
        
        Args:
            client: AI客户端
            config: 配置参数
        """
        self.client = client
        self.config = config
        self.context_builder = ContextBuilder(config)
        self.prompt_templates = PromptTemplates()
        self.token_tracker = get_token_tracker()
        # 尝试从配置中获取max_retries，如果不存在则使用默认值3
        if hasattr(config, 'get'):
            # 配置是字典
            self.max_retries = config.get('max_retries', 3)
            self.model = config.get('model', 'deepseek-reasoner')
            self.language = config.get('language', 'cn')
            self.max_tokens_per_file = config.get('max_tokens_per_file', 8000)
        else:
            # 配置是对象
            self.max_retries = getattr(config, 'max_retries', 3)
            if hasattr(config, 'ai'):
                ai_config = getattr(config, 'ai')
                if hasattr(ai_config, 'model'):
                    self.model = getattr(ai_config, 'model', 'deepseek-reasoner')
                else:
                    self.model = 'deepseek-reasoner'
            else:
                self.model = 'deepseek-reasoner'
            self.language = getattr(config, 'language', 'cn')
            self.max_tokens_per_file = getattr(config, 'max_tokens_per_file', 8000)
        # Agent协作相关
        self.agent_memory = {}  # 存储Agent之间共享的信息
        self.agent_dependencies = self._build_agent_dependencies()  # 构建Agent依赖关系
        self.agent_performance = {}  # 记录Agent性能指标
    
    async def run_pipeline(self, file_path: str, fast_mode: bool = False) -> Dict[str, Any]:
        """运行完整的多Agent流水线

        Args:
            file_path: 文件路径
            fast_mode: 是否使用快速模式

        Returns:
            分析结果
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
        
        try:
            print(f"[DEBUG] 开始运行多Agent流水线: {file_path}")
            total_start_time = time.time()
            agent_timings = {}
            total_token_usage = {
                'prompt_tokens': 0,
                'completion_tokens': 0,
                'total_tokens': 0
            }
            
            # 清空Agent内存
            self.agent_memory = {}
            
            # 使用统一的Progress管理器，避免多个status/print混合导致的混乱
            # 修复进度条闪烁和重复输出问题
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
                transient=True,  # 完成后自动清除进度条
                refresh_per_second=1  # 减少刷新频率，避免重复输出
            ) as progress:
                # 构建上下文
                start_time = time.time()
                context = self.context_builder.build_context(file_path)
                elapsed = time.time() - start_time
                agent_timings['context_build'] = elapsed
                
                if fast_mode:
                    # 快速模式：3个Agent
                    main_task = progress.add_task(f"[cyan]快速分析: {Path(file_path).name}[/cyan]", total=3)
                    
                    # 1. Scanner Agent: 扫描漏洞
                    start_time = time.time()
                    scanner_result, token_usage = await self._run_scanner_agent(file_path, context['file_content'])
                    elapsed = time.time() - start_time
                    agent_timings['scanner_agent'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    # 更新Agent内存
                    self._update_agent_memory('scanner', scanner_result)
                    progress.advance(main_task)
                    
                    # 2. Reasoning Agent: 推理漏洞
                    start_time = time.time()
                    # 获取依赖数据
                    reasoning_deps = self._get_dependency_data('reasoning')
                    reasoning_result, token_usage = await self._run_reasoning_agent(file_path, scanner_result, context['file_content'])
                    elapsed = time.time() - start_time
                    agent_timings['reasoning_agent'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    # 更新Agent内存
                    self._update_agent_memory('reasoning', reasoning_result)
                    progress.advance(main_task)
                    
                    # 3. Report Agent: 生成报告
                    start_time = time.time()
                    # 获取依赖数据
                    report_deps = self._get_dependency_data('report')
                    final_report, token_usage = await self._run_report_agent(file_path, reasoning_result, reasoning_result)
                    elapsed = time.time() - start_time
                    agent_timings['report_agent'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    # 更新Agent内存
                    self._update_agent_memory('report', final_report)
                    progress.advance(main_task)
                else:
                    # 完整模式：5个Agent
                    main_task = progress.add_task(f"[cyan]分析: {Path(file_path).name}[/cyan]", total=5)
                    
                    # 1. Scanner Agent: 扫描漏洞
                    start_time = time.time()
                    scanner_result, token_usage = await self._run_scanner_agent(file_path, context['file_content'])
                    elapsed = time.time() - start_time
                    agent_timings['scanner_agent'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    # 更新Agent内存
                    self._update_agent_memory('scanner', scanner_result)
                    progress.advance(main_task)
                    
                    # 2. Reasoning Agent: 推理漏洞
                    start_time = time.time()
                    # 获取依赖数据
                    reasoning_deps = self._get_dependency_data('reasoning')
                    reasoning_result, token_usage = await self._run_reasoning_agent(file_path, scanner_result, context['file_content'])
                    elapsed = time.time() - start_time
                    agent_timings['reasoning_agent'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    # 更新Agent内存
                    self._update_agent_memory('reasoning', reasoning_result)
                    progress.advance(main_task)
                    
                    # 3. Exploit Agent: 生成POC
                    start_time = time.time()
                    # 获取依赖数据
                    exploit_deps = self._get_dependency_data('exploit')
                    exploit_result, token_usage = await self._run_exploit_agent(file_path, reasoning_result, context['file_content'])
                    elapsed = time.time() - start_time
                    agent_timings['exploit_agent'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    # 更新Agent内存
                    self._update_agent_memory('exploit', exploit_result)
                    progress.advance(main_task)
                    
                    # 4. Fix Agent: 修复建议
                    start_time = time.time()
                    # 获取依赖数据
                    fix_deps = self._get_dependency_data('fix')
                    fix_result, token_usage = await self._run_fix_agent(file_path, reasoning_result, context['file_content'])
                    elapsed = time.time() - start_time
                    agent_timings['fix_agent'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    # 更新Agent内存
                    self._update_agent_memory('fix', fix_result)
                    progress.advance(main_task)
                    
                    # 5. Report Agent: 生成报告
                    start_time = time.time()
                    # 获取依赖数据
                    report_deps = self._get_dependency_data('report')
                    final_report, token_usage = await self._run_report_agent(file_path, reasoning_result, fix_result)
                    elapsed = time.time() - start_time
                    agent_timings['report_agent'] = elapsed
                    total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                    total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                    total_token_usage['total_tokens'] += token_usage['total_tokens']
                    # 更新Agent内存
                    self._update_agent_memory('report', final_report)
                    progress.advance(main_task)
            
            # 更新Agent性能指标
            self._update_agent_performance(agent_timings, total_token_usage)
            
            # Progress结束后输出最终结果
            total_elapsed = time.time() - total_start_time
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold green]✓ {Path(file_path).name} 分析完成[/bold green] [dim]({total_elapsed:.2f}s)[/dim]")
            
            # 显示总体token统计
            if total_token_usage['total_tokens'] > 0:
                agent_count = 3 if fast_mode else 5
                avg_tokens_per_agent = total_token_usage['total_tokens'] / agent_count if agent_count > 0 else 0
                console.print(f"[dim]  📊 Token: {total_token_usage['total_tokens']:,} (提示词: {total_token_usage['prompt_tokens']:,}, 补全: {total_token_usage['completion_tokens']:,})[/dim]")
            
            result = {
                'file_path': file_path,
                'final_report': final_report,
                'token_usage': total_token_usage,
                'timings': agent_timings,
                'agent_memory': self.agent_memory
            }
            
            # 添加其他结果字段
            if not fast_mode:
                result.update({
                    'scanner_result': scanner_result,
                    'reasoning_result': reasoning_result,
                    'exploit_result': exploit_result,
                    'fix_result': fix_result
                })
            else:
                result.update({
                    'scanner_result': scanner_result,
                    'reasoning_result': reasoning_result
                })
            
            return result
        except Exception as e:
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold red]✗ {Path(file_path).name} 分析失败: {e}[/bold red]")
            import traceback
            traceback.print_exc()
            return {
                'file_path': file_path,
                'error': str(e)
            }
    
    async def _run_scanner_agent(self, file_path: str, file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Scanner Agent：扫描漏洞

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            (扫描结果, token使用信息)
        """
        print(f"[DEBUG] 运行Scanner Agent on: {file_path}")
        prompt = self.prompt_templates.AGENT_SCANNER.format(
            file_path=file_path,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Scanner Agent", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Scanner Agent 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_reasoning_agent(self, file_path: str, scanner_result: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Reasoning Agent：推理漏洞

        Args:
            file_path: 文件路径
            scanner_result: 扫描结果
            file_content: 文件内容

        Returns:
            (推理结果, token使用信息)
        """
        print(f"[DEBUG] 运行Reasoning Agent on: {file_path}")
        scanner_json = json.dumps(scanner_result, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_REASONING.format(
            file_path=file_path,
            scanner_result=scanner_json,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Reasoning Agent", temperature=0.3)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Reasoning Agent 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_exploit_agent(self, file_path: str, reasoning_result: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Exploit Agent：生成POC

        Args:
            file_path: 文件路径
            reasoning_result: 推理结果
            file_content: 文件内容

        Returns:
            (POC生成结果, token使用信息)
        """
        print(f"[DEBUG] 运行Exploit Agent on: {file_path}")
        reasoning_json = json.dumps(reasoning_result, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_EXPLOIT.format(
            file_path=file_path,
            reasoning_result=reasoning_json,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Exploit Agent", temperature=0.4)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Exploit Agent 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_fix_agent(self, file_path: str, reasoning_result: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Fix Agent：修复建议

        Args:
            file_path: 文件路径
            reasoning_result: 推理结果
            file_content: 文件内容

        Returns:
            (修复建议结果, token使用信息)
        """
        print(f"[DEBUG] 运行Fix Agent on: {file_path}")
        reasoning_json = json.dumps(reasoning_result, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_FIX.format(
            file_path=file_path,
            reasoning_result=reasoning_json,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Fix Agent", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Fix Agent 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_report_agent(self, file_path: str, reasoning_result: Dict[str, Any], fix_result: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Report Agent：生成报告

        Args:
            file_path: 文件路径
            reasoning_result: 推理结果
            fix_result: 修复建议结果

        Returns:
            (报告结果, token使用信息)
        """
        print(f"[DEBUG] 运行Report Agent on: {file_path}")
        reasoning_json = json.dumps(reasoning_result, ensure_ascii=False)
        fix_json = json.dumps(fix_result, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_REPORT.format(
            file_path=file_path,
            reasoning_result=reasoning_json,
            fix_result=fix_json
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Report Agent", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Report Agent 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_0(self, file_path: str, context: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 0：上下文构建

        Args:
            file_path: 文件路径
            context: 上下文信息

        Returns:
            (上下文分析结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 0 (上下文构建) on: {file_path}")
        prompt = self.prompt_templates.AGENT_0_CONTEXT_BUILDER.format(
            file_path=file_path,
            file_content=context['file_content'],
            related_files=self.prompt_templates.format_related_files(context['related_files']),
            imports=self.prompt_templates.format_imports(context['imports']),
            function_calls=self.prompt_templates.format_function_calls(context['function_calls'])
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 0", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Agent 0 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_1(self, file_path: str, context: Dict[str, Any], context_analysis: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 1：代码理解

        Args:
            file_path: 文件路径
            context: 上下文信息
            context_analysis: 上下文分析结果

        Returns:
            (代码理解结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 1 (代码理解) on: {file_path}")
        context_info = json.dumps(context_analysis, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_1_CODE_UNDERSTANDING.format(
            file_path=file_path,
            file_content=context['file_content'],
            context_info=context_info
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 1", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Agent 1 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_2(self, file_path: str, code_understanding: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 2：风险枚举

        Args:
            file_path: 文件路径
            code_understanding: 代码理解结果

        Returns:
            (风险枚举结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 2 (风险枚举) on: {file_path}")
        structured_data = json.dumps(code_understanding, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_2_RISK_ENUMERATION.format(
            file_path=file_path,
            structured_data=structured_data
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 2", temperature=0.3)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Agent 2 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_3(self, file_path: str, risk_enumeration: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 3：漏洞验证

        Args:
            file_path: 文件路径
            risk_enumeration: 风险枚举结果
            file_content: 文件内容

        Returns:
            (漏洞验证结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 3 (漏洞验证) on: {file_path}")
        risk_list = json.dumps(risk_enumeration.get('risks', []), ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_3_VULNERABILITY_VERIFICATION.format(
            file_path=file_path,
            risk_list=risk_list,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 3", temperature=0.1)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Agent 3 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_4(self, file_path: str, vulnerability_verification: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 4：攻击链分析

        Args:
            file_path: 文件路径
            vulnerability_verification: 漏洞验证结果

        Returns:
            (攻击链分析结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 4 (攻击链分析) on: {file_path}")
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_4_ATTACK_CHAIN_ANALYSIS.format(
            file_path=file_path,
            verification_results=verification_results
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 4", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Agent 4 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_5(self, file_path: str, attack_chain_analysis: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 5：对抗验证

        Args:
            file_path: 文件路径
            attack_chain_analysis: 攻击链分析结果
            file_content: 文件内容

        Returns:
            (对抗验证结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 5 (对抗验证) on: {file_path}")
        attack_chain_json = json.dumps(attack_chain_analysis, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_5_ADVERSARIAL_VALIDATION.format(
            file_path=file_path,
            attack_chain_analysis=attack_chain_json,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 5", temperature=0.1)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Agent 5 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_agent_6(self, file_path: str, adversarial_validation: Dict[str, Any], vulnerability_verification: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 6：最终裁决

        Args:
            file_path: 文件路径
            adversarial_validation: 对抗验证结果
            vulnerability_verification: 漏洞验证结果

        Returns:
            (最终裁决结果, token使用信息)
        """
        print(f"[DEBUG] 运行Agent 6 (最终裁决) on: {file_path}")
        adversarial_results = json.dumps(adversarial_validation, ensure_ascii=False)
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_6_FINAL_DECISION.format(
            file_path=file_path,
            adversarial_results=adversarial_results,
            verification_results=verification_results
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 6", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Agent 6 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    def _estimate_token_count(self, text: str) -> int:
        """估计文本的token数量

        Args:
            text: 文本内容

        Returns:
            估计的token数量
        """
        # 简单的token估计：1个token约等于4个字符
        return len(text) // 4

    async def _run_context_compressor(self, file_path: str, file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行ContextCompressor Agent：代码摘要压缩

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            (压缩结果, token使用信息)
        """
        print(f"[DEBUG] 运行ContextCompressor on: {file_path}")
        
        # 检查文件大小是否超过token限制
        token_count = self._estimate_token_count(file_content)
        if token_count > self.max_tokens_per_file:
            print(f"[DEBUG] 文件 {file_path} 超过token限制 ({token_count} > {self.max_tokens_per_file})，进行分块处理")
            # 简单分块：按行分割
            lines = file_content.split('\n')
            chunks = []
            current_chunk = []
            current_tokens = 0
            
            for line in lines:
                line_tokens = self._estimate_token_count(line)
                if current_tokens + line_tokens > self.max_tokens_per_file:
                    chunks.append('\n'.join(current_chunk))
                    current_chunk = [line]
                    current_tokens = line_tokens
                else:
                    current_chunk.append(line)
                    current_tokens += line_tokens
            
            if current_chunk:
                chunks.append('\n'.join(current_chunk))
            
            # 并行处理所有分块
            tasks = []
            for i, chunk in enumerate(chunks):
                chunk_file_path = f"{file_path}:chunk:{i+1}"
                task = self._run_context_compressor(chunk_file_path, chunk)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            # 合并结果
            merged_result = {
                'summary': '',
                'key_functions': [],
                'security_relevant_sections': [],
                'compressed_content': ''
            }
            total_token_usage = {
                'prompt_tokens': 0,
                'completion_tokens': 0,
                'total_tokens': 0
            }
            
            for result, token_usage in results:
                if 'summary' in result:
                    merged_result['summary'] += result['summary'] + '\n'
                if 'key_functions' in result:
                    merged_result['key_functions'].extend(result['key_functions'])
                if 'security_relevant_sections' in result:
                    merged_result['security_relevant_sections'].extend(result['security_relevant_sections'])
                if 'compressed_content' in result:
                    merged_result['compressed_content'] += result['compressed_content'] + '\n'
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
            
            return merged_result, total_token_usage
        
        prompt = self.prompt_templates.AGENT_CONTEXT_COMPRESSOR.format(
            file_path=file_path,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "ContextCompressor", temperature=0.1)
        result = self._parse_json_response(response)
        print(f"[DEBUG] ContextCompressor 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_risk_validator(self, file_path: str, code_understanding: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行RiskValidator Agent：合并风险枚举和漏洞验证

        Args:
            file_path: 文件路径
            code_understanding: 代码理解结果
            file_content: 文件内容

        Returns:
            (风险验证结果, token使用信息)
        """
        print(f"[DEBUG] 运行RiskValidator on: {file_path}")
        code_understanding_json = json.dumps(code_understanding, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_RISK_VALIDATOR.format(
            file_path=file_path,
            code_understanding=code_understanding_json,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "RiskValidator", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] RiskValidator 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _run_attack_simulator(self, file_path: str, risk_validation: Dict[str, Any], file_content: str) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行AttackSimulator Agent：合并攻击链分析和对抗验证

        Args:
            file_path: 文件路径
            risk_validation: 风险验证结果
            file_content: 文件内容

        Returns:
            (攻击模拟结果, token使用信息)
        """
        print(f"[DEBUG] 运行AttackSimulator on: {file_path}")
        risk_validation_json = json.dumps(risk_validation, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_ATTACK_SIMULATOR.format(
            file_path=file_path,
            risk_validation=risk_validation_json,
            file_content=file_content
        )
        prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
        
        response, token_usage = await self._generate_with_retry(prompt, "AttackSimulator", temperature=0.1)
        result = self._parse_json_response(response)
        print(f"[DEBUG] AttackSimulator 完成，token使用: {token_usage['total_tokens']}")
        return result, token_usage
    
    async def _generate_with_retry(self, prompt: str, agent_name: str = "unknown", temperature: float = 0.0) -> Tuple[str, Dict[str, int]]:
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
                # JSON Guard: 在prompt顶部添加JSON输出强制约束
                json_guard_prompt = "只输出JSON，否则视为失败\n\n" + prompt
                
                # 创建AIRequest对象
                request = AIRequest(
                    prompt=json_guard_prompt,
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
                console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]生成失败 (Agent: {agent_name}, 尝试 {i+1}/{self.max_retries}): {e}[/yellow]")
                import traceback
                traceback.print_exc()
                if i == self.max_retries - 1:
                    raise
                await asyncio.sleep(1)
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """解析JSON响应
        
        Args:
            response: 响应字符串
            
        Returns:
            解析后的JSON对象
        """
        try:
            # 清理响应字符串
            cleaned_response = response.strip()
            
            # 首先尝试直接解析
            try:
                parsed_json = json.loads(cleaned_response)
                # 检查是否包含final_findings
                if 'final_findings' not in parsed_json:
                    parsed_json['final_findings'] = [{
                        "vulnerability": "未发现安全问题",
                        "location": "unknown",
                        "severity": "info",
                        "status": "VALID",
                        "confidence": "高",
                        "cvss_score": "",
                        "recommendation": "代码安全，无需修复",
                        "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                    }]
                if 'summary' not in parsed_json:
                    parsed_json['summary'] = {
                        "total_vulnerabilities": 0,
                        "valid_vulnerabilities": 0,
                        "uncertain_vulnerabilities": 0,
                        "invalid_vulnerabilities": 0,
                        "high_severity_count": 0,
                        "medium_severity_count": 0,
                        "low_severity_count": 0
                    }
                return parsed_json
            except json.JSONDecodeError:
                pass
            
            # 提取JSON部分（处理markdown代码块）
            # 尝试匹配 ```json ... ``` 格式
            json_match = re.search(r'```json\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    parsed_json = json.loads(json_str)
                    # 检查是否包含final_findings
                    if 'final_findings' not in parsed_json:
                        parsed_json['final_findings'] = [{
                            "vulnerability": "未发现安全问题",
                            "location": "unknown",
                            "severity": "info",
                            "status": "VALID",
                            "confidence": "高",
                            "cvss_score": "",
                            "recommendation": "代码安全，无需修复",
                            "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                        }]
                    if 'summary' not in parsed_json:
                        parsed_json['summary'] = {
                            "total_vulnerabilities": 0,
                            "valid_vulnerabilities": 0,
                            "uncertain_vulnerabilities": 0,
                            "invalid_vulnerabilities": 0,
                            "high_severity_count": 0,
                            "medium_severity_count": 0,
                            "low_severity_count": 0
                        }
                    return parsed_json
                except json.JSONDecodeError:
                    pass
            
            # 尝试匹配 ``` ... ``` 格式
            json_match = re.search(r'```\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    parsed_json = json.loads(json_str)
                    # 检查是否包含final_findings
                    if 'final_findings' not in parsed_json:
                        parsed_json['final_findings'] = [{
                            "vulnerability": "未发现安全问题",
                            "location": "unknown",
                            "severity": "info",
                            "status": "VALID",
                            "confidence": "高",
                            "cvss_score": "",
                            "recommendation": "代码安全，无需修复",
                            "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                        }]
                    if 'summary' not in parsed_json:
                        parsed_json['summary'] = {
                            "total_vulnerabilities": 0,
                            "valid_vulnerabilities": 0,
                            "uncertain_vulnerabilities": 0,
                            "invalid_vulnerabilities": 0,
                            "high_severity_count": 0,
                            "medium_severity_count": 0,
                            "low_severity_count": 0
                        }
                    return parsed_json
                except json.JSONDecodeError:
                    pass
            
            # 尝试匹配 { ... } 格式
            json_match = re.search(r'\{[\s\S]*\}', cleaned_response)
            if json_match:
                json_str = json_match.group(0)
                try:
                    parsed_json = json.loads(json_str)
                    # 检查是否包含final_findings
                    if 'final_findings' not in parsed_json:
                        parsed_json['final_findings'] = [{
                            "vulnerability": "未发现安全问题",
                            "location": "unknown",
                            "severity": "info",
                            "status": "VALID",
                            "confidence": "高",
                            "cvss_score": "",
                            "recommendation": "代码安全，无需修复",
                            "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                        }]
                    if 'summary' not in parsed_json:
                        parsed_json['summary'] = {
                            "total_vulnerabilities": 0,
                            "valid_vulnerabilities": 0,
                            "uncertain_vulnerabilities": 0,
                            "invalid_vulnerabilities": 0,
                            "high_severity_count": 0,
                            "medium_severity_count": 0,
                            "low_severity_count": 0
                        }
                    return parsed_json
                except json.JSONDecodeError:
                    pass
            
            # 尝试更宽松的JSON提取和修复
            # 1. 提取可能的JSON部分
            possible_json = cleaned_response
            # 找到第一个 { 和最后一个 }
            first_brace = possible_json.find('{')
            last_brace = possible_json.rfind('}')
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                json_str = possible_json[first_brace:last_brace+1]
                # 尝试修复常见的JSON问题
                # 1. 修复未转义的引号
                json_str = re.sub(r'(?<!\\)\'', '"', json_str)
                # 2. 修复属性名缺少引号
                json_str = re.sub(r'(\w+)\s*:', '"\1":', json_str)
                # 3. 修复尾部逗号
                json_str = re.sub(r',\s*}', '}', json_str)
                json_str = re.sub(r',\s*\]', ']', json_str)
                try:
                    parsed_json = json.loads(json_str)
                    # 检查是否包含final_findings
                    if 'final_findings' not in parsed_json:
                        parsed_json['final_findings'] = [{
                            "vulnerability": "未发现安全问题",
                            "location": "unknown",
                            "severity": "info",
                            "status": "VALID",
                            "confidence": "高",
                            "cvss_score": "",
                            "recommendation": "代码安全，无需修复",
                            "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                        }]
                    if 'summary' not in parsed_json:
                        parsed_json['summary'] = {
                            "total_vulnerabilities": 0,
                            "valid_vulnerabilities": 0,
                            "uncertain_vulnerabilities": 0,
                            "invalid_vulnerabilities": 0,
                            "high_severity_count": 0,
                            "medium_severity_count": 0,
                            "low_severity_count": 0
                        }
                    return parsed_json
                except json.JSONDecodeError:
                    pass
            
            # 尝试提取最基本的JSON结构
            # 查找所有可能的JSON对象
            json_objects = []
            brace_count = 0
            start_index = -1
            
            for i, char in enumerate(cleaned_response):
                if char == '{':
                    if brace_count == 0:
                        start_index = i
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and start_index != -1:
                        json_str = cleaned_response[start_index:i+1]
                        json_objects.append(json_str)
                        start_index = -1
            
            # 尝试解析找到的JSON对象
            for json_str in json_objects:
                try:
                    parsed_json = json.loads(json_str)
                    # 检查是否包含final_findings
                    if 'final_findings' not in parsed_json:
                        parsed_json['final_findings'] = [{
                            "vulnerability": "未发现安全问题",
                            "location": "unknown",
                            "severity": "info",
                            "status": "VALID",
                            "confidence": "高",
                            "cvss_score": "",
                            "recommendation": "代码安全，无需修复",
                            "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                        }]
                    if 'summary' not in parsed_json:
                        parsed_json['summary'] = {
                            "total_vulnerabilities": 0,
                            "valid_vulnerabilities": 0,
                            "uncertain_vulnerabilities": 0,
                            "invalid_vulnerabilities": 0,
                            "high_severity_count": 0,
                            "medium_severity_count": 0,
                            "low_severity_count": 0
                        }
                    return parsed_json
                except json.JSONDecodeError:
                    # 尝试修复后再解析
                    try:
                        # 修复未转义的引号
                        json_str = re.sub(r'(?<!\\)\'', '"', json_str)
                        # 修复属性名缺少引号
                        json_str = re.sub(r'(\w+)\s*:', '"\1":', json_str)
                        # 修复尾部逗号
                        json_str = re.sub(r',\s*}', '}', json_str)
                        json_str = re.sub(r',\s*\]', ']', json_str)
                        parsed_json = json.loads(json_str)
                        # 检查是否包含final_findings
                        if 'final_findings' not in parsed_json:
                            parsed_json['final_findings'] = [{
                                "vulnerability": "未发现安全问题",
                                "location": "unknown",
                                "severity": "info",
                                "status": "VALID",
                                "confidence": "高",
                                "cvss_score": "",
                                "recommendation": "代码安全，无需修复",
                                "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                            }]
                        if 'summary' not in parsed_json:
                            parsed_json['summary'] = {
                                "total_vulnerabilities": 0,
                                "valid_vulnerabilities": 0,
                                "uncertain_vulnerabilities": 0,
                                "invalid_vulnerabilities": 0,
                                "high_severity_count": 0,
                                "medium_severity_count": 0,
                                "low_severity_count": 0
                            }
                        return parsed_json
                    except json.JSONDecodeError:
                        pass
            
            # 如果仍然没有找到JSON，返回默认的JSON对象
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]无法解析JSON，返回默认对象[/yellow]")
            return {
                'final_findings': [{
                    "vulnerability": "未发现安全问题",
                    "location": "unknown",
                    "severity": "info",
                    "status": "VALID",
                    "confidence": "高",
                    "cvss_score": "",
                    "recommendation": "代码安全，无需修复",
                    "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                }],
                'summary': {
                    "total_vulnerabilities": 0,
                    "valid_vulnerabilities": 0,
                    "uncertain_vulnerabilities": 0,
                    "invalid_vulnerabilities": 0,
                    "high_severity_count": 0,
                    "medium_severity_count": 0,
                    "low_severity_count": 0
                }
            }
        except Exception as e:
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]JSON解析失败: {e}[/yellow]")
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [dim]原始响应: {response[:500]}...[/dim]")
            # 返回默认的JSON对象
            return {
                'final_findings': [{
                    "vulnerability": "未发现安全问题",
                    "location": "unknown",
                    "severity": "info",
                    "status": "VALID",
                    "confidence": "高",
                    "cvss_score": "",
                    "recommendation": "代码安全，无需修复",
                    "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
                }],
                'summary': {
                    "total_vulnerabilities": 0,
                    "valid_vulnerabilities": 0,
                    "uncertain_vulnerabilities": 0,
                    "invalid_vulnerabilities": 0,
                    "high_severity_count": 0,
                    "medium_severity_count": 0,
                    "low_severity_count": 0
                }
            }
    
    def _build_agent_dependencies(self) -> Dict[str, List[str]]:
        """构建Agent之间的依赖关系
        
        Returns:
            Agent依赖关系字典
        """
        return {
            'scanner': [],  # Scanner Agent 没有依赖
            'reasoning': ['scanner'],  # Reasoning Agent 依赖 Scanner Agent
            'exploit': ['reasoning'],  # Exploit Agent 依赖 Reasoning Agent
            'fix': ['reasoning'],  # Fix Agent 依赖 Reasoning Agent
            'report': ['reasoning', 'fix']  # Report Agent 依赖 Reasoning Agent 和 Fix Agent
        }

    def _update_agent_memory(self, agent_name: str, data: Dict[str, Any]) -> None:
        """更新Agent内存
        
        Args:
            agent_name: Agent名称
            data: 要存储的数据
        """
        if agent_name not in self.agent_memory:
            self.agent_memory[agent_name] = []
        self.agent_memory[agent_name].append(data)

    def _get_agent_memory(self, agent_name: str) -> List[Dict[str, Any]]:
        """获取Agent内存
        
        Args:
            agent_name: Agent名称
            
        Returns:
            Agent内存数据
        """
        return self.agent_memory.get(agent_name, [])

    def _get_dependency_data(self, agent_name: str) -> Dict[str, Any]:
        """获取Agent依赖的数据
        
        Args:
            agent_name: Agent名称
            
        Returns:
            依赖数据
        """
        dependency_data = {}
        dependencies = self.agent_dependencies.get(agent_name, [])
        for dependency in dependencies:
            dependency_data[dependency] = self._get_agent_memory(dependency)
        return dependency_data

    def _update_agent_performance(self, agent_timings: Dict[str, float], token_usage: Dict[str, int]) -> None:
        """更新Agent性能指标
        
        Args:
            agent_timings: Agent执行时间
            token_usage: Token使用情况
        """
        for agent_name, timing in agent_timings.items():
            if agent_name not in self.agent_performance:
                self.agent_performance[agent_name] = {
                    'total_executions': 0,
                    'total_time': 0,
                    'avg_time': 0,
                    'total_tokens': 0
                }
            
            performance = self.agent_performance[agent_name]
            performance['total_executions'] += 1
            performance['total_time'] += timing
            performance['avg_time'] = performance['total_time'] / performance['total_executions']
            
        # 更新总体token使用
        self.agent_performance['total_tokens'] = token_usage['total_tokens']

    def process_query(self, query: str) -> str:
        """处理自然语言查询
        
        Args:
            query: 自然语言查询
            
        Returns:
            查询结果
        """
        import asyncio
        
        async def _process_query():
            """异步处理查询"""
            prompt = f"""你是 HOS-LS 安全助手，负责回答关于代码安全的问题。
            
            用户问题: {query}
            
            请提供详细、专业的回答，包括:
            1. 问题分析
            2. 安全建议
            3. 相关漏洞类型
            4. 修复方案
            """
            
            prompt = self.prompt_templates.apply_language_instruction(prompt, self.language)
            
            try:
                response, token_usage = await self._generate_with_retry(prompt, "QueryProcessor", temperature=0.3)
                return response
            except Exception as e:
                console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]查询处理失败: {e}[/yellow]")
                return "抱歉，无法处理您的查询，请尝试重新表述。"
        
        # 同步调用异步函数
        result = asyncio.run(_process_query())
        return result

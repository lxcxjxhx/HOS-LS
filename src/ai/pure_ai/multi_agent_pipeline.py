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
        else:
            # 配置是对象
            self.max_retries = getattr(config, 'max_retries', 3)
            self.model = getattr(config, 'ai', {}).get('model', 'deepseek-reasoner') if hasattr(config, 'ai') else 'deepseek-reasoner'
    
    async def run_pipeline(self, file_path: str) -> Dict[str, Any]:
        """运行完整的多Agent流水线

        Args:
            file_path: 文件路径

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
                # 主任务：7个步骤（上下文构建 + 6个Agent）
                main_task = progress.add_task(f"[cyan]分析: {Path(file_path).name}[/cyan]", total=7)
                
                # 1. 构建上下文
                start_time = time.time()
                context = self.context_builder.build_context(file_path)
                elapsed = time.time() - start_time
                agent_timings['context_build'] = elapsed
                progress.advance(main_task)
                
                # 2. Agent 0: 上下文分析
                start_time = time.time()
                context_analysis, token_usage = await self._run_agent_0(file_path, context)
                elapsed = time.time() - start_time
                agent_timings['agent_0'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)
                
                # 3. Agent 1: 代码理解
                start_time = time.time()
                code_understanding, token_usage = await self._run_agent_1(file_path, context, context_analysis)
                elapsed = time.time() - start_time
                agent_timings['agent_1'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)
                
                # 4. Agent 2: 风险枚举
                start_time = time.time()
                risk_enumeration, token_usage = await self._run_agent_2(file_path, code_understanding)
                elapsed = time.time() - start_time
                agent_timings['agent_2'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)
                
                # 5. Agent 3: 漏洞验证
                start_time = time.time()
                vulnerability_verification, token_usage = await self._run_agent_3(file_path, risk_enumeration, context['file_content'])
                elapsed = time.time() - start_time
                agent_timings['agent_3'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)
                
                # 6. Agent 4: 攻击链分析
                start_time = time.time()
                attack_chain_analysis, token_usage = await self._run_agent_4(file_path, vulnerability_verification)
                elapsed = time.time() - start_time
                agent_timings['agent_4'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)
                
                # 7. Agent 5: 对抗验证
                start_time = time.time()
                adversarial_validation, token_usage = await self._run_agent_5(file_path, attack_chain_analysis, context['file_content'])
                elapsed = time.time() - start_time
                agent_timings['agent_5'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)
                
                # 8. Agent 6: 最终裁决
                start_time = time.time()
                final_decision, token_usage = await self._run_agent_6(file_path, adversarial_validation, vulnerability_verification)
                elapsed = time.time() - start_time
                agent_timings['agent_6'] = elapsed
                total_token_usage['prompt_tokens'] += token_usage['prompt_tokens']
                total_token_usage['completion_tokens'] += token_usage['completion_tokens']
                total_token_usage['total_tokens'] += token_usage['total_tokens']
                progress.advance(main_task)
            
            # Progress结束后输出最终结果
            total_elapsed = time.time() - total_start_time
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold green]✓ {Path(file_path).name} 分析完成[/bold green] [dim]({total_elapsed:.2f}s)[/dim]")
            
            # 显示总体token统计
            if total_token_usage['total_tokens'] > 0:
                avg_tokens_per_agent = total_token_usage['total_tokens'] / 6 if 6 > 0 else 0
                console.print(f"[dim]  📊 Token: {total_token_usage['total_tokens']:,} (提示词: {total_token_usage['prompt_tokens']:,}, 补全: {total_token_usage['completion_tokens']:,})[/dim]")
            
            return {
                'file_path': file_path,
                'context_analysis': context_analysis,
                'code_understanding': code_understanding,
                'risk_enumeration': risk_enumeration,
                'vulnerability_verification': vulnerability_verification,
                'attack_chain_analysis': attack_chain_analysis,
                'adversarial_validation': adversarial_validation,
                'final_decision': final_decision
            }
        except Exception as e:
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [bold red]✗ {Path(file_path).name} 分析失败: {e}[/bold red]")
            import traceback
            traceback.print_exc()
            return {
                'file_path': file_path,
                'error': str(e)
            }
    
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
        
        response, token_usage = await self._generate_with_retry(prompt, "Agent 6", temperature=0.2)
        result = self._parse_json_response(response)
        print(f"[DEBUG] Agent 6 完成，token使用: {token_usage['total_tokens']}")
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
                return json.loads(cleaned_response)
            except json.JSONDecodeError:
                pass
            
            # 提取JSON部分（处理markdown代码块）
            # 尝试匹配 ```json ... ``` 格式
            json_match = re.search(r'```json\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
            
            # 尝试匹配 ``` ... ``` 格式
            json_match = re.search(r'```\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
            
            # 尝试匹配 { ... } 格式
            json_match = re.search(r'\{[\s\S]*\}', cleaned_response)
            if json_match:
                json_str = json_match.group(0)
                try:
                    return json.loads(json_str)
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
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
            
            # 如果没有找到JSON，返回原始响应
            return {'raw_response': response}
        except Exception as e:
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [yellow]JSON解析失败: {e}[/yellow]")
            console.print(f"[bold cyan][PURE-AI][/bold cyan] [dim]原始响应: {response[:500]}...[/dim]")
            return {'raw_response': response, 'error': str(e)}

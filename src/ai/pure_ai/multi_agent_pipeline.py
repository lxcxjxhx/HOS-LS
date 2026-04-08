import asyncio
import json
import re
from typing import Dict, List, Any, Optional
from src.ai.pure_ai.context_builder import ContextBuilder
from src.ai.pure_ai.prompt_templates import PromptTemplates
from src.ai.models import AIRequest

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
        try:
            print(f"[PURE-AI] 开始分析文件: {file_path}")
            
            # 1. 构建上下文
            context = self.context_builder.build_context(file_path)
            print(f"[PURE-AI] 上下文构建完成")
            
            # 2. Agent 0: 上下文分析
            context_analysis = await self._run_agent_0(file_path, context)
            print(f"[PURE-AI] Agent 0 分析完成")
            
            # 3. Agent 1: 代码理解
            code_understanding = await self._run_agent_1(file_path, context, context_analysis)
            print(f"[PURE-AI] Agent 1 分析完成")
            
            # 4. Agent 2: 风险枚举
            risk_enumeration = await self._run_agent_2(file_path, code_understanding)
            print(f"[PURE-AI] Agent 2 分析完成")
            
            # 5. Agent 3: 漏洞验证
            vulnerability_verification = await self._run_agent_3(file_path, risk_enumeration, context['file_content'])
            print(f"[PURE-AI] Agent 3 分析完成")
            
            # 6. Agent 4: 攻击链分析
            attack_chain_analysis = await self._run_agent_4(file_path, vulnerability_verification)
            print(f"[PURE-AI] Agent 4 分析完成")
            
            # 7. Agent 5: 对抗验证
            adversarial_validation = await self._run_agent_5(file_path, attack_chain_analysis, context['file_content'])
            print(f"[PURE-AI] Agent 5 分析完成")
            
            # 8. Agent 6: 最终裁决
            final_decision = await self._run_agent_6(file_path, adversarial_validation, vulnerability_verification)
            print(f"[PURE-AI] Agent 6 分析完成")
            
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
            print(f"[PURE-AI] 分析失败: {e}")
            import traceback
            traceback.print_exc()
            return {
                'file_path': file_path,
                'error': str(e)
            }
    
    async def _run_agent_0(self, file_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """运行Agent 0：上下文构建
        
        Args:
            file_path: 文件路径
            context: 上下文信息
            
        Returns:
            上下文分析结果
        """
        prompt = self.prompt_templates.AGENT_0_CONTEXT_BUILDER.format(
            file_path=file_path,
            file_content=context['file_content'],
            related_files=self.prompt_templates.format_related_files(context['related_files']),
            imports=self.prompt_templates.format_imports(context['imports']),
            function_calls=self.prompt_templates.format_function_calls(context['function_calls'])
        )
        
        response = await self._generate_with_retry(prompt)
        return self._parse_json_response(response)
    
    async def _run_agent_1(self, file_path: str, context: Dict[str, Any], context_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """运行Agent 1：代码理解
        
        Args:
            file_path: 文件路径
            context: 上下文信息
            context_analysis: 上下文分析结果
            
        Returns:
            代码理解结果
        """
        context_info = json.dumps(context_analysis, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_1_CODE_UNDERSTANDING.format(
            file_path=file_path,
            file_content=context['file_content'],
            context_info=context_info
        )
        
        response = await self._generate_with_retry(prompt)
        return self._parse_json_response(response)
    
    async def _run_agent_2(self, file_path: str, code_understanding: Dict[str, Any]) -> Dict[str, Any]:
        """运行Agent 2：风险枚举
        
        Args:
            file_path: 文件路径
            code_understanding: 代码理解结果
            
        Returns:
            风险枚举结果
        """
        structured_data = json.dumps(code_understanding, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_2_RISK_ENUMERATION.format(
            file_path=file_path,
            structured_data=structured_data
        )
        
        response = await self._generate_with_retry(prompt)
        return self._parse_json_response(response)
    
    async def _run_agent_3(self, file_path: str, risk_enumeration: Dict[str, Any], file_content: str) -> Dict[str, Any]:
        """运行Agent 3：漏洞验证
        
        Args:
            file_path: 文件路径
            risk_enumeration: 风险枚举结果
            file_content: 文件内容
            
        Returns:
            漏洞验证结果
        """
        risk_list = json.dumps(risk_enumeration.get('risks', []), ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_3_VULNERABILITY_VERIFICATION.format(
            file_path=file_path,
            risk_list=risk_list,
            file_content=file_content
        )
        
        response = await self._generate_with_retry(prompt)
        return self._parse_json_response(response)
    
    async def _run_agent_4(self, file_path: str, vulnerability_verification: Dict[str, Any]) -> Dict[str, Any]:
        """运行Agent 4：攻击链分析
        
        Args:
            file_path: 文件路径
            vulnerability_verification: 漏洞验证结果
            
        Returns:
            攻击链分析结果
        """
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_4_ATTACK_CHAIN_ANALYSIS.format(
            file_path=file_path,
            verification_results=verification_results
        )
        
        response = await self._generate_with_retry(prompt)
        return self._parse_json_response(response)
    
    async def _run_agent_5(self, file_path: str, attack_chain_analysis: Dict[str, Any], file_content: str) -> Dict[str, Any]:
        """运行Agent 5：对抗验证
        
        Args:
            file_path: 文件路径
            attack_chain_analysis: 攻击链分析结果
            file_content: 文件内容
            
        Returns:
            对抗验证结果
        """
        attack_chain_json = json.dumps(attack_chain_analysis, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_5_ADVERSARIAL_VALIDATION.format(
            file_path=file_path,
            attack_chain_analysis=attack_chain_json,
            file_content=file_content
        )
        
        response = await self._generate_with_retry(prompt)
        return self._parse_json_response(response)
    
    async def _run_agent_6(self, file_path: str, adversarial_validation: Dict[str, Any], vulnerability_verification: Dict[str, Any]) -> Dict[str, Any]:
        """运行Agent 6：最终裁决
        
        Args:
            file_path: 文件路径
            adversarial_validation: 对抗验证结果
            vulnerability_verification: 漏洞验证结果
            
        Returns:
            最终裁决结果
        """
        adversarial_results = json.dumps(adversarial_validation, ensure_ascii=False)
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)
        prompt = self.prompt_templates.AGENT_6_FINAL_DECISION.format(
            file_path=file_path,
            adversarial_results=adversarial_results,
            verification_results=verification_results
        )
        
        response = await self._generate_with_retry(prompt)
        return self._parse_json_response(response)
    
    async def _generate_with_retry(self, prompt: str) -> str:
        """带重试的生成
        
        Args:
            prompt: 提示词
            
        Returns:
            生成的响应
        """
        for i in range(self.max_retries):
            try:
                # 创建AIRequest对象
                request = AIRequest(
                    prompt=prompt,
                    model=self.model,
                    temperature=0.0,
                    max_tokens=4096
                )
                
                # 调用客户端生成
                response = await self.client.generate(request)
                
                # 返回响应内容
                if hasattr(response, 'content'):
                    return response.content
                else:
                    return str(response)
                    
            except Exception as e:
                print(f"[PURE-AI] 生成失败 (尝试 {i+1}/{self.max_retries}): {e}")
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
            print(f"[PURE-AI] JSON解析失败: {e}")
            print(f"[PURE-AI] 原始响应: {response[:500]}...")  # 打印前500字符
            return {'raw_response': response, 'error': str(e)}

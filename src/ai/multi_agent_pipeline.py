"""多Agent管道模块

实现 Multi-Agent Prompt Pipeline，包含7个Agent的执行逻辑。
"""

import asyncio
from typing import List, Dict, Any, Optional

from src.ai.models import AnalysisContext, SecurityAnalysisResult, VulnerabilityFinding
from src.ai.context_builder import ContextBuilder
from src.ai.prompt_templates import PromptTemplates


class MultiAgentPipeline:
    """多Agent管道

    实现7个Agent的执行逻辑，包括上下文构建、代码语义解析、风险枚举、
    漏洞验证、攻击链构建、对抗验证和最终裁决。
    """

    def __init__(self, ai_client, config):
        """初始化多Agent管道

        Args:
            ai_client: AI客户端
            config: 配置对象
        """
        self.ai_client = ai_client
        self.config = config
        self.context_builder = ContextBuilder()
        self.prompt_templates = PromptTemplates()

    async def run(self, context: AnalysisContext) -> SecurityAnalysisResult:
        """运行多Agent分析

        Args:
            context: 分析上下文

        Returns:
            安全分析结果
        """
        try:
            # Step 1: 上下文构建（Agent 0）
            enhanced_context = await self._run_agent_0(context)

            # Step 2: 代码语义解析（Agent 1）
            semantic_result = await self._run_agent_1(enhanced_context)

            # Step 3: 风险枚举（Agent 2）
            risk_result = await self._run_agent_2(semantic_result)

            # Step 4: 漏洞验证（Agent 3）
            validation_result = await self._run_agent_3(risk_result)

            # Step 5: 攻击链构建（Agent 4）
            attack_chain_result = await self._run_agent_4(validation_result)

            # Step 6: 对抗验证（Agent 5）
            adversarial_result = await self._run_agent_5(attack_chain_result)

            # Step 7: 最终裁决（Agent 6）
            final_result = await self._run_agent_6(adversarial_result)

            return final_result
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] 多Agent管道执行失败: {e}")
            return SecurityAnalysisResult(
                findings=[],
                risk_score=0.0,
                summary="Analysis failed",
                recommendations=[],
                metadata={"error": str(e)}
            )

    async def _run_agent_0(self, context: AnalysisContext) -> Dict[str, Any]:
        """Agent 0: 上下文构建（伪RAG核心）

        Args:
            context: 分析上下文

        Returns:
            增强的上下文
        """
        # 构建上下文
        enhanced_context = await self.context_builder.build_context(context)
        
        # 生成Prompt
        prompt = self.prompt_templates.get_prompt("agent_0", {
            "file_content": context.code_content,
            "imports": enhanced_context.get("imports", []),
            "related_files": enhanced_context.get("related_files", []),
            "function_calls": enhanced_context.get("function_calls", [])
        })

        # 调用AI
        response = await self.ai_client.chat_completion([{"role": "user", "content": prompt}])
        
        # 解析响应
        try:
            import json
            analysis_result = json.loads(response)
        except:
            analysis_result = {
                "key_functions": [],
                "external_dependencies": [],
                "data_inputs": [],
                "context_summary": ""
            }

        # 合并上下文
        return {
            **enhanced_context,
            "analysis_result": analysis_result,
            "original_context": context
        }

    async def _run_agent_1(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Agent 1: 代码理解（强制结构化）

        Args:
            context: 增强的上下文

        Returns:
            代码理解结果
        """
        # 生成Prompt
        prompt = self.prompt_templates.get_prompt("agent_1", {
            "file_content": context["original_context"].code_content,
            "context_summary": context["analysis_result"].get("context_summary", "")
        })

        # 调用AI
        response = await self.ai_client.chat_completion([{"role": "user", "content": prompt}])

        # 解析响应
        try:
            import json
            semantic_result = json.loads(response)
        except:
            semantic_result = {
                "input_sources": [],
                "dangerous_operations": [],
                "data_flows": [],
                "suspicious_points": []
            }

        return {
            **context,
            "semantic_result": semantic_result
        }

    async def _run_agent_2(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Agent 2: 风险枚举（最大召回）

        Args:
            context: 代码理解结果

        Returns:
            风险枚举结果
        """
        # 生成Prompt
        prompt = self.prompt_templates.get_prompt("agent_2", {
            "semantic_result": context["semantic_result"]
        })

        # 调用AI
        response = await self.ai_client.chat_completion([{"role": "user", "content": prompt}])

        # 解析响应
        try:
            import json
            risk_result = json.loads(response)
        except:
            risk_result = {
                "risks": []
            }

        return {
            **context,
            "risk_result": risk_result
        }

    async def _run_agent_3(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Agent 3: 漏洞验证（核心）

        Args:
            context: 风险枚举结果

        Returns:
            漏洞验证结果
        """
        # 生成Prompt
        prompt = self.prompt_templates.get_prompt("agent_3", {
            "file_content": context["original_context"].code_content,
            "risks": context["risk_result"].get("risks", [])
        })

        # 调用AI
        response = await self.ai_client.chat_completion([{"role": "user", "content": prompt}])

        # 解析响应
        try:
            import json
            validation_result = json.loads(response)
        except:
            validation_result = {
                "validated_risks": []
            }

        return {
            **context,
            "validation_result": validation_result
        }

    async def _run_agent_4(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Agent 4: 攻击链分析（高级能力）

        Args:
            context: 漏洞验证结果

        Returns:
            攻击链分析结果
        """
        # 生成Prompt
        prompt = self.prompt_templates.get_prompt("agent_4", {
            "validated_risks": context["validation_result"].get("validated_risks", [])
        })

        # 调用AI
        response = await self.ai_client.chat_completion([{"role": "user", "content": prompt}])

        # 解析响应
        try:
            import json
            attack_chain_result = json.loads(response)
        except:
            attack_chain_result = {
                "attack_chains": []
            }

        return {
            **context,
            "attack_chain_result": attack_chain_result
        }

    async def _run_agent_5(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Agent 5: 对抗验证（关键增强）

        Args:
            context: 攻击链分析结果

        Returns:
            对抗验证结果
        """
        # 生成Prompt
        prompt = self.prompt_templates.get_prompt("agent_5", {
            "file_content": context["original_context"].code_content,
            "validated_risks": context["validation_result"].get("validated_risks", []),
            "attack_chains": context["attack_chain_result"].get("attack_chains", [])
        })

        # 调用AI
        response = await self.ai_client.chat_completion([{"role": "user", "content": prompt}])

        # 解析响应
        try:
            import json
            adversarial_result = json.loads(response)
        except:
            adversarial_result = {
                "verified_risks": []
            }

        return {
            **context,
            "adversarial_result": adversarial_result
        }

    async def _run_agent_6(self, context: Dict[str, Any]) -> SecurityAnalysisResult:
        """Agent 6: 最终裁决（防胡说）

        Args:
            context: 对抗验证结果

        Returns:
            最终安全分析结果
        """
        # 生成Prompt
        prompt = self.prompt_templates.get_prompt("agent_6", {
            "verified_risks": context["adversarial_result"].get("verified_risks", [])
        })

        # 调用AI
        response = await self.ai_client.chat_completion([{"role": "user", "content": prompt}])

        # 解析响应
        try:
            import json
            final_result = json.loads(response)
        except:
            final_result = {
                "vulnerabilities": [],
                "confidence": 0.0,
                "summary": "No vulnerabilities found"
            }

        # 转换为 SecurityAnalysisResult
        findings = []
        for vuln in final_result.get("vulnerabilities", []):
            finding = VulnerabilityFinding(
                rule_id=vuln.get("rule_id", "PURE-AI-VULN"),
                rule_name=vuln.get("rule_name", "Pure AI Vulnerability"),
                description=vuln.get("description", ""),
                severity=vuln.get("severity", "medium"),
                confidence=vuln.get("confidence", 0.7),
                location=vuln.get("location", {
                    "file": context["original_context"].file_path,
                    "line": 1,
                    "column": 0
                }),
                code_snippet=vuln.get("code_snippet", context["original_context"].code_content[:200]),
                fix_suggestion=vuln.get("fix_suggestion", ""),
                explanation=vuln.get("explanation", ""),
                references=vuln.get("references", []),
                exploit_scenario=vuln.get("exploit_scenario", "")
            )
            findings.append(finding)

        return SecurityAnalysisResult(
            findings=findings,
            risk_score=final_result.get("risk_score", 0.0),
            summary=final_result.get("summary", "No vulnerabilities found"),
            recommendations=final_result.get("recommendations", []),
            metadata={
                "agent_analysis": {
                    "context_analysis": context["analysis_result"],
                    "semantic_analysis": context["semantic_result"],
                    "risk_analysis": context["risk_result"],
                    "validation_analysis": context["validation_result"],
                    "attack_chain_analysis": context["attack_chain_result"],
                    "adversarial_analysis": context["adversarial_result"]
                }
            }
        )

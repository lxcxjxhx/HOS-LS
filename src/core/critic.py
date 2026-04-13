"""执行批评器模块

核心功能：
- 检查执行结果是否合理
- 识别信息缺失和执行错误
- 决定是否需要重新规划
- 生成修正计划

实现反馈闭环：result → critic LLM → correction plan
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class ExecutionResult:
    """执行结果"""
    success: bool
    output: Any
    error: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = field(default_factory=dict)
    context: Optional[Dict[str, Any]] = field(default_factory=dict)


@dataclass
class CorrectionPlan:
    """修正计划"""
    need_replan: bool
   修正_actions: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    explanation: str = ""


class ExecutionCritic:
    """执行批评器"""
    
    def __init__(self, ai_client=None):
        self.ai_client = ai_client
    
    def analyze(self, result: ExecutionResult, original_plan: Optional[Dict[str, Any]] = None) -> CorrectionPlan:
        """分析执行结果
        
        Args:
            result: 执行结果
            original_plan: 原始计划
            
        Returns:
            修正计划
        """
        # 1. 基础检查
        if not result.success:
            return self._handle_failure(result, original_plan)
        
        # 2. 结果合理性检查
        if not self._is_result_reasonable(result):
            return self._generate_correction_plan(result, original_plan)
        
        # 3. 信息完整性检查
        missing_info = self._identify_missing_information(result)
        if missing_info:
            return self._handle_missing_info(result, original_plan, missing_info)
        
        # 4. 执行质量评估
        quality_score = self._evaluate_execution_quality(result)
        if quality_score < 0.7:
            return self._improve_execution(result, original_plan, quality_score)
        
        # 5. 正常完成
        return CorrectionPlan(
            need_replan=False,
            修正_actions=[],
            confidence=1.0,
            explanation="执行成功，结果合理"
        )
    
    def _handle_failure(self, result: ExecutionResult, original_plan: Optional[Dict[str, Any]]) -> CorrectionPlan:
        """处理执行失败"""
        修正_actions = []
        
        if result.error:
            # 分析错误类型
            if "token budget" in result.error.lower():
                修正_actions.append({
                    "type": "reduce_token_usage",
                    "description": "减少 token 使用，优化 prompt"
                })
            elif "timeout" in result.error.lower():
                修正_actions.append({
                    "type": "increase_timeout",
                    "description": "增加超时时间"
                })
            elif "permission" in result.error.lower():
                修正_actions.append({
                    "type": "check_permissions",
                    "description": "检查权限设置"
                })
        
        return CorrectionPlan(
            need_replan=True,
            修正_actions=修正_actions,
            confidence=0.8,
            explanation=f"执行失败: {result.error}"
        )
    
    def _is_result_reasonable(self, result: ExecutionResult) -> bool:
        """检查结果是否合理"""
        # 基于结果类型的合理性检查
        if isinstance(result.output, dict):
            # 检查必要字段
            if "findings" in result.output:
                findings = result.output["findings"]
                if isinstance(findings, list) and len(findings) > 1000:
                    return False  # 结果数量异常
        
        # 检查执行时间
        if "execution_time" in result.metrics:
            exec_time = result.metrics["execution_time"]
            if exec_time > 3600:  # 超过1小时
                return False
        
        return True
    
    def _identify_missing_information(self, result: ExecutionResult) -> List[str]:
        """识别缺失的信息"""
        missing = []
        
        if isinstance(result.output, dict):
            # 检查扫描结果的完整性
            if "findings" not in result.output:
                missing.append("扫描结果")
            if "summary" not in result.output:
                missing.append("扫描摘要")
            if "metrics" not in result.output:
                missing.append("执行指标")
        
        return missing
    
    def _handle_missing_info(self, result: ExecutionResult, original_plan: Optional[Dict[str, Any]], missing_info: List[str]) -> CorrectionPlan:
        """处理缺失信息"""
        修正_actions = [{
            "type": "补充信息",
            "description": f"补充缺失的信息: {', '.join(missing_info)}"
        }]
        
        return CorrectionPlan(
            need_replan=True,
            修正_actions=修正_actions,
            confidence=0.7,
            explanation=f"缺少必要信息: {', '.join(missing_info)}"
        )
    
    def _evaluate_execution_quality(self, result: ExecutionResult) -> float:
        """评估执行质量"""
        score = 1.0
        
        # 基于执行时间的评分
        if "execution_time" in result.metrics:
            exec_time = result.metrics["execution_time"]
            if exec_time > 600:  # 超过10分钟
                score -= 0.2
            elif exec_time > 300:  # 超过5分钟
                score -= 0.1
        
        # 基于结果完整性的评分
        if isinstance(result.output, dict):
            if "findings" in result.output:
                findings = result.output["findings"]
                if isinstance(findings, list) and len(findings) == 0:
                    score -= 0.3  # 没有发现结果
        
        return max(0.0, min(1.0, score))
    
    def _improve_execution(self, result: ExecutionResult, original_plan: Optional[Dict[str, Any]], quality_score: float) -> CorrectionPlan:
        """改进执行质量"""
        修正_actions = []
        
        if quality_score < 0.5:
            修正_actions.append({
                "type": "重新执行",
                "description": "执行质量过低，需要重新执行"
            })
        else:
            修正_actions.append({
                "type": "优化执行",
                "description": "优化执行参数，提高质量"
            })
        
        return CorrectionPlan(
            need_replan=True,
            修正_actions=修正_actions,
            confidence=0.6,
            explanation=f"执行质量评分: {quality_score:.2f}"
        )
    
    def _generate_correction_plan(self, result: ExecutionResult, original_plan: Optional[Dict[str, Any]]) -> CorrectionPlan:
        """生成修正计划"""
        修正_actions = [{
            "type": "重新规划",
            "description": "执行结果不合理，需要重新规划"
        }]
        
        return CorrectionPlan(
            need_replan=True,
            修正_actions=修正_actions,
            confidence=0.7,
            explanation="执行结果不合理"
        )


class AICritic:
    """基于AI的执行批评器"""
    
    def __init__(self, ai_client):
        self.ai_client = ai_client
        self.base_critic = ExecutionCritic()
    
    async def analyze(self, result: ExecutionResult, original_plan: Optional[Dict[str, Any]] = None) -> CorrectionPlan:
        """使用AI分析执行结果"""
        # 先使用基础批评器进行分析
        base_plan = self.base_critic.analyze(result, original_plan)
        
        # 如果需要更深入的分析，使用AI
        if base_plan.need_replan or base_plan.confidence < 0.8:
            return await self._ai_enhanced_analysis(result, original_plan, base_plan)
        
        return base_plan
    
    async def _ai_enhanced_analysis(self, result: ExecutionResult, original_plan: Optional[Dict[str, Any]], base_plan: CorrectionPlan) -> CorrectionPlan:
        """AI增强的分析"""
        if not self.ai_client:
            return base_plan
        
        try:
            from src.ai.models import AIRequest
            
            prompt = f"""你是一个执行批评器，负责分析AI系统的执行结果并提供修正建议。
            
            执行结果：
            {result}
            
            原始计划：
            {original_plan}
            
            基础分析结果：
            {base_plan}
            
            请分析以下内容：
            1. 执行结果是否合理
            2. 是否存在信息缺失
            3. 是否需要重新规划
            4. 提供具体的修正建议
            
            请返回JSON格式：
            {{
              "need_replan": true/false,
              "修正_actions": [
                {{
                  "type": "action_type",
                  "description": "action_description"
                }}
              ],
              "confidence": 0.0-1.0,
              "explanation": "详细说明"
            }}
            """
            
            request = AIRequest(
                prompt=prompt,
                system_prompt="你是一个专业的执行批评器，擅长分析AI系统的执行结果并提供精确的修正建议。",
                max_tokens=500,
                temperature=0.1
            )
            
            response = await self.ai_client.generate(request)
            ai_result = self._parse_ai_response(response.content)
            
            return CorrectionPlan(
                need_replan=ai_result.get("need_replan", base_plan.need_replan),
                修正_actions=ai_result.get("修正_actions", base_plan.修正_actions),
                confidence=ai_result.get("confidence", base_plan.confidence),
                explanation=ai_result.get("explanation", base_plan.explanation)
            )
            
        except Exception as e:
            # 回退到基础分析
            return base_plan
    
    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """解析AI响应"""
        import json
        
        content = content.strip()
        
        # 尝试直接解析
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # 提取JSON部分
        import re
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
                
        return {}


class CriticManager:
    """批评器管理器"""
    
    def __init__(self, ai_client=None):
        self.ai_client = ai_client
        self.critic = AICritic(ai_client) if ai_client else ExecutionCritic()
    
    async def analyze_execution(self, result: ExecutionResult, original_plan: Optional[Dict[str, Any]] = None) -> CorrectionPlan:
        """分析执行结果并生成修正计划"""
        if hasattr(self.critic, 'analyze') and callable(self.critic.analyze):
            if asyncio.iscoroutinefunction(self.critic.analyze):
                return await self.critic.analyze(result, original_plan)
            else:
                return self.critic.analyze(result, original_plan)
        return CorrectionPlan(need_replan=False, confidence=0.0)


# 异步支持
import asyncio
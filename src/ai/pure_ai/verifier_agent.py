"""证伪员Agent (Verifier Agent)

基于Agent 3 (漏洞验证) + Agent 5 (对抗验证)改造，
负责反事实验证：回退补丁后路径是否消失。
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.dep.counterfactual import (
    CounterfactualVerifier, 
    VerificationResult, 
    VerificationStatus,
    VerificationEvidence,
)
from src.dep.differ import SuspiciousPath
from src.sal.path_explorer import CandidatePath


@dataclass
class VerifierOutput:
    """证伪员输出"""
    verification_results: List[VerificationResult] = field(default_factory=list)
    confirmed_vulnerabilities: List[VerificationResult] = field(default_factory=list)
    rejected_findings: List[VerificationResult] = field(default_factory=list)
    uncertain_findings: List[VerificationResult] = field(default_factory=dict)
    token_usage: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "verification_results": [r.to_dict() for r in self.verification_results],
            "confirmed_vulnerabilities": [r.to_dict() for r in self.confirmed_vulnerabilities],
            "rejected_findings": [r.to_dict() for r in self.rejected_findings],
            "uncertain_findings": [r.to_dict() for r in self.uncertain_findings],
            "token_usage": self.token_usage,
            "metadata": self.metadata,
        }


class VerifierAgent:
    """证伪员Agent
    
    结合Agent 3的验证逻辑和Agent 5的对抗逻辑，
    进行反事实验证。
    
    验证流程：
    1. 对每个SuspiciousPath进行反事实验证
    2. 使用Agent 3的验证逻辑检查路径可达性
    3. 使用Agent 5的对抗逻辑进行确认/拒绝
    4. 只有通过验证的才输出为确认漏洞
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.counterfactual_verifier = CounterfactualVerifier()
    
    async def verify(
        self,
        suspicious_paths: List[SuspiciousPath],
        r_before: str,
        r_after: str,
        delta_ai: str,
        modified_funcs: List[str],
        task_desc: str = "",
    ) -> VerifierOutput:
        """验证可疑路径
        
        Args:
            suspicious_paths: 可疑路径列表
            r_before: 改前仓库路径
            r_after: 改后仓库路径
            delta_ai: AI生成的补丁
            modified_funcs: 修改的函数列表
            task_desc: 任务描述
            
        Returns:
            验证输出
        """
        verification_results = []
        
        # 对每个可疑路径进行反事实验证
        for suspicious_path in suspicious_paths:
            result = self.counterfactual_verifier.verify(
                suspicious_path=suspicious_path,
                r_before=r_before,
                r_after=r_after,
                delta_ai=delta_ai,
                modified_funcs=modified_funcs,
            )
            verification_results.append(result)
        
        # 使用LLM增强验证（可选）
        if self.llm_client and task_desc:
            enhanced_results = await self._llm_enhance_verification(
                verification_results, task_desc, delta_ai
            )
            verification_results = enhanced_results
        
        # 分类结果
        confirmed = [r for r in verification_results 
                    if r.status == VerificationStatus.CONFIRMED]
        rejected = [r for r in verification_results 
                   if r.status == VerificationStatus.REJECTED]
        uncertain = [r for r in verification_results 
                    if r.status == VerificationStatus.UNCERTAIN]
        
        return VerifierOutput(
            verification_results=verification_results,
            confirmed_vulnerabilities=confirmed,
            rejected_findings=rejected,
            uncertain_findings=uncertain,
            metadata={
                "r_before": r_before,
                "r_after": r_after,
                "modified_funcs": modified_funcs,
                "task_desc": task_desc,
                "total_suspicious": len(suspicious_paths),
                "confirmed_count": len(confirmed),
                "rejected_count": len(rejected),
                "uncertain_count": len(uncertain),
            }
        )
    
    async def _llm_enhance_verification(
        self,
        results: List[VerificationResult],
        task_desc: str,
        delta_ai: str,
    ) -> List[VerificationResult]:
        """使用LLM增强验证"""
        if not self.llm_client:
            return results
        
        # 构建prompt
        prompt = self._build_verification_prompt(results, task_desc, delta_ai)
        
        try:
            # 调用LLM
            response = await self.llm_client.generate(prompt)
            
            # 解析LLM响应
            enhanced = self._parse_llm_response(response, results)
            
            return enhanced
        except Exception as e:
            # LLM调用失败，返回原始结果
            return results
    
    def _build_verification_prompt(
        self,
        results: List[VerificationResult],
        task_desc: str,
        delta_ai: str,
    ) -> str:
        """构建LLM增强prompt"""
        results_desc = "\n".join([
            f"- 状态: {r.status.value}, 路径: {r.suspicious_path.path.entry_point} -> {r.suspicious_path.path.sink}"
            for r in results[:10]
        ])
        
        return f"""你是一个安全验证专家。请验证以下漏洞检测结果的准确性。

## 任务描述
{task_desc}

## AI生成的补丁
```diff
{delta_ai[:2000]}
```

## 验证结果
{results_desc}

## 验证要求
1. 确认每个漏洞的真实性
2. 检查是否有误报
3. 评估漏洞的严重性
4. 提供修复建议

## 输出格式
请以JSON格式输出，包含：
- "confirmed": 确认的漏洞列表
- "rejected": 拒绝的误报列表
- "uncertain": 需要人工复核的列表
- "fix_suggestions": 修复建议
"""
    
    def _parse_llm_response(
        self, response: str, original_results: List[VerificationResult]
    ) -> List[VerificationResult]:
        """解析LLM响应"""
        try:
            result = json.loads(response)
            
            # LLM可能标记某些结果为误报
            rejected_by_llm = result.get("rejected", [])
            
            # 更新结果状态
            for r in original_results:
                # 检查是否被LLM标记为误报
                for rejected in rejected_by_llm:
                    if isinstance(rejected, dict):
                        # 匹配逻辑需要更精确
                        pass
            
            return original_results
        except Exception:
            return original_results
    
    def generate_final_report(
        self, verifier_output: VerifierOutput
    ) -> Dict[str, Any]:
        """生成最终报告"""
        confirmed = verifier_output.confirmed_vulnerabilities
        
        if not confirmed:
            return {
                "vulnerability_found": False,
                "critical_path": None,
                "verification_evidence": None,
                "confidence": 0.0,
                "summary": "未发现AI补丁引入的漏洞",
            }
        
        # 取置信度最高的确认漏洞
        best_result = max(confirmed, key=lambda r: r.confidence)
        
        return {
            "vulnerability_found": True,
            "critical_path": {
                "entry_point": best_result.suspicious_path.path.entry_point,
                "sink": best_result.suspicious_path.path.sink,
                "call_chain": best_result.suspicious_path.path.call_chain,
                "modified_functions": best_result.suspicious_path.path.modified_functions,
                "files_involved": best_result.suspicious_path.path.files_involved,
            },
            "verification_evidence": best_result.evidence.to_dict(),
            "confidence": best_result.confidence,
            "summary": best_result.description,
            "all_confirmed": [r.to_dict() for r in confirmed],
            "rejected_count": len(verifier_output.rejected_findings),
            "uncertain_count": len(verifier_output.uncertain_findings),
        }

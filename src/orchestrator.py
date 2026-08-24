"""主控协调器 (Orchestrator)

协调定位员、差分员、证伪员三个Agent，完成差分漏洞验证。
"""

import json
import os
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from src.ai.pure_ai.locator_agent import LocatorAgent, LocatorResult
from src.ai.pure_ai.differ_agent import DifferAgent, DifferResult
from src.ai.pure_ai.verifier_agent import VerifierAgent, VerifierOutput
from src.dep.differ import SuspiciousPath
from src.dep.counterfactual import VerificationResult, VerificationStatus
from src.sal.sink_registry import SinkRegistry
from src.sal.path_explorer import SALExplorer, CandidatePath


class LLMClient:
    """LLM客户端封装
    
    封装OpenAI兼容API调用，支持DeepSeek/MiMo等提供商。
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "mimo-v2.5-pro",
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY") or os.getenv("HOS_LS_AI_API_KEY")
        self.base_url = base_url or "https://token-plan-cn.xiaomimimo.com/v1"
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._client = None
    
    def _get_client(self):
        """获取OpenAI客户端"""
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                )
            except ImportError:
                raise ImportError("openai package is required. Install with: pip install openai")
        return self._client
    
    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        """生成响应"""
        client = self._get_client()
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = await asyncio.to_thread(
                client.chat.completions.create,
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"LLM generation failed: {e}")
    
    def generate_sync(self, prompt: str, system_prompt: str = "") -> str:
        """同步生成响应"""
        client = self._get_client()
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"LLM generation failed: {e}")


class AnalysisMode(str, Enum):
    """分析模式枚举"""
    FULL = "full"  # 完整分析（三个Agent）
    LOCATOR_ONLY = "locator_only"  # 只运行定位员
    DIFFER_ONLY = "differ_only"  # 只运行差分员
    VERIFIER_ONLY = "verifier_only"  # 只运行证伪员
    LOCATOR_DIFFER = "locator_differ"  # 定位员+差分员


@dataclass
class PatchTriplet:
    """输入三元组"""
    r_before: str  # 原始仓库路径
    task_desc: str  # 自然语言修改需求
    delta_ai: str  # AI生成的Unified Diff
    sample_id: str = ""  # 样本标识
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    language: str = "python"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "r_before": self.r_before,
            "task_desc": self.task_desc,
            "delta_ai": self.delta_ai,
            "sample_id": self.sample_id,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "language": self.language,
        }


@dataclass
class VerificationReport:
    """验证报告"""
    vulnerability_found: bool = False
    critical_path: Optional[Dict[str, Any]] = None
    verification_evidence: Optional[Dict[str, Any]] = None
    confidence: float = 0.0
    summary: str = ""
    locator_result: Optional[LocatorResult] = None
    differ_result: Optional[DifferResult] = None
    verifier_output: Optional[VerifierOutput] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_found": self.vulnerability_found,
            "critical_path": self.critical_path,
            "verification_evidence": self.verification_evidence,
            "confidence": self.confidence,
            "summary": self.summary,
            "locator_result": self.locator_result.to_dict() if self.locator_result else None,
            "differ_result": self.differ_result.to_dict() if self.differ_result else None,
            "verifier_output": self.verifier_output.to_dict() if self.verifier_output else None,
            "metadata": self.metadata,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class CacheManager:
    """缓存管理器
    
    缓存分析结果，避免重复计算。
    """
    
    def __init__(self, max_size: int = 1000):
        self._cache: Dict[str, Any] = {}
        self._max_size = max_size
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存"""
        if key in self._cache:
            self._hits += 1
            return self._cache[key]
        self._misses += 1
        return None
    
    def set(self, key: str, value: Any):
        """设置缓存"""
        if len(self._cache) >= self._max_size:
            # 简单的LRU：删除第一个
            first_key = next(iter(self._cache))
            del self._cache[first_key]
        self._cache[key] = value
    
    def clear(self):
        """清空缓存"""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
    
    def stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / total if total > 0 else 0.0,
        }


class Orchestrator:
    """主控协调器
    
    协调定位员、差分员、证伪员三个Agent，完成差分漏洞验证。
    
    流程：
    1. 定位员：从Modified_Funcs出发，找到到Sink的路径
    2. 差分员：对比改前改后路径，标记Suspicious
    3. 证伪员：反事实验证，确认漏洞
    
    性能优化：
    - 并行扫描：多个样本并行处理
    - 结果缓存：避免重复计算
    """
    
    def __init__(
        self,
        llm_client=None,
        sink_registry: Optional[SinkRegistry] = None,
        mode: AnalysisMode = AnalysisMode.FULL,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "deepseek-v4-flash",
        enable_cache: bool = True,
        max_workers: int = 4,
    ):
        # 初始化LLM客户端
        if llm_client is None:
            self.llm_client = LLMClient(
                api_key=api_key,
                base_url=base_url,
                model=model,
            )
        else:
            self.llm_client = llm_client
        
        self.sink_registry = sink_registry or SinkRegistry()
        self.mode = mode
        self.max_workers = max_workers
        
        # 初始化缓存
        self.cache = CacheManager() if enable_cache else None
        
        # 初始化三个Agent
        self.locator = LocatorAgent(
            llm_client=self.llm_client,
            sink_registry=self.sink_registry,
        )
        self.differ = DifferAgent(llm_client=self.llm_client)
        self.verifier = VerifierAgent(llm_client=self.llm_client)
    
    async def analyze(
        self,
        triplet: PatchTriplet,
        modified_funcs: Optional[List[str]] = None,
    ) -> VerificationReport:
        """分析AI补丁
        
        Args:
            triplet: 输入三元组
            modified_funcs: 修改的函数列表（如果为None则自动检测）
            
        Returns:
            验证报告
        """
        # 检查缓存
        if self.cache:
            cache_key = self._get_cache_key(triplet)
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
        
        start_time = time.time()
        
        # 自动检测修改的函数（如果未提供）
        if modified_funcs is None:
            modified_funcs = self._detect_modified_functions(triplet.delta_ai)
        
        # 准备改后版本
        r_after = self._prepare_r_after(triplet.r_before, triplet.delta_ai)
        
        # 使用LLM直接分析diff（简化流程，无需tree-sitter）
        analysis_result = await self._llm_analyze_diff(triplet)
        
        # 根据模式运行不同的Agent组合
        locator_result = None
        differ_result = None
        verifier_output = None
        
        if self.mode in [AnalysisMode.FULL, AnalysisMode.LOCATOR_ONLY, 
                        AnalysisMode.LOCATOR_DIFFER]:
            # Step 1: 定位员
            locator_result = await self.locator.locate_paths(
                modified_funcs=modified_funcs,
                r_before=triplet.r_before,
                r_after=r_after,
                delta_ai=triplet.delta_ai,
                task_desc=triplet.task_desc,
                language=triplet.language,
            )
        
        if self.mode in [AnalysisMode.FULL, AnalysisMode.DIFFER_ONLY,
                        AnalysisMode.LOCATOR_DIFFER]:
            # Step 2: 差分员
            if locator_result:
                paths_before = []
                paths_after = locator_result.candidate_paths
                
                differ_result = await self.differ.diff_paths(
                    paths_before=paths_before,
                    paths_after=paths_after,
                    modified_funcs=modified_funcs,
                    r_before=triplet.r_before,
                    r_after=r_after,
                    delta_ai=triplet.delta_ai,
                    task_desc=triplet.task_desc,
                )
        
        if self.mode in [AnalysisMode.FULL, AnalysisMode.VERIFIER_ONLY]:
            # Step 3: 证伪员
            if differ_result and differ_result.suspicious_paths:
                verifier_output = await self.verifier.verify(
                    suspicious_paths=differ_result.suspicious_paths,
                    r_before=triplet.r_before,
                    r_after=r_after,
                    delta_ai=triplet.delta_ai,
                    modified_funcs=modified_funcs,
                    task_desc=triplet.task_desc,
                )
        
        # 生成最终报告（使用LLM分析结果）
        report = self._generate_report_with_llm(
            triplet=triplet,
            locator_result=locator_result,
            differ_result=differ_result,
            verifier_output=verifier_output,
            modified_funcs=modified_funcs,
            r_after=r_after,
            elapsed=time.time() - start_time,
            llm_analysis=analysis_result,
        )
        
        return report
    
    async def _llm_analyze_diff(self, triplet: PatchTriplet) -> Dict[str, Any]:
        """使用LLM直接分析diff"""
        if not self.llm_client:
            return {"vulnerability_found": False, "confidence": 0.0}
        
        prompt = f"""You are a security expert. Analyze the following code patch for security vulnerabilities.

Task: {triplet.task_desc}

Patch:
```diff
{triplet.delta_ai}
```

Analyze if this patch introduces any security vulnerabilities. Consider:
1. SQL Injection
2. Command Injection
3. Path Traversal
4. XSS
5. SSRF
6. Authentication Bypass

Respond in JSON format:
{{
    "vulnerability_found": true/false,
    "vulnerability_type": "type if found",
    "confidence": 0.0-1.0,
    "explanation": "brief explanation"
}}"""
        
        try:
            response = await self.llm_client.generate(prompt)
            # Try to parse JSON from response
            import json
            # Find JSON in response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
            return {"vulnerability_found": False, "confidence": 0.0, "raw_response": response}
        except Exception as e:
            return {"vulnerability_found": False, "confidence": 0.0, "error": str(e)}
    
    def _detect_modified_functions(self, delta_ai: str) -> List[str]:
        """从diff中检测修改的函数"""
        modified = []
        
        # 简单的启发式检测
        lines = delta_ai.split("\n")
        current_file = None
        
        for line in lines:
            # 检测文件名
            if line.startswith("+++") or line.startswith("---"):
                if "b/" in line:
                    current_file = line.split("b/")[-1]
                elif "a/" in line:
                    current_file = line.split("a/")[-1]
            
            # 检测函数定义
            if current_file and ("def " in line or "function " in line or 
                               "class " in line or "public " in line):
                # 提取函数名
                if "def " in line:
                    func_name = line.split("def ")[1].split("(")[0].strip()
                    modified.append(f"{current_file}:{func_name}")
                elif "function " in line:
                    func_name = line.split("function ")[1].split("(")[0].strip()
                    modified.append(f"{current_file}:{func_name}")
        
        return modified if modified else ["unknown:unknown"]
    
    def _prepare_r_after(self, r_before: str, delta_ai: str) -> str:
        """准备改后版本
        
        应用补丁到改前版本，生成改后版本。
        """
        # TODO: 实现补丁应用逻辑
        # 暂时返回改前路径，实际需要应用补丁
        return r_before
    
    def _generate_report(
        self,
        triplet: PatchTriplet,
        locator_result: Optional[LocatorResult],
        differ_result: Optional[DifferResult],
        verifier_output: Optional[VerifierOutput],
        modified_funcs: List[str],
        r_after: str,
        elapsed: float,
    ) -> VerificationReport:
        """生成验证报告"""
        # 如果有验证结果，使用验证器的报告
        if verifier_output:
            final_report = self.verifier.generate_final_report(verifier_output)
            report = VerificationReport(
                vulnerability_found=final_report["vulnerability_found"],
                critical_path=final_report.get("critical_path"),
                verification_evidence=final_report.get("verification_evidence"),
                confidence=final_report.get("confidence", 0.0),
                summary=final_report.get("summary", ""),
                locator_result=locator_result,
                differ_result=differ_result,
                verifier_output=verifier_output,
                metadata={
                    "sample_id": triplet.sample_id,
                    "cve_ids": triplet.cve_ids,
                    "cwe_ids": triplet.cwe_ids,
                    "modified_funcs": modified_funcs,
                    "elapsed_seconds": elapsed,
                    "mode": self.mode.value,
                }
            )
        else:
            # 否则返回部分结果
            report = VerificationReport(
                vulnerability_found=False,
                summary="分析未完成，缺少验证结果",
                locator_result=locator_result,
                differ_result=differ_result,
                metadata={
                    "sample_id": triplet.sample_id,
                    "elapsed_seconds": elapsed,
                    "mode": self.mode.value,
                }
            )
        
        # 缓存结果
        if self.cache:
            cache_key = self._get_cache_key(triplet)
            self.cache.set(cache_key, report)
        
        return report
    
    def _generate_report_with_llm(
        self,
        triplet: PatchTriplet,
        locator_result: Optional[LocatorResult],
        differ_result: Optional[DifferResult],
        verifier_output: Optional[VerifierOutput],
        modified_funcs: List[str],
        r_after: str,
        elapsed: float,
        llm_analysis: Dict[str, Any],
    ) -> VerificationReport:
        """使用LLM分析结果生成验证报告"""
        # 如果有验证结果，使用验证器的报告
        if verifier_output:
            final_report = self.verifier.generate_final_report(verifier_output)
            report = VerificationReport(
                vulnerability_found=final_report["vulnerability_found"],
                critical_path=final_report.get("critical_path"),
                verification_evidence=final_report.get("verification_evidence"),
                confidence=final_report.get("confidence", 0.0),
                summary=final_report.get("summary", ""),
                locator_result=locator_result,
                differ_result=differ_result,
                verifier_output=verifier_output,
                metadata={
                    "sample_id": triplet.sample_id,
                    "cve_ids": triplet.cve_ids,
                    "cwe_ids": triplet.cwe_ids,
                    "modified_funcs": modified_funcs,
                    "elapsed_seconds": elapsed,
                    "mode": self.mode.value,
                }
            )
        else:
            # 使用LLM分析结果
            vuln_found = llm_analysis.get("vulnerability_found", False)
            confidence = llm_analysis.get("confidence", 0.0)
            explanation = llm_analysis.get("explanation", "")
            vuln_type = llm_analysis.get("vulnerability_type", "unknown")
            
            report = VerificationReport(
                vulnerability_found=vuln_found,
                confidence=confidence,
                summary=f"[LLM Analysis] {explanation}" if explanation else "LLM analysis completed",
                locator_result=locator_result,
                differ_result=differ_result,
                metadata={
                    "sample_id": triplet.sample_id,
                    "cve_ids": triplet.cve_ids,
                    "cwe_ids": triplet.cwe_ids,
                    "modified_funcs": modified_funcs,
                    "elapsed_seconds": elapsed,
                    "mode": self.mode.value,
                    "llm_analysis": llm_analysis,
                    "vulnerability_type": vuln_type,
                }
            )
        
        # 缓存结果
        if self.cache:
            cache_key = self._get_cache_key(triplet)
            self.cache.set(cache_key, report)
        
        return report
    
    async def analyze_batch(
        self,
        triplets: List[PatchTriplet],
        modified_funcs_list: Optional[List[List[str]]] = None,
    ) -> List[VerificationReport]:
        """批量分析AI补丁（并行处理）
        
        Args:
            triplets: 输入三元组列表
            modified_funcs_list: 修改的函数列表列表（可选）
            
        Returns:
            验证报告列表
        """
        if modified_funcs_list is None:
            modified_funcs_list = [None] * len(triplets)
        
        # 创建任务
        tasks = []
        for triplet, modified_funcs in zip(triplets, modified_funcs_list):
            tasks.append(self.analyze(triplet, modified_funcs))
        
        # 并行执行
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常
        reports = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # 创建错误报告
                reports.append(VerificationReport(
                    vulnerability_found=False,
                    summary=f"分析失败: {str(result)}",
                    metadata={
                        "sample_id": triplets[i].sample_id,
                        "error": str(result),
                    }
                ))
            else:
                reports.append(result)
        
        return reports
    
    def _get_cache_key(self, triplet: PatchTriplet) -> str:
        """生成缓存键"""
        # 使用sample_id和delta_ai的hash作为缓存键
        import hashlib
        content = f"{triplet.sample_id}:{triplet.delta_ai}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def set_mode(self, mode: AnalysisMode):
        """设置分析模式"""
        self.mode = mode
    
    def get_mode(self) -> AnalysisMode:
        """获取当前分析模式"""
        return self.mode
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        if self.cache:
            return self.cache.stats()
        return {"enabled": False}
    
    def clear_cache(self):
        """清空缓存"""
        if self.cache:
            self.cache.clear()

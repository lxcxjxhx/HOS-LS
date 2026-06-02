from dataclasses import dataclass
from typing import Optional, Dict, Any, List


@dataclass
class VerificationResult:
    is_exploitable: bool
    confidence: float
    test_case: Optional[str]
    analysis: str


class DynamicAgent:
    DYNAMIC_ANALYSIS_PROMPT = """你是一个专业的安全测试工程师，负责生成针对特定漏洞类型的动态测试用例。

## 漏洞类型
{vuln_type}

## 待测试代码片段
```{language}
{code}
```

## 上下文信息
{context}

## 测试用例生成要求
1. 生成的测试用例必须能够触发目标漏洞
2. 测试用例应该是可执行的，并产生明确的输出结果
3. 测试用例应该包含攻击Payload和预期的良性输入
4. 考虑边界情况和异常输入
5. 确保测试用例的安全性，不要包含恶意代码

## 输出格式要求
请以JSON格式输出，结构如下：
{{
    "test_cases": [
        {{
            "name": "测试用例名称",
            "payload": "测试Payload",
            "description": "测试用例描述",
            "expected_behavior": "预期行为描述",
            "is_attack": true/false
        }}
    ],
    "analysis": "对漏洞和测试策略的分析说明"
}}

请生成合适的测试用例："""

    def __init__(self, llm_client):
        self.llm_client = llm_client

    def generate_test_case(
        self,
        code: str,
        language: str,
        vuln_type: str,
        context: str
    ) -> Dict[str, Any]:
        prompt = self.DYNAMIC_ANALYSIS_PROMPT.format(
            vuln_type=vuln_type,
            code=code,
            language=language,
            context=context
        )
        response = self.llm_client.complete(prompt)
        import json
        try:
            result = json.loads(response)
            return result
        except json.JSONDecodeError:
            return {
                "test_cases": [],
                "analysis": f"Failed to parse LLM response: {response}"
            }

    def analyze_result(
        self,
        execution_result: str,
        expected_result: str
    ) -> str:
        analysis_prompt = f"""分析以下动态验证执行结果：

执行结果:
{execution_result}

预期结果:
{expected_result}

请判断：
1. 漏洞是否被成功触发
2. 执行结果是否符合预期
3. 给出简要的分析说明

请以简洁的文本形式回答。"""

        response = self.llm_client.complete(analysis_prompt)
        return response

    def calculate_confidence(
        self,
        static_confidence: float,
        dynamic_result: Dict[str, Any]
    ) -> float:
        base_weight = 0.4
        dynamic_weight = 0.6

        exploitability_score = 0.0
        if dynamic_result.get("exploited", False):
            exploitability_score = 1.0
        elif dynamic_result.get("uncertain", False):
            exploitability_score = 0.5
        else:
            exploitability_score = 0.2

        combined = (
            static_confidence * base_weight +
            exploitability_score * dynamic_weight
        )

        return min(1.0, max(0.0, combined))


class DynamicVerificationPipeline:
    def __init__(self, llm_client, dynamic_analyzer):
        self.dynamic_agent = DynamicAgent(llm_client)
        self.dynamic_analyzer = dynamic_analyzer

    def verify(
        self,
        code: str,
        language: str,
        vuln_type: str,
        context: str
    ) -> VerificationResult:
        test_case_result = self.dynamic_agent.generate_test_case(
            code=code,
            language=language,
            vuln_type=vuln_type,
            context=context
        )

        test_cases = test_case_result.get("test_cases", [])
        if not test_cases:
            return VerificationResult(
                is_exploitable=False,
                confidence=0.0,
                test_case=None,
                analysis="No test cases generated"
            )

        primary_test = test_cases[0]
        test_case_str = primary_test.get("payload", "")

        execution_result = self.dynamic_analyzer.analyze(
            code=code,
            language=language,
            test_case=test_case_str
        )

        expected = primary_test.get("expected_behavior", "")
        analysis = self.dynamic_agent.analyze_result(
            execution_result=str(execution_result),
            expected_result=expected
        )

        is_exploitable = "triggered" in analysis.lower() or "exploited" in analysis.lower()
        if "not" in analysis.lower() and "exploitable" in analysis.lower():
            is_exploitable = False

        confidence = self.dynamic_agent.calculate_confidence(
            static_confidence=0.5,
            dynamic_result={"exploited": is_exploitable}
        )

        return VerificationResult(
            is_exploitable=is_exploitable,
            confidence=confidence,
            test_case=test_case_str,
            analysis=analysis
        )

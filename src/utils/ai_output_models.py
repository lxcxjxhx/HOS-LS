#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI输出协议模型

定义AI输出的标准JSON格式，确保100%可解析
"""

from typing import Optional
from pydantic import BaseModel, Field, validator


class AIFindingAnalysis(BaseModel):
    """AI发现分析输出模型 - 严格协议"""
    
    is_false_positive: bool = Field(
        ...,
        description="是否是误报",
        example=False
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="置信度分数 0-10",
        example=8.5
    )
    justification: str = Field(
        ...,
        min_length=1,
        description="判断理由",
        example="代码使用了参数化查询，不存在SQL注入风险"
    )
    exclusion_reason: Optional[str] = Field(
        default=None,
        description="如果是误报，排除原因",
        example="使用了参数化查询"
    )
    
    @validator('confidence_score')
    def validate_confidence(cls, v):
        if not 0 <= v <= 10:
            raise ValueError('confidence_score必须在0-10之间')
        return v
    
    @validator('justification')
    def validate_justification(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('justification不能为空')
        return v.strip()


class AIVulnerabilityAnalysis(BaseModel):
    """AI漏洞分析输出模型"""
    
    vulnerable: bool = Field(
        ...,
        description="是否存在漏洞"
    )
    type: str = Field(
        ...,
        min_length=1,
        description="漏洞类型"
    )
    severity: str = Field(
        default="medium",
        description="严重程度: low/medium/high/critical"
    )
    attack_path: str = Field(
        default="",
        description="攻击路径"
    )
    exploit: str = Field(
        default="",
        description="可利用方式"
    )
    fix: str = Field(
        default="",
        description="修复建议"
    )
    confidence: float = Field(
        default=5.0,
        ge=0.0,
        le=10.0,
        description="置信度 0-10"
    )


class AIAttackChain(BaseModel):
    """AI攻击链分析输出模型"""
    
    chain: list[str] = Field(
        default_factory=list,
        description="攻击链步骤"
    )
    risk: str = Field(
        default="low",
        description="风险等级: low/medium/high"
    )
    steps: list[str] = Field(
        default_factory=list,
        description="攻击步骤"
    )


class AIAttackChainAnalysis(BaseModel):
    """AI攻击链分析完整输出"""
    
    attack_chains: list[AIAttackChain] = Field(
        default_factory=list,
        description="攻击链列表"
    )


class AIFilterResult(BaseModel):
    """AI过滤结果模型"""
    
    keep_finding: bool = Field(
        ...,
        description="是否保留发现"
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="置信度分数"
    )
    justification: str = Field(
        ...,
        min_length=1,
        description="判断理由"
    )
    exclusion_reason: Optional[str] = Field(
        default=None,
        description="排除原因"
    )


# 强制JSON格式模板
AI_FILTER_PROMPT_TEMPLATE = """你是一个专业的安全分析师，负责评估安全扫描发现的误报可能性。

请分析以下安全发现，判断它是否是误报：

文件: {file_path}
行号: {line_number}
问题: {issue}
严重程度: {severity}
详情: {details}
代码片段: {code_snippet}
{context_str}
{custom_instructions_str}

评估标准：
1. 这个问题是否真实存在？
2. 它是否构成真正的安全风险？
3. 它是否可能是误报或低影响问题？
4. 基于代码片段和上下文，这个问题的可信度如何？

【重要】你必须只返回以下JSON格式，不要添加任何其他内容：

{{
  "is_false_positive": true/false,
  "confidence_score": 0.0-10.0,
  "justification": "详细的判断理由",
  "exclusion_reason": "如果是误报，说明排除原因，否则为null"
}}

约束：
- is_false_positive: boolean类型，true表示是误报，false表示不是误报
- confidence_score: 数字类型，范围0.0-10.0
- justification: 字符串类型，不能为空
- exclusion_reason: 字符串类型或null
- 不要输出markdown代码块标记
- 不要输出任何解释性文本
"""


AI_VULNERABILITY_PROMPT_TEMPLATE = """你是高级安全审计专家，请分析以下代码是否存在{vulnerability_type}漏洞：

代码：
{code_context}

【重要】你必须只返回以下JSON格式，不要添加任何其他内容：

{{
  "vulnerable": true/false,
  "type": "漏洞类型",
  "severity": "low/medium/high/critical",
  "attack_path": "攻击路径描述",
  "exploit": "可利用方式描述",
  "fix": "修复建议",
  "confidence": 0.0-10.0
}}

约束：
- vulnerable: boolean类型
- type: 字符串类型
- severity: 必须是 "low", "medium", "high", 或 "critical"
- confidence: 数字类型，范围0.0-10.0
- 不要输出markdown代码块标记
- 不要输出任何解释性文本
"""


AI_ATTACK_CHAIN_PROMPT_TEMPLATE = """你是高级安全审计专家，请分析以下代码的攻击链：

代码：
{code_context}

入口点：
{entry_points}

危险调用：
{danger_calls}

【重要】你必须只返回以下JSON格式，不要添加任何其他内容：

{{
  "attack_chains": [
    {{
      "chain": ["步骤1", "步骤2", "步骤3"],
      "risk": "low/medium/high",
      "steps": ["详细步骤1", "详细步骤2"]
    }}
  ]
}}

约束：
- attack_chains: 数组类型
- chain: 字符串数组
- risk: 必须是 "low", "medium", 或 "high"
- steps: 字符串数组
- 不要输出markdown代码块标记
- 不要输出任何解释性文本
"""

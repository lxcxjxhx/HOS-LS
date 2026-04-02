#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
提示词管理模块

功能：
1. 管理和优化 AI 分析的提示词模板
2. 提供针对不同安全场景的专业提示词
3. 支持自定义提示词扩展
4. 优化提示词结构，提高 AI 分析准确性
"""

from typing import Dict, Any, List, Optional


class PromptManager:
    """提示词管理器"""
    
    def __init__(self):
        """初始化提示词管理器"""
        self._prompts = {
            "security_analysis": self._get_security_analysis_prompt(),
            "code_review": self._get_code_review_prompt(),
            "vulnerability_detection": self._get_vulnerability_detection_prompt(),
            "exploit_scenario": self._get_exploit_scenario_prompt(),
            "fix_recommendation": self._get_fix_recommendation_prompt(),
            "false_positive_filter": self._get_false_positive_filter_prompt()
        }
    
    def get_prompt(self, prompt_type: str, **kwargs) -> str:
        """获取指定类型的提示词
        
        Args:
            prompt_type: 提示词类型
            **kwargs: 提示词参数
            
        Returns:
            生成的提示词
        """
        if prompt_type not in self._prompts:
            raise ValueError(f"未知的提示词类型: {prompt_type}")
        
        prompt_template = self._prompts[prompt_type]
        return prompt_template.format(**kwargs)
    
    def _get_security_analysis_prompt(self) -> str:
        """获取安全分析提示词模板"""
        return """
你是一位专业的安全分析师，精通各种常见的安全漏洞和攻击技术。

请分析以下代码，识别其中可能存在的安全问题：

文件: {file_path}
行号: {line_number}
代码片段:
{code_snippet}

请按照以下格式输出分析结果：

1. 问题识别：
   - 详细描述发现的安全问题
   - 说明问题的严重程度（高/中/低）
   - 提供问题的置信度（0-10）

2. 技术分析：
   - 解释问题的技术原理
   - 分析可能的攻击场景
   - 评估漏洞的影响范围

3. 修复建议：
   - 提供具体的修复方案
   - 说明修复的技术原理
   - 给出最佳实践建议

4. 参考资料（如果有）：
   - 相关的 CVE 编号
   - 安全标准或规范
   - 相关的安全文档

请确保分析结果详细、准确，并提供专业的安全建议。
"""
    
    def _get_code_review_prompt(self) -> str:
        """获取代码审查提示词模板"""
        return """
你是一位资深的安全代码审查专家，专注于识别代码中的安全漏洞和隐患。

请对以下代码进行全面的安全审查：

文件: {file_path}
代码片段:
{code_snippet}

审查重点包括但不限于：
1. 输入验证和数据清理
2. 认证和授权机制
3. 加密和数据保护
4. 错误处理和日志记录
5. 会话管理
6. API 安全
7. 第三方依赖的安全问题
8. 业务逻辑漏洞

请按照以下格式输出审查结果：

1. 发现的问题：
   - 列出所有发现的安全问题
   - 对每个问题进行详细描述
   - 评估每个问题的严重程度

2. 风险分析：
   - 分析每个问题可能导致的安全风险
   - 评估风险的影响范围和可能性

3. 修复建议：
   - 为每个问题提供具体的修复方案
   - 说明修复的技术原理和最佳实践

4. 代码质量建议：
   - 提供提高代码安全性的建议
   - 推荐相关的安全编码标准

请确保审查结果全面、专业，并提供可操作的建议。
"""
    
    def _get_vulnerability_detection_prompt(self) -> str:
        """获取漏洞检测提示词模板"""
        return """
你是一位专业的漏洞检测专家，擅长识别各种类型的安全漏洞。

请分析以下代码，检测其中可能存在的安全漏洞：

文件: {file_path}
行号: {line_number}
代码片段:
{code_snippet}

请检测以下类型的漏洞：
1. SQL 注入
2. 跨站脚本 (XSS)
3. 命令注入
4. 路径遍历
5. 认证绕过
6. 授权问题
7. 敏感数据泄露
8. 不安全的反序列化
9. 跨站请求伪造 (CSRF)
10. 服务器端请求伪造 (SSRF)
11. 业务逻辑漏洞
12. 依赖组件漏洞

请按照以下格式输出检测结果：

1. 漏洞检测：
   - 漏洞类型：[漏洞类型]
   - 严重程度：[高/中/低]
   - 置信度：[0-10]
   - 详细描述：[详细描述漏洞的具体情况]

2. 技术分析：
   - 漏洞原理：[解释漏洞的技术原理]
   - 攻击场景：[描述可能的攻击场景]
   - 影响范围：[评估漏洞的影响范围]

3. 修复建议：
   - 修复方案：[提供具体的修复方案]
   - 最佳实践：[提供相关的安全最佳实践]

如果未发现漏洞，请明确说明并解释原因。
"""
    
    def _get_exploit_scenario_prompt(self) -> str:
        """获取攻击场景生成提示词模板"""
        return """
你是一位专业的安全渗透测试专家，擅长模拟攻击者的思维和行为。

请基于以下安全问题，生成详细的攻击场景：

安全问题：{security_issue}
代码片段:
{code_snippet}

请按照以下格式输出攻击场景：

1. 攻击场景描述：
   - 详细描述攻击者如何利用该漏洞
   - 攻击的步骤和流程
   - 可能使用的工具和技术

2. 攻击条件：
   - 成功攻击需要满足的条件
   - 攻击者需要的权限和资源
   - 攻击的前置条件

3. 攻击后果：
   - 攻击成功后可能导致的后果
   - 数据泄露或系统损坏的程度
   - 对业务的影响

4. 防御建议：
   - 如何检测此类攻击
   - 如何预防此类攻击
   - 应急响应措施

请确保攻击场景详细、逼真，并基于实际的安全实践。
"""
    
    def _get_fix_recommendation_prompt(self) -> str:
        """获取修复建议提示词模板"""
        return """
你是一位专业的安全修复专家，擅长提供具体、可操作的安全修复方案。

请基于以下安全问题，提供详细的修复建议：

安全问题：{security_issue}
代码片段:
{code_snippet}

请按照以下格式输出修复建议：

1. 修复方案：
   - 具体的修复代码示例
   - 修复的技术原理
   - 修复的优缺点

2. 最佳实践：
   - 相关的安全编码标准
   - 预防类似问题的措施
   - 代码审查要点

3. 验证方法：
   - 如何验证修复是否有效
   - 推荐的测试方法
   - 可能的边缘情况

4. 参考资料：
   - 相关的安全文档
   - 最佳实践指南
   - 类似漏洞的修复案例

请确保修复建议具体、可操作，并符合安全最佳实践。
"""
    
    def _get_false_positive_filter_prompt(self) -> str:
        """获取误报过滤提示词模板"""
        return """
你是一位专业的安全分析师，擅长评估安全扫描发现的误报可能性。

请分析以下安全发现，判断它是否是误报：

文件: {file_path}
行号: {line_number}
问题: {issue}
严重程度: {severity}
详情: {details}
代码片段: {code_snippet}

评估标准：
1. 这个问题是否真实存在？
2. 它是否构成真正的安全风险？
3. 它是否可能是误报或低影响问题？
4. 基于代码片段和上下文，这个问题的可信度如何？

请输出 JSON 格式的分析结果，包含以下字段：
- keep_finding: 布尔值，表示是否应该保留这个发现
- confidence_score: 0-10 的分数，表示保留/排除的置信度
- justification: 详细的判断理由
- exclusion_reason: 如果是误报，说明排除的原因

示例输出：
{
  "keep_finding": false,
  "confidence_score": 8.5,
  "justification": "这是一个典型的误报，因为代码中使用了参数化查询，不存在 SQL 注入风险",
  "exclusion_reason": "使用了参数化查询，不存在 SQL 注入风险"
}

请只输出 JSON，不要添加任何其他内容。
"""
    
    def add_custom_prompt(self, prompt_type: str, prompt_template: str):
        """添加自定义提示词模板
        
        Args:
            prompt_type: 提示词类型
            prompt_template: 提示词模板
        """
        self._prompts[prompt_type] = prompt_template
    
    def get_available_prompts(self) -> List[str]:
        """获取可用的提示词类型
        
        Returns:
            提示词类型列表
        """
        return list(self._prompts.keys())


if __name__ == '__main__':
    # 测试提示词管理器
    prompt_manager = PromptManager()
    
    # 测试安全分析提示词
    security_prompt = prompt_manager.get_prompt(
        "security_analysis",
        file_path="test.py",
        line_number=10,
        code_snippet="query = f\"SELECT * FROM users WHERE id = {user_id}\""
    )
    print("安全分析提示词:")
    print(security_prompt)
    print("\n" + "="*80 + "\n")
    
    # 测试漏洞检测提示词
    vulnerability_prompt = prompt_manager.get_prompt(
        "vulnerability_detection",
        file_path="test.py",
        line_number=10,
        code_snippet="query = f\"SELECT * FROM users WHERE id = {user_id}\""
    )
    print("漏洞检测提示词:")
    print(vulnerability_prompt)
    print("\n" + "="*80 + "\n")
    
    # 测试修复建议提示词
    fix_prompt = prompt_manager.get_prompt(
        "fix_recommendation",
        security_issue="SQL 注入风险",
        code_snippet="query = f\"SELECT * FROM users WHERE id = {user_id}\""
    )
    print("修复建议提示词:")
    print(fix_prompt)

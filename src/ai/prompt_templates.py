"""Prompt模板库模块

为每个Agent提供3套Prompt变体，确保分析的准确性和稳定性。
"""

from typing import Dict, Any, List


class PromptTemplates:
    """Prompt模板库

    为每个Agent提供3套Prompt变体。
    """

    def __init__(self):
        """初始化Prompt模板库"""
        self.templates = {
            "agent_0": [
                # 变体1
                """你是代码关系分析器，请提取以下信息：

1. 当前文件的关键功能
2. 外部依赖（import）
3. 调用的关键函数
4. 可能的数据输入来源

文件内容：
{file_content}

导入信息：
{imports}

相关文件：
{related_files}

函数调用：
{function_calls}

请输出结构化JSON，包含以下字段：
- key_functions: 关键函数列表
- external_dependencies: 外部依赖列表
- data_inputs: 数据输入来源列表
- context_summary: 上下文摘要

你必须逐步推理，不允许跳步。""",
                # 变体2
                """作为代码分析专家，我需要你分析以下文件的上下文信息：

文件内容：
{file_content}

导入的模块：
{imports}

相关文件：
{related_files}

调用的函数：
{function_calls}

请提供以下信息的结构化JSON：
1. 该文件的主要功能和职责
2. 依赖的外部库及其用途
3. 关键函数调用及其作用
4. 可能的用户输入或数据来源
5. 文件在整个项目中的角色

你必须详细分析，不允许跳过任何步骤。""",
                # 变体3
                """代码上下文分析任务：

请分析以下文件及其相关信息，提供详细的上下文分析：

文件内容：
{file_content}

导入模块：
{imports}

相关文件：
{related_files}

函数调用：
{function_calls}

分析要求：
- 识别文件的核心功能
- 分析外部依赖的作用
- 提取关键函数调用
- 确定数据输入来源
- 总结文件的上下文环境

请以JSON格式输出分析结果，包含必要的详细信息。"""
            ],
            "agent_1": [
                # 变体1
                """你必须将以下代码转换为结构化语义表示：

代码内容：
{file_content}

上下文摘要：
{context_summary}

输出要求：
- input_sources: 输入源列表（用户输入/HTTP/ENV等）
- dangerous_operations: 危险操作列表（exec/file/network等）
- data_flows: 数据流路径列表
- suspicious_points: 可疑点列表（仅标记，不判断漏洞）

禁止：
- 不允许判断漏洞
- 只进行事实描述，不做价值判断

你必须逐步推理，不允许跳步。""",
                # 变体2
                """代码语义解析任务：

请对以下代码进行结构化语义分析：

代码：
{file_content}

上下文：
{context_summary}

分析要求：
1. 识别所有输入源（用户输入、环境变量、网络请求等）
2. 标记所有危险操作（文件操作、网络请求、命令执行等）
3. 追踪数据流动路径
4. 标记可疑的代码片段

输出格式：
请以JSON格式输出，包含上述四个部分。

注意：只做事实分析，不判断是否为漏洞。""",
                # 变体3
                """作为代码语义分析师，你的任务是将代码转换为结构化表示：

代码内容：
{file_content}

上下文信息：
{context_summary}

请提取并结构化以下信息：
- 输入源：所有可能的输入来源
- 危险操作：可能存在风险的操作
- 数据流：数据如何在代码中流动
- 可疑点：需要进一步审查的代码片段

请以JSON格式输出，不要包含任何漏洞判断。"""
            ],
            "agent_2": [
                # 变体1
                """基于以下结构化数据，列出所有可能的安全风险：

语义分析结果：
{semantic_result}

要求：
1. 尽可能多（允许误报）
2. 覆盖：RCE、SSRF、文件读写、注入、prompt injection
3. 不要验证，只枚举可能的风险
4. 每个风险需要包含：类型、位置、描述

你必须逐步推理，不允许跳步。""",
                # 变体2
                """风险枚举任务：

基于以下代码语义分析结果，枚举所有可能的安全风险：

{semantic_result}

枚举要求：
- 高召回率，尽可能列出所有可能的风险
- 覆盖常见漏洞类型：RCE、SSRF、文件操作、注入攻击、prompt注入等
- 每个风险项需包含：风险类型、可能位置、简要描述
- 不需要验证风险是否真实存在

请以JSON格式输出风险列表。""",
                # 变体3
                """作为安全风险分析师，你的任务是枚举所有可能的安全风险：

分析数据：
{semantic_result}

请列出所有可能的安全风险，包括但不限于：
- 远程代码执行（RCE）
- 服务器端请求伪造（SSRF）
- 不安全的文件操作
- 各种注入攻击
- Prompt注入

每个风险需要包含类型、可能的位置和简要描述。
请以JSON格式输出完整的风险列表。"""
            ],
            "agent_3": [
                # 变体1
                """验证每个风险是否真实存在：

文件内容：
{file_content}

风险列表：
{risks}

必须：
1. 构造攻击路径
2. 提供payload
3. 明确 YES / NO 判断

规则：
- 无法构造利用链 = NO
- 必须提供具体的验证步骤

你必须逐步推理，不允许跳步。""",
                # 变体2
                """漏洞验证任务：

请验证以下风险是否真实存在：

文件代码：
{file_content}

风险列表：
{risks}

验证要求：
1. 对每个风险进行详细分析
2. 构造具体的攻击路径
3. 提供可利用的payload
4. 明确给出 YES/NO 的验证结果
5. 无法构造完整利用链的风险标记为 NO

请以JSON格式输出验证结果。""",
                # 变体3
                """作为漏洞验证专家，你的任务是验证每个风险的真实性：

代码文件：
{file_content}

待验证风险：
{risks}

验证步骤：
1. 分析每个风险的技术可行性
2. 构造详细的攻击路径
3. 提供具体的payload示例
4. 基于能否构造完整利用链做出 YES/NO 判断

请以JSON格式输出验证结果，包含每个风险的验证详情。"""
            ],
            "agent_4": [
                # 变体1
                """分析漏洞是否可形成攻击链：

验证结果：
{validated_risks}

输出：
1. 攻击步骤（step-by-step）
2. 前置条件
3. 利用顺序
4. 最终影响（RCE/数据泄露）

请输出 attack graph 格式的结果。

你必须逐步推理，不允许跳步。""",
                # 变体2
                """攻击链分析任务：

基于以下验证通过的漏洞，分析可能的攻击链：

{validated_risks}

分析要求：
1. 识别漏洞之间的关联性
2. 构建完整的攻击路径
3. 详细描述每一步的攻击步骤
4. 列出攻击的前置条件
5. 分析最终可能的影响

请以JSON格式输出攻击链分析结果，包含攻击图结构。""",
                # 变体3
                """作为攻击链分析专家，你的任务是分析漏洞之间的连锁效应：

验证通过的漏洞：
{validated_risks}

请分析：
- 如何组合这些漏洞形成攻击链
- 攻击的具体步骤和顺序
- 成功攻击需要的前置条件
- 攻击可能造成的最终影响

请以攻击图的形式输出分析结果。"""
            ],
            "agent_5": [
                # 变体1
                """你是安全对抗分析员，请反驳上述漏洞：

文件内容：
{file_content}

验证结果：
{validated_risks}

攻击链：
{attack_chains}

检查：
1. 是否真的可控输入？
2. 是否存在执行路径？
3. payload是否可执行？

输出：
- REFUTE / ACCEPT / UNCERTAIN

你必须逐步推理，不允许跳步。""",
                # 变体2
                """对抗验证任务：

作为安全对抗分析师，你需要对以下漏洞分析进行反驳：

代码文件：
{file_content}

验证通过的漏洞：
{validated_risks}

攻击链分析：
{attack_chains}

请从以下角度进行反驳：
1. 输入是否真的可控
2. 攻击路径是否真实存在
3. payload是否能够实际执行

对每个漏洞给出 REFUTE/ACCEPT/UNCERTAIN 的判断。

请以JSON格式输出反驳结果。""",
                # 变体3
                """安全反驳分析：

请对以下漏洞分析进行批判性审查：

文件内容：
{file_content}

已验证漏洞：
{validated_risks}

攻击链：
{attack_chains}

审查要点：
- 输入控制：攻击者是否真的能控制输入
- 执行路径：攻击路径是否存在且可达
- 利用可行性：payload是否能实际执行

对每个漏洞给出最终判断：
- ACCEPT：漏洞真实存在
- REFUTE：漏洞不存在
- UNCERTAIN：无法确定

请以JSON格式输出审查结果。"""
            ],
            "agent_6": [
                # 变体1
                """综合所有分析结果，给出最终判断：

验证结果：
{verified_risks}

标准：
- 有真实利用链 → VALID
- 存疑 → UNCERTAIN
- 无法利用 → INVALID

输出：
- 漏洞列表
- 置信度
- 修复建议

你必须逐步推理，不允许跳步。""",
                # 变体2
                """最终裁决任务：

基于以下验证结果，给出最终的安全漏洞判断：

{verified_risks}

裁决标准：
- VALID：存在真实的利用链
- UNCERTAIN：证据不足，需要进一步验证
- INVALID：无法利用

请输出：
1. 最终的漏洞列表
2. 每个漏洞的置信度
3. 详细的修复建议

请以JSON格式输出最终裁决结果。""",
                # 变体3
                """作为安全裁决专家，你的任务是综合所有分析结果：

验证结果：
{verified_risks}

请根据以下标准做出最终判断：
- VALID：有完整的攻击链和利用路径
- UNCERTAIN：证据不足，存在疑问
- INVALID：无法构造有效的利用链

输出内容：
- 最终确认的漏洞列表
- 每个漏洞的置信度评分
- 具体的修复建议

请以JSON格式输出完整的裁决结果。"""
            ]
        }

    def get_prompt(self, agent_name: str, variables: Dict[str, Any]) -> str:
        """获取Prompt模板

        Args:
            agent_name: Agent名称
            variables: 模板变量

        Returns:
            渲染后的Prompt
        """
        templates = self.templates.get(agent_name, [])
        if not templates:
            return ""

        # 默认使用第一个模板变体
        template = templates[0]

        # 渲染模板
        rendered_prompt = template.format(**variables)
        return rendered_prompt

    def get_prompt_variants(self, agent_name: str, variables: Dict[str, Any]) -> List[str]:
        """获取所有Prompt变体

        Args:
            agent_name: Agent名称
            variables: 模板变量

        Returns:
            渲染后的Prompt变体列表
        """
        templates = self.templates.get(agent_name, [])
        variants = []

        for template in templates:
            rendered_prompt = template.format(**variables)
            variants.append(rendered_prompt)

        return variants

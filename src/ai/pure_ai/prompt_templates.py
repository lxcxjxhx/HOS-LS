class PromptTemplates:
    """纯AI模式的提示模板
    
    为每个Agent提供专业的提示模板，确保分析质量和一致性
    """
    
    # Agent 0: 上下文构建（伪RAG）
    AGENT_0_CONTEXT_BUILDER = """
你是代码关系分析器，请分析以下代码文件及其上下文：

文件路径: {file_path}

文件内容:
{file_content}

相关文件:
{related_files}

导入语句:
{imports}

函数调用:
{function_calls}

请提取并输出以下信息：

1. 当前文件的关键功能和作用
2. 外部依赖（import）的主要用途
3. 调用的关键函数及其可能的安全影响
4. 可能的数据输入来源
5. 与其他文件的关系

输出必须是结构化JSON，格式如下：
{{
  "file_function": "文件的主要功能",
  "dependencies": [
    {{
      "import": "导入语句",
      "purpose": "用途"
    }}
  ],
  "key_functions": [
    {{
      "name": "函数名",
      "purpose": "用途",
      "security_impact": "可能的安全影响"
    }}
  ],
  "input_sources": ["输入来源1", "输入来源2"],
  "file_relationships": [
    {{
      "file": "相关文件路径",
      "relationship": "关系描述"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
"""
    
    # Agent 1: 代码理解（强制结构化）
    AGENT_1_CODE_UNDERSTANDING = """
你是代码语义解析专家，请将以下代码转换为结构化语义表示：

文件路径: {file_path}

文件内容:
{file_content}

上下文信息:
{context_info}

请提取并输出以下结构化信息：

1. 输入源：识别所有可能的用户输入、HTTP请求、环境变量等数据来源
2. 危险操作：识别所有可能的危险操作，如exec、文件读写、网络请求等
3. 数据流路径：描述数据从输入到危险操作的流动路径
4. 可疑点：标记可能存在安全问题的代码位置

输出必须是结构化JSON，格式如下：
{{
  "input_sources": [
    {{
      "type": "输入类型",
      "location": "代码位置",
      "description": "描述"
    }}
  ],
  "dangerous_operations": [
    {{
      "type": "操作类型",
      "location": "代码位置",
      "description": "描述"
    }}
  ],
  "data_flows": [
    {{
      "source": "数据来源",
      "sink": "数据去向",
      "path": "流动路径描述"
    }}
  ],
  "suspicious_points": [
    {{
      "location": "代码位置",
      "description": "可疑原因"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
禁止判断漏洞，只进行事实提取。
"""
    
    # Agent 2: 风险枚举（高召回）
    AGENT_2_RISK_ENUMERATION = """
你是安全风险枚举专家，基于以下结构化数据，列出所有可能的安全风险：

文件路径: {file_path}

结构化数据:
{structured_data}

请尽可能多地列出可能的安全风险，包括但不限于：
- 远程代码执行 (RCE)
- 服务器端请求伪造 (SSRF)
- 文件读写漏洞
- 注入攻击（SQL注入、命令注入等）
- Prompt注入
- 认证绕过
- 授权问题
- 敏感信息泄露

输出必须是结构化JSON，格式如下：
{{
  "risks": [
    {{
      "type": "风险类型",
      "location": "可能的代码位置",
      "description": "风险描述",
      "potential_impact": "潜在影响"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
要求尽可能多的列举，允许误报。
不要验证风险是否真实存在，只进行枚举。
"""
    
    # Agent 3: 漏洞验证（核心）
    AGENT_3_VULNERABILITY_VERIFICATION = """
你是漏洞验证专家，请验证以下风险是否真实存在：

文件路径: {file_path}

风险列表:
{risk_list}

代码内容:
{file_content}

对于每个风险，请：
1. 构造攻击路径
2. 提供具体的payload
3. 明确判断 YES / NO（是否真实存在）

输出必须是结构化JSON，格式如下：
{{
  "verifications": [
    {{
      "risk_type": "风险类型",
      "location": "代码位置",
      "attack_path": "攻击路径描述",
      "payload": "具体的攻击payload",
      "verdict": "YES/NO",
      "reason": "验证理由"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
无法构造利用链 = NO。
"""
    
    # Agent 4: 攻击链分析（高级能力）
    AGENT_4_ATTACK_CHAIN_ANALYSIS = """
你是攻击链分析专家，请分析以下漏洞是否可形成攻击链：

文件路径: {file_path}

验证结果:
{verification_results}

请分析：
1. 攻击步骤（step-by-step）
2. 前置条件
3. 利用顺序
4. 最终影响（RCE/数据泄露等）

输出必须是结构化JSON，格式如下：
{{
  "attack_chains": [
    {{
      "name": "攻击链名称",
      "steps": [
        {{
          "step": 1,
          "description": "步骤描述",
          "prerequisites": ["前置条件1", "前置条件2"]
        }}
      ],
      "final_impact": "最终影响",
      "severity": "严重程度"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
"""
    
    # Agent 5: 对抗验证（反AI幻觉）
    AGENT_5_ADVERSARIAL_VALIDATION = """
你是安全对抗分析员，请反驳以下漏洞分析：

文件路径: {file_path}

攻击链分析:
{attack_chain_analysis}

代码内容:
{file_content}

请检查：
1. 是否真的可控输入？
2. 是否存在执行路径？
3. payload是否可执行？

对于每个攻击链，请输出：
- REFUTE（反驳）/ ACCEPT（接受）/ UNCERTAIN（不确定）
- 详细理由

输出必须是结构化JSON，格式如下：
{{
  "adversarial_analysis": [
    {{
      "attack_chain_name": "攻击链名称",
      "verdict": "REFUTE/ACCEPT/UNCERTAIN",
      "reason": "详细理由",
      "counter_arguments": ["反驳论点1", "反驳论点2"]
    }}
  ]
}}

你必须逐步推理，不允许跳步。
"""
    
    # Agent 6: 最终裁决（防胡说）
    AGENT_6_FINAL_DECISION = """
你是最终裁决专家，请综合所有分析结果，给出最终判断：

文件路径: {file_path}

对抗验证结果:
{adversarial_results}

验证结果:
{verification_results}

请根据以下标准进行判断：
- 有真实利用链 → VALID
- 存疑 → UNCERTAIN
- 无法利用 → INVALID

输出必须是结构化JSON，格式如下：
{{
  "final_findings": [
    {{
      "vulnerability": "漏洞描述",
      "location": "代码位置",
      "severity": "严重程度",
      "status": "VALID/UNCERTAIN/INVALID",
      "confidence": "置信度 (0-100)",
      "recommendation": "修复建议"
    }}
  ],
  "summary": {{
    "total_vulnerabilities": 数字,
    "valid_vulnerabilities": 数字,
    "uncertain_vulnerabilities": 数字,
    "invalid_vulnerabilities": 数字
  }}
}}

你必须逐步推理，不允许跳步。
"""
    
    # 辅助函数：格式化相关文件
    @staticmethod
    def format_related_files(related_files):
        """格式化相关文件信息
        
        Args:
            related_files: 相关文件列表
            
        Returns:
            格式化后的字符串
        """
        if not related_files:
            return "无"
        
        formatted = []
        for i, file_info in enumerate(related_files):
            path = file_info.get('path', '未知路径')
            content = file_info.get('content', '').strip()[:500]  # 限制内容长度
            formatted.append(f"文件 {i+1}: {path}\n{content}\n")
        
        return '\n'.join(formatted)
    
    # 辅助函数：格式化导入语句
    @staticmethod
    def format_imports(imports):
        """格式化导入语句
        
        Args:
            imports: 导入语句列表
            
        Returns:
            格式化后的字符串
        """
        if not imports:
            return "无"
        return '\n'.join(imports)
    
    # 辅助函数：格式化函数调用
    @staticmethod
    def format_function_calls(function_calls):
        """格式化函数调用
        
        Args:
            function_calls: 函数调用列表
            
        Returns:
            格式化后的字符串
        """
        if not function_calls:
            return "无"
        return '\n'.join(function_calls)

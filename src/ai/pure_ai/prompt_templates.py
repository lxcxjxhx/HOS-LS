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

1. 输入源：识别所有可能的用户输入、HTTP请求、环境变量、命令行参数、文件输入等数据来源
2. 危险操作：识别所有可能的危险操作，如exec、eval、文件读写、网络请求、系统命令执行等
3. 数据流路径：详细描述数据从输入到危险操作的完整流动路径，包括变量名和函数调用
4. 可疑点：标记可能存在安全问题的代码位置，包括具体的行号和代码片段
5. 依赖关系：识别代码中使用的外部依赖和库

输出必须是结构化JSON，格式如下：
{{
  "input_sources": [
    {{
      "type": "输入类型",
      "location": "文件路径:行号",
      "description": "详细描述",
      "variable_name": "变量名（如果有）"
    }}
  ],
  "dangerous_operations": [
    {{
      "type": "操作类型",
      "location": "文件路径:行号",
      "description": "详细描述",
      "function_name": "函数名（如果有）"
    }}
  ],
  "data_flows": [
    {{
      "source": "数据来源",
      "sink": "数据去向",
      "path": "详细流动路径描述",
      "steps": ["步骤1", "步骤2"]
    }}
  ],
  "suspicious_points": [
    {{
      "location": "文件路径:行号",
      "description": "可疑原因",
      "code_snippet": "相关代码片段"
    }}
  ],
  "dependencies": [
    {{
      "name": "依赖名称",
      "type": "导入类型",
      "usage": "使用方式"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
禁止判断漏洞，只进行事实提取。
请确保信息的准确性和完整性。
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
- 文件读写漏洞（任意文件读取、文件上传漏洞等）
- 注入攻击（SQL注入、命令注入、LDAP注入等）
- Prompt注入
- 认证绕过
- 授权问题
- 敏感信息泄露
- 跨站脚本 (XSS)
- 跨站请求伪造 (CSRF)
- 会话管理问题
- 密码存储问题
- 不安全的加密实现

输出必须是结构化JSON，格式如下：
{{
  "risks": [
    {{
      "type": "风险类型",
      "location": "可能的代码位置",
      "description": "详细风险描述",
      "potential_impact": "潜在影响",
      "cvss_score": "估计的CVSS评分（0-10）"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
要求尽可能多的列举，允许误报。
不要验证风险是否真实存在，只进行枚举。
请确保风险描述的详细性和准确性。
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
1. 详细分析代码逻辑
2. 构造具体的攻击路径
3. 提供可执行的具体payload
4. 明确判断 YES / NO（是否真实存在）
5. 给出详细的验证理由

输出必须是结构化JSON，格式如下：
{{
  "verifications": [
    {{
      "risk_type": "风险类型",
      "location": "代码位置",
      "attack_path": "详细攻击路径描述",
      "payload": "具体的攻击payload",
      "verdict": "YES/NO",
      "reason": "详细验证理由",
      "cvss_score": "验证后的CVSS评分（0-10）"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
无法构造利用链 = NO。
请确保验证过程的严谨性和准确性。
"""
    
    # Agent 4: 攻击链分析（高级能力）
    AGENT_4_ATTACK_CHAIN_ANALYSIS = """
你是攻击链分析专家，请分析以下漏洞是否可形成攻击链：

文件路径: {file_path}

验证结果:
{verification_results}

请分析：
1. 攻击步骤（step-by-step，详细描述每个步骤）
2. 前置条件（所有必要的条件）
3. 利用顺序（最佳攻击顺序）
4. 最终影响（RCE/数据泄露等详细描述）
5. 防御绕过方法（如果有）

输出必须是结构化JSON，格式如下：
{{
  "attack_chains": [
    {{
      "name": "攻击链名称",
      "steps": [
        {{
          "step": 1,
          "description": "详细步骤描述",
          "prerequisites": ["前置条件1", "前置条件2"],
          "payload": "步骤使用的payload"
        }}
      ],
      "final_impact": "详细最终影响",
      "severity": "严重程度",
      "cvss_score": "攻击链的CVSS评分（0-10）",
      "defense_bypasses": ["防御绕过方法1", "防御绕过方法2"]
    }}
  ]
}}

你必须逐步推理，不允许跳步。
请确保攻击链分析的完整性和可行性。
"""
    
    # Agent 5: 对抗验证（反AI幻觉）
    AGENT_5_ADVERSARIAL_VALIDATION = """
你是安全对抗分析员，请反驳以下漏洞分析：

文件路径: {file_path}

攻击链分析:
{attack_chain_analysis}

代码内容:
{file_content}

请严格检查：
1. 是否真的可控输入？输入是否经过验证或过滤？
2. 是否存在执行路径？代码逻辑是否允许攻击路径执行？
3. payload是否可执行？是否有防御机制阻止payload执行？
4. 攻击链是否存在逻辑漏洞或假设错误？

对于每个攻击链，请输出：
- REFUTE（反驳）/ ACCEPT（接受）/ UNCERTAIN（不确定）
- 详细理由（基于代码事实）
- 具体的反驳论点

输出必须是结构化JSON，格式如下：
{{
  "adversarial_analysis": [
    {{
      "attack_chain_name": "攻击链名称",
      "verdict": "REFUTE/ACCEPT/UNCERTAIN",
      "reason": "详细理由（基于代码分析）",
      "counter_arguments": ["具体反驳论点1", "具体反驳论点2"],
      "evidence": "支持反驳的代码证据"
    }}
  ]
}}

你必须逐步推理，不允许跳步。
请基于代码事实进行反驳，避免主观臆断。
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
- 有真实利用链且经过验证 → VALID
- 存疑或需要更多信息 → UNCERTAIN
- 无法利用或被反驳 → INVALID

对于每个发现，请：
1. 给出明确的状态判断
2. 提供详细的判断理由
3. 给出具体的修复建议
4. 评估置信度（0-100）

输出必须是结构化JSON，格式如下：
{{
  "final_findings": [
    {{
      "vulnerability": "详细漏洞描述",
      "location": "代码位置",
      "severity": "严重程度",
      "status": "VALID/UNCERTAIN/INVALID",
      "confidence": "置信度 (0-100)",
      "cvss_score": "最终CVSS评分（0-10）",
      "recommendation": "详细修复建议",
      "evidence": "支持判断的证据"
    }}
  ],
  "summary": {{
    "total_vulnerabilities": 数字,
    "valid_vulnerabilities": 数字,
    "uncertain_vulnerabilities": 数字,
    "invalid_vulnerabilities": 数字,
    "high_severity_count": 数字,
    "medium_severity_count": 数字,
    "low_severity_count": 数字
  }}
}}

你必须逐步推理，不允许跳步。
请确保判断的客观性和准确性。
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

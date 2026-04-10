"""智能Pipeline构建器

增强版Pipeline构建器，基于原PipelineBuilder，增加：
- AI驱动的智能解析
- 自然语言理解
- 上下文感知的Pipeline优化
"""

from typing import List, Dict, Any, Optional
import re
import json

from src.core.agent_pipeline import PipelineBuilder, AgentNode, AgentType
from src.core.config import Config


class IntelligentPipelineBuilder(PipelineBuilder):
    """智能Pipeline构建器
    
    继承自PipelineBuilder，添加AI增强能力：
    - 从自然语言构建Pipeline
    - Pipeline到自然语言的双向转换
    - 基于上下文的优化建议
    """
    
    AGENT_DESCRIPTIONS = {
        AgentType.SCANNER: {
            "name": "scan",
            "cn": "代码扫描",
            "en": "Code Scanning",
            "description": "扫描代码文件，检测安全漏洞"
        },
        AgentType.REASONER: {
            "name": "reason",
            "cn": "漏洞推理",
            "en": "Vulnerability Reasoning",
            "description": "分析漏洞原因和影响"
        },
        AgentType.ATTACK_CHAIN: {
            "name": "attack-chain",
            "cn": "攻击链分析",
            "en": "Attack Chain Analysis",
            "description": "构建完整的攻击路径"
        },
        AgentType.POC: {
            "name": "poc",
            "cn": "POC生成",
            "en": "POC Generation",
            "description": "生成漏洞利用代码"
        },
        AgentType.VERIFIER: {
            "name": "verify",
            "cn": "漏洞验证",
            "en": "Vulnerability Verification",
            "description": "验证漏洞的真实性"
        },
        AgentType.FIX: {
            "name": "fix",
            "cn": "修复建议",
            "en": "Fix Suggestions",
            "description": "提供修复建议和补丁"
        },
        AgentType.REPORT: {
            "name": "report",
            "cn": "报告生成",
            "en": "Report Generation",
            "description": "生成安全扫描报告"
        }
    }
    
    COMMON_PIPELINES = {
        "快速扫描": ["scan", "report"],
        "quick-scan": ["scan", "report"],
        
        "标准分析": ["scan", "reason", "report"],
        "standard-analysis": ["scan", "reason", "report"],
        
        "深度审计": ["scan", "reason", "attack-chain", "poc", "verify", "report"],
        "full-audit": ["scan", "reason", "attack-chain", "poc", "verify", "report"],
        
        "POC生成": ["scan", "reason", "poc"],
        "poc-only": ["scan", "reason", "poc"],
        
        "攻击链分析": ["scan", "reason", "attack-chain"],
        "attack-chain": ["scan", "reason", "attack-chain"],
        
        "漏洞验证": ["scan", "reason", "poc", "verify"],
        "verify-only": ["scan", "reason", "poc", "verify"]
    }
    
    @classmethod
    def from_natural_language(cls, text: str, ai_client=None, config: Config = None) -> List[AgentNode]:
        """从自然语言构建Pipeline（AI增强版）
        
        Args:
            text: 用户自然语言输入
            ai_client: AI客户端（可选，用于复杂理解）
            config: 配置对象
            
        Returns:
            构建好的AgentNode列表
            
        示例:
        >>> pipeline = IntelligentPipelineBuilder.from_natural_language("扫描认证模块并生成POC")
        >>> # 返回: [AgentNode(SCANNER), AgentNode(REASONER), AgentNode(POC)]
        """
        # 1. 尝试匹配常用Pipeline模式
        nodes = cls._match_common_pipeline(text)
        if nodes:
            completed = cls.auto_complete(nodes)
            return cls.deduplicate(completed)
        
        # 2. 使用规则提取关键词
        nodes = cls._extract_from_keywords(text)
        if nodes:
            completed = cls.auto_complete(nodes)
            return cls.deduplicate(completed)
        
        # 3. 如果AI可用，使用AI解析
        if ai_client:
            try:
                import asyncio
                nodes = asyncio.run(
                    cls._ai_parse_pipeline(text, ai_client, config)
                )
                if nodes:
                    return nodes
            except Exception:
                pass
        
        # 4. 默认返回标准Pipeline
        return [
            AgentNode(type=AgentType.SCANNER),
            AgentNode(type=AgentType.REASONER),
            AgentNode(type=AgentType.REPORT)
        ]
    
    @classmethod
    def _match_common_pipeline(cls, text: str) -> Optional[List[AgentNode]]:
        """匹配常用的Pipeline模式"""
        text_lower = text.lower()
        
        for pattern_name, flags in cls.COMMON_PIPELINES.items():
            if pattern_name in text_lower or pattern_name.replace('-', ' ') in text_lower:
                nodes = [cls.parse_flag(flag) for flag in flags]
                return nodes
                
        # 特殊模式匹配
        if any(kw in text_lower for kw in ['完整', '全面', 'comprehensive', 'full']):
            return [cls.parse_flag(flag) for flag in cls.COMMON_PIPELINES['full-audit']]
            
        if any(kw in text_lower for kw in ['快速', '简单', 'quick', 'simple', 'fast']):
            return [cls.parse_flag(flag) for flag in cls.COMMON_PIPELINES['quick-scan']]
            
        return None
    
    @classmethod
    def _extract_from_keywords(cls, text: str) -> Optional[List[AgentNode]]:
        """从文本中提取关键词并映射到Agent"""
        text_lower = text.lower()
        nodes = []
        
        keyword_to_agent = {
            '扫描': AgentType.SCANNER,
            'scan': AgentType.SCANNER,
            '检查': AgentType.SCANNER,
            
            '分析': AgentType.REASONER,
            'analyze': AgentType.REASONER,
            '推理': AgentType.REASONER,
            'reason': AgentType.REASONER,
            
            '攻击链': AgentType.ATTACK_CHAIN,
            'attack.chain': AgentType.ATTACK_CHAIN,
            'attack-chain': AgentType.ATTACK_CHAIN,
            
            'poc': AgentType.POC,
            '利用': AgentType.POC,
            'exploit': AgentType.POC,
            
            '验证': AgentType.VERIFIER,
            'verify': AgentType.VERIFIER,
            
            '修复': AgentType.FIX,
            'fix': AgentType.FIX,
            'patch': AgentType.FIX,
            
            '报告': AgentType.REPORT,
            'report': AgentType.REPORT
        }
        
        for keyword, agent_type in keyword_to_agent.items():
            if keyword in text_lower and agent_type not in [n.type for n in nodes]:
                nodes.append(AgentNode(type=agent_type))
                
        return nodes if nodes else None
    
    @classmethod
    async def _ai_parse_pipeline(cls, text: str, ai_client, config: Config) -> List[AgentNode]:
        """使用AI解析自然语言为Pipeline"""
        from src.ai.models import AIRequest
        
        prompt = f"""你是一个安全扫描Pipeline构建专家。根据用户需求生成最优的Agent Pipeline。

用户需求: {text}

可用的Agent节点及其功能:
{cls._get_agents_info_for_prompt()}

常用Pipeline组合:
- 快速扫描: scan → report
- 标准分析: scan → reason → report  
- 深度审计: scan → reason → attack-chain → poc → verify → report
- POC生成: scan → reason → poc
- 攻击链分析: scan → reason → attack-chain

请分析用户需求，返回JSON格式的Pipeline:
{{"pipeline": ["agent1", "agent2", ...], "params": {{"agent1": {{"key": "value"}}}}}}

注意:
1. 只返回JSON，不要其他内容
2. pipeline数组中的元素必须是上述可用节点名称
3. 根据用户需求选择最合适的组合
4. 保持简洁，不要过度设计"""

        request = AIRequest(
            prompt=prompt,
            system_prompt="你是专业的安全扫描Pipeline构建专家。",
            max_tokens=500,
            temperature=0.3  # 低温度确保输出稳定
        )
        
        response = await ai_client.generate(request)
        
        result = cls._parse_ai_response(response.content)
        
        if result and result.get('pipeline'):
            nodes = []
            for agent_name in result.get('pipeline', []):
                params = result.get('params', {}).get(agent_name, {})
                node = cls.parse_flag(agent_name)
                if params:
                    node.params.update(params)
                nodes.append(node)
                
            completed = cls.auto_complete(nodes)
            unique_nodes = cls.deduplicate(completed)
            return unique_nodes
            
        return None
    
    @classmethod
    def _get_agents_info_for_prompt(cls) -> str:
        """获取用于Prompt的Agent信息"""
        lines = []
        for agent_type, info in cls.AGENT_DESCRIPTIONS.items():
            lines.append(f"- {info['name']}: {info['cn']} ({info['en']})")
        return "\n".join(lines)
    
    @classmethod
    def _parse_ai_response(cls, content: str) -> Optional[Dict[str, Any]]:
        """解析AI响应"""
        json_match = re.search(r'\{[^{}]+\}', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return None
    
    @classmethod
    def to_natural_language(cls, nodes: List[AgentNode], detail_level: str = "standard") -> str:
        """将Pipeline转换为易懂的自然语言描述
        
        Args:
            nodes: AgentNode列表
            detail_level: 详细程度 (simple/standard/detailed)
            
        Returns:
            自然语言描述字符串
        """
        if not nodes:
            return "空Pipeline"
            
        if detail_level == "simple":
            descriptions = []
            for node in nodes:
                info = cls.AGENT_DESCRIPTIONS.get(node.type, {})
                descriptions.append(info.get('cn', node.type.value))
            return "、".join(descriptions)
            
        elif detail_level == "detailed":
            lines = ["📋 执行计划:"]
            for i, node in enumerate(nodes, 1):
                info = cls.AGENT_DESCRIPTIONS.get(node.type, {})
                desc = info.get('cn', node.type.value)
                desc_en = info.get('en', '')
                params_str = ""
                if node.params:
                    params_str = f" (参数: {node.params})"
                    
                lines.append(f"  {i}. **{desc}** ({desc_en}){params_str}")
                lines.append(f"     └─ {info.get('description', '')}")
            return "\n".join(lines)
            
        else:  # standard
            actions = []
            for node in nodes:
                info = cls.AGENT_DESCRIPTIONS.get(node.type, {})
                actions.append(info.get('cn', node.type.value))
            return f"将执行以下操作: {' → '.join(actions)}"
    
    @classmethod
    def to_cli_command(cls, nodes: List[AgentNode], target: str = ".") -> str:
        """将Pipeline转换为CLI命令
        
        Args:
            nodes: AgentNode列表
            target: 目标路径
            
        Returns:
            CLI命令字符串
        """
        flags = []
        for node in nodes:
            flag = f"--{node.type.value}"
            if node.params:
                strategy = node.params.get('strategy')
                if strategy:
                    flag += f"={strategy}"
            flags.append(flag)
            
        cmd = f"hos-ls scan {' '.join(flags)} {target}"
        return cmd
    
    @classmethod
    def from_cli_command(cls, cli_command: str) -> List[AgentNode]:
        """从CLI命令构建Pipeline
        
        Args:
            cli_command: CLI命令字符串
            
        Returns:
            AgentNode列表
        """
        parts = cli_command.split()
        flags = []
        
        for part in parts[1:]:  # 跳过命令名
            if part.startswith('--'):
                flag = part[2:]
                if '+' in flag:
                    chain_nodes = cls.parse_chain_flag('--' + flag)
                    flags.extend([n.type.value for n in chain_nodes])
                else:
                    flags.append(flag)
                    
        return cls.build_pipeline(flags)
    
    @classmethod
    def optimize_for_context(cls, nodes: List[AgentNode], context: Dict[str, Any]) -> List[AgentNode]:
        """基于上下文优化Pipeline
        
        Args:
            nodes: 初始Pipeline
            context: 上下文信息（项目特征、历史记录等）
            
        Returns:
            优化后的Pipeline
        """
        optimized_nodes = list(nodes)
        
        # 如果是大型项目，考虑减少步骤
        total_files = context.get('total_files', 0)
        if total_files > 1000:
            if len(optimized_nodes) > 5:
                optimized_nodes = optimized_nodes[:5]
                
        # 如果之前执行过类似操作，可以参考历史
        history = context.get('execution_history', [])
        if history:
            last_successful = next(
                (h for h in reversed(history) if h.get('success')),
                None
            )
            if last_successful:
                pass  # 可以根据历史调整顺序
                
        return optimized_nodes
    
    @classmethod
    def suggest_improvements(cls, nodes: List[AgentNode]) -> List[str]:
        """基于当前Pipeline提供改进建议
        
        Args:
            nodes: 当前Pipeline
            
        Returns:
            改进建议列表
        """
        suggestions = []
        current_types = {node.type for node in nodes}
        
        if AgentType.SCANNER not in current_types:
            suggestions.append("💡 建议: 添加扫描步骤 (--scan)")
            
        if AgentType.REPORT not in current_types:
            suggestions.append("💡 建议: 添加报告生成 (--report)")
            
        if AgentType.POC in current_types and AgentType.VERIFY not in current_types:
            suggestions.append("⚠️ 提示: 生成了POC但未验证，建议添加验证步骤 (--verify)")
            
        if len(nodes) < 3 and AgentType.REASONER not in current_types:
            suggestions.append("💡 建议: Pipeline较简单，考虑添加深度分析 (--reason)")
            
        return suggestions

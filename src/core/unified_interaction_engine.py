"""统一交互引擎

支持自然语言输入和智能完成的核心交互系统。
"""

from typing import Optional, Dict, Any, List
import re
import os
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ConversationMessage:
    """对话消息"""
    role: str
    content: str


@dataclass
class ConversationHistory:
    """对话历史"""
    messages: List[ConversationMessage]


class SimpleConversationManager:
    """简化对话管理器"""
    
    def __init__(self):
        """初始化"""
        self.project_context = {}
        self.messages = []
    
    def add_user_message(self, content: str):
        """添加用户消息"""
        self.messages.append(ConversationMessage(role="user", content=content))
    
    def add_assistant_message(self, content: str):
        """添加助手消息"""
        self.messages.append(ConversationMessage(role="assistant", content=content))
    
    def get_messages(self):
        """获取所有消息"""
        return self.messages


class UnifiedInteractionEngine:
    """统一交互引擎"""
    
    def __init__(self, config=None, session_name: Optional[str] = None, ai_client=None):
        """初始化交互引擎
        
        Args:
            config: 配置对象（兼容旧接口）
            session_name: 会话名称（兼容旧接口）
            ai_client: AI 客户端
        """
        self.config = config
        self.session_name = session_name
        self.ai_client = ai_client
        self.history = []
        self.context = {}
        
        # 兼容旧接口的属性
        self.conversation_manager = SimpleConversationManager()
    
    def process(self, user_input: str) -> Dict[str, Any]:
        """处理用户输入（兼容旧接口）
        
        Args:
            user_input: 用户输入文本
            
        Returns:
            处理结果，包含意图、参数等信息
        """
        result = self.process_input(user_input)
        
        # 兼容旧接口的响应格式
        compatible_result = {
            "content": result["response"]["message"],
            "action": result["response"]["action"],
            "params": result["params"],
            "intent": result["intent"]
        }
        
        # 添加到对话历史
        self.conversation_manager.add_user_message(user_input)
        self.conversation_manager.add_assistant_message(compatible_result["content"])
        
        return compatible_result
    
    def process_input(self, user_input: str) -> Dict[str, Any]:
        """处理用户输入
        
        Args:
            user_input: 用户输入文本
            
        Returns:
            处理结果，包含意图、参数等信息
        """
        # 预处理输入
        processed_input = self._preprocess_input(user_input)
        
        # 解析意图
        intent_data = self._parse_intent(processed_input)
        
        # 提取参数
        params = self._extract_parameters(processed_input, intent_data)
        
        # 生成响应
        response = self._generate_response(intent_data, params)
        
        # 记录历史
        self.history.append({
            "input": user_input,
            "processed_input": processed_input,
            "intent": intent_data,
            "params": params,
            "response": response
        })
        
        return {
            "intent": intent_data,
            "params": params,
            "response": response
        }
    
    def _preprocess_input(self, user_input: str) -> str:
        """预处理输入
        
        Args:
            user_input: 用户输入文本
            
        Returns:
            预处理后的输入
        """
        # 去除多余空格
        user_input = re.sub(r'\s+', ' ', user_input.strip())
        
        # 处理常见缩写
        abbreviations = {
            "scan": ["扫描", "检查", "检测"],
            "analyze": ["分析", "解析"],
            "exploit": ["利用", "攻击"],
            "fix": ["修复", "修复方案"],
            "report": ["报告", "生成报告"]
        }
        
        # 简单的同义词替换
        for key, synonyms in abbreviations.items():
            for synonym in synonyms:
                user_input = user_input.replace(synonym, key)
        
        return user_input
    
    def _parse_intent(self, user_input: str) -> Dict[str, Any]:
        """解析用户意图
        
        Args:
            user_input: 预处理后的用户输入
            
        Returns:
            意图数据
        """
        # 意图模式
        intent_patterns = {
            "scan": [r'scan', r'扫描', r'检查', r'检测'],
            "analyze": [r'analyze', r'分析', r'解析'],
            "exploit": [r'exploit', r'利用', r'攻击'],
            "fix": [r'fix', r'修复', r'修复方案'],
            "report": [r'report', r'报告', r'生成报告'],
            "info": [r'info', r'信息', r'帮助', r'如何'],
            "plan": [r'plan', r'计划', r'执行计划']
        }
        
        # 匹配意图
        for intent, patterns in intent_patterns.items():
            for pattern in patterns:
                if re.search(pattern, user_input, re.IGNORECASE):
                    return {
                        "type": intent,
                        "confidence": 0.9
                    }
        
        # 默认为信息查询
        return {
            "type": "info",
            "confidence": 0.5
        }
    
    def _extract_parameters(self, user_input: str, intent_data: Dict[str, Any]) -> Dict[str, Any]:
        """提取参数
        
        Args:
            user_input: 预处理后的用户输入
            intent_data: 意图数据
            
        Returns:
            提取的参数
        """
        params = {}
        
        # 提取目标路径
        path_patterns = [
            r'(?:scan|分析|检查)\s+(.*?)\s+(?:漏洞|安全|问题)',
            r'对\s+(.*?)\s+进行(?:扫描|分析|检查)',
            r'(.*?)\s+的(?:漏洞|安全|问题)'
        ]
        
        for pattern in path_patterns:
            match = re.search(pattern, user_input, re.IGNORECASE)
            if match:
                path = match.group(1).strip()
                if os.path.exists(path):
                    params["target"] = path
                break
        
        # 提取漏洞类型
        vulnerability_types = [
            "SQL注入", "XSS", "CSRF", "RCE", "SSRF", 
            "认证绕过", "授权问题", "信息泄露", "命令注入"
        ]
        
        for vuln_type in vulnerability_types:
            if vuln_type in user_input:
                params["vulnerability_type"] = vuln_type
                break
        
        # 提取深度
        depth_patterns = {
            "deep": ["深度", "详细", "全面"],
            "fast": ["快速", "简单", "基本"],
            "stealth": [" stealth", "隐秘", "低调"]
        }
        
        for depth, keywords in depth_patterns.items():
            for keyword in keywords:
                if keyword in user_input:
                    params["depth"] = depth
                    break
        
        return params
    
    def _generate_response(self, intent_data: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """生成响应
        
        Args:
            intent_data: 意图数据
            params: 提取的参数
            
        Returns:
            响应数据
        """
        intent_type = intent_data.get("type", "info")
        
        responses = {
            "scan": {
                "action": "scan",
                "message": f"开始扫描 {params.get('target', '.')} 的安全漏洞",
                "params": params
            },
            "analyze": {
                "action": "analyze",
                "message": f"开始分析 {params.get('target', '.')} 的代码安全",
                "params": params
            },
            "exploit": {
                "action": "exploit",
                "message": f"开始生成 {params.get('target', '.')} 的利用代码",
                "params": params
            },
            "fix": {
                "action": "fix",
                "message": f"开始生成 {params.get('target', '.')} 的修复方案",
                "params": params
            },
            "report": {
                "action": "report",
                "message": f"开始生成安全报告",
                "params": params
            },
            "info": {
                "action": "info",
                "message": "我可以帮你扫描代码安全漏洞、分析代码、生成利用代码和修复方案。请告诉我你需要什么帮助。",
                "params": params
            },
            "plan": {
                "action": "plan",
                "message": f"开始生成执行计划",
                "params": params
            }
        }
        
        return responses.get(intent_type, responses["info"])
    
    def get_suggestions(self, partial_input: str) -> List[str]:
        """获取输入建议
        
        Args:
            partial_input: 部分输入
            
        Returns:
            建议列表
        """
        suggestions = []
        
        # 基于历史的建议
        for item in reversed(self.history):
            input_text = item.get("input", "")
            if input_text.startswith(partial_input) and input_text not in suggestions:
                suggestions.append(input_text)
                if len(suggestions) >= 3:
                    break
        
        # 基于常用命令的建议
        common_commands = [
            "scan ./project",
            "analyze ./code.py",
            "exploit SQL注入漏洞",
            "fix XSS漏洞",
            "report 生成安全报告"
        ]
        
        for cmd in common_commands:
            if cmd.startswith(partial_input) and cmd not in suggestions:
                suggestions.append(cmd)
                if len(suggestions) >= 5:
                    break
        
        return suggestions
    
    def update_context(self, key: str, value: Any):
        """更新上下文
        
        Args:
            key: 上下文键
            value: 上下文值
        """
        self.context[key] = value
    
    def get_context(self, key: str) -> Optional[Any]:
        """获取上下文
        
        Args:
            key: 上下文键
            
        Returns:
            上下文值
        """
        return self.context.get(key)
    
    def clear_history(self):
        """清除历史记录"""
        self.history = []
    
    def get_history(self) -> List[Dict[str, Any]]:
        """获取历史记录
        
        Returns:
            历史记录列表
        """
        return self.history
    
    def save_session(self):
        """保存会话（兼容旧接口）"""
        # 简单实现，保存到内存即可
        pass
    
    def get_conversation_history(self) -> ConversationHistory:
        """获取对话历史（兼容旧接口）
        
        Returns:
            对话历史
        """
        return ConversationHistory(messages=self.conversation_manager.messages)


class InteractionManager:
    """交互管理器"""
    
    def __init__(self, ai_client=None):
        """初始化交互管理器"""
        self.engine = UnifiedInteractionEngine(ai_client=ai_client)
        self.session_id = self._generate_session_id()
    
    def _generate_session_id(self) -> str:
        """生成会话ID
        
        Returns:
            会话ID
        """
        import uuid
        return str(uuid.uuid4())
    
    def handle_input(self, user_input: str) -> Dict[str, Any]:
        """处理用户输入
        
        Args:
            user_input: 用户输入文本
            
        Returns:
            处理结果
        """
        result = self.engine.process_input(user_input)
        
        # 添加会话信息
        result["session_id"] = self.session_id
        result["timestamp"] = self._get_timestamp()
        
        return result
    
    def _get_timestamp(self) -> str:
        """获取时间戳
        
        Returns:
            时间戳字符串
        """
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_suggestions(self, partial_input: str) -> List[str]:
        """获取输入建议
        
        Args:
            partial_input: 部分输入
            
        Returns:
            建议列表
        """
        return self.engine.get_suggestions(partial_input)
    
    def get_session_info(self) -> Dict[str, Any]:
        """获取会话信息
        
        Returns:
            会话信息
        """
        return {
            "session_id": self.session_id,
            "history_count": len(self.engine.get_history()),
            "context": self.engine.context
        }
    
    def reset_session(self):
        """重置会话"""
        self.engine.clear_history()
        self.session_id = self._generate_session_id()


def create_unified_interaction_engine(config=None, session_name: Optional[str] = None, ai_client=None) -> UnifiedInteractionEngine:
    """创建统一交互引擎实例
    
    Args:
        config: 配置对象
        session_name: 会话名称
        ai_client: AI客户端实例
        
    Returns:
        统一交互引擎实例
    """
    return UnifiedInteractionEngine(config=config, session_name=session_name, ai_client=ai_client)

def create_interaction_manager(ai_client=None) -> InteractionManager:
    """创建交互管理器实例
    
    Args:
        ai_client: AI客户端实例
        
    Returns:
        交互管理器实例
    """
    return InteractionManager(ai_client=ai_client)

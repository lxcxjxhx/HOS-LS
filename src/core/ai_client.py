"""AI 客户端管理

管理 AI 模型的连接和调用。
"""

from typing import Optional, Dict, Any
import os


class AIClient:
    """AI 客户端基类"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化 AI 客户端"""
        self.config = config or {}
        self.provider = self.config.get("provider", "deepseek")
        self.model = self.config.get("model", "deepseek-chat")
    
    def generate(self, prompt: str, **kwargs) -> str:
        """生成文本
        
        Args:
            prompt: 提示词
            **kwargs: 额外参数
            
        Returns:
            生成的文本
        """
        # 基础实现，子类需要重写
        return f"AI 生成的响应 for: {prompt[:50]}..."
    
    def chat(self, messages: list, **kwargs) -> str:
        """聊天模式
        
        Args:
            messages: 消息列表
            **kwargs: 额外参数
            
        Returns:
            生成的响应
        """
        # 基础实现，子类需要重写
        return f"AI 聊天响应 for {len(messages)} messages"


def get_ai_client(config: Any = None) -> AIClient:
    """获取 AI 客户端实例
    
    Args:
        config: 配置对象
        
    Returns:
        AI 客户端实例
    """
    # 从配置中获取 AI 配置
    ai_config = {}
    if config and hasattr(config, 'ai'):
        ai_config = {
            "provider": getattr(config.ai, 'provider', "deepseek"),
            "model": getattr(config.ai, 'model', "deepseek-chat"),
            "api_key": getattr(config.ai, 'api_key', None),
            "base_url": getattr(config.ai, 'base_url', None)
        }
    
    # 创建并返回 AI 客户端实例
    return AIClient(ai_config)

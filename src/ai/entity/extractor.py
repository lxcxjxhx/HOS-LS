import re
import logging
from typing import Optional

from src.ai.intent.intent_model import IntentEntity

logger = logging.getLogger(__name__)


class AIEntityExtractor:
    """实体提取器。
    
    从输入文本中提取关键实体信息，如目标路径、域名、IP地址等。
    """
    
    # 常见路径模式
    PATH_PATTERN = re.compile(r'(?:[a-zA-Z]:\\|/|~)[^\s]*')
    
    # 域名模式
    DOMAIN_PATTERN = re.compile(r'(?:https?://)?(?:[\w-]+\.)+[\w-]+(?:/\S*)?')
    
    # IP地址模式
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    # 端口模式
    PORT_PATTERN = re.compile(r'[:](\d{2,5})\b')
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._initialized = False
    
    async def initialize(self):
        """异步初始化，目前没有特殊初始化逻辑。"""
        self._initialized = True
        logger.debug("AIEntityExtractor initialized")
    
    async def extract(self, text: str) -> IntentEntity:
        """从文本中提取实体信息。
        
        尝试查找目标路径、域名或IP地址。
        """
        # 尝试提取路径
        target_path = self._extract_target(text)
        
        # 尝试提取端口
        port = self._extract_port(text)
        
        metadata = {}
        if port:
            metadata["port"] = port
        
        return IntentEntity(
            type="target",
            value=target_path,
            metadata=metadata,
        )
    
    def _extract_target(self, text: str) -> str:
        """提取目标路径/域名/IP。"""
        # 优先查找路径
        path_match = self.PATH_PATTERN.search(text)
        if path_match:
            return path_match.group(0)
        
        # 查找域名
        domain_match = self.DOMAIN_PATTERN.search(text)
        if domain_match:
            return domain_match.group(0)
        
        # 查找IP
        ip_match = self.IP_PATTERN.search(text)
        if ip_match:
            return ip_match.group(0)
        
        # 默认返回原文
        return text
    
    def _extract_port(self, text: str) -> Optional[str]:
        """提取端口号。"""
        port_match = self.PORT_PATTERN.search(text)
        if port_match:
            return port_match.group(1)
        return None

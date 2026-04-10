"""本地AI提供商

支持Ollama本地模型
"""

import asyncio
import json
import aiohttp
from typing import Dict, Any, Optional, Tuple

from src.ai.client import AIClient
from src.ai.models import AIProvider, AIRequest, AIResponse
from src.core.config import Config


class LocalClient(AIClient):
    """本地AI客户端
    
    支持Ollama本地模型
    """
    
    def __init__(self, config: Optional[Config] = None):
        super().__init__(config)
        # 正确访问配置
        if hasattr(self.config, 'ai'):
            self.base_url = getattr(self.config.ai, 'local_url', 'http://localhost:11434')
            self.model = getattr(self.config.ai, 'model', 'llama3')
        else:
            self.base_url = 'http://localhost:11434'
            self.model = 'llama3'
        self.timeout = 60.0
        self.session = None
        self._initialized = False
    
    @property
    def provider(self) -> AIProvider:
        """提供商"""
        return AIProvider.LOCAL
    
    async def initialize(self) -> None:
        """初始化客户端"""
        if not self._initialized:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
            self._initialized = True
    
    async def close(self) -> None:
        """关闭客户端"""
        if self.session and not self.session.closed:
            await self.session.close()
        self._initialized = False
    
    async def generate(self, request: AIRequest) -> AIResponse:
        """生成响应
        
        Args:
            request: AI请求
            
        Returns:
            AI响应
        """
        if not self._initialized:
            await self.initialize()
        
        model = request.model or self.model
        url = f"{self.base_url}/api/generate"
        
        payload = {
            "model": model,
            "prompt": request.prompt,
            "system": request.system_prompt,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens
        }
        
        try:
            async with self.session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Ollama API error: {error_text}")
                
                # 读取流式响应
                content = []
                async for chunk in response.content:
                    if chunk:
                        chunk_data = json.loads(chunk.decode('utf-8'))
                        if 'response' in chunk_data:
                            content.append(chunk_data['response'])
                        if chunk_data.get('done', False):
                            break
                
                full_content = ''.join(content)
                
                # 构建响应
                return AIResponse(
                    content=full_content,
                    model=model,
                    provider=AIProvider.LOCAL,
                    usage={}
                )
        except Exception as e:
            raise Exception(f"Local model generation failed: {str(e)}")
    
    def is_available(self) -> bool:
        """检查客户端是否可用"""
        return self._initialized
    
    async def validate_api_access(self) -> Tuple[bool, str]:
        """验证API访问
        
        Returns:
            Tuple[bool, str]: (是否成功, 错误信息)
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            url = f"{self.base_url}/api/tags"
            async with self.session.get(url) as response:
                if response.status == 200:
                    return True, "Ollama API access successful"
                else:
                    return False, f"Ollama API error: {await response.text()}"
        except Exception as e:
            return False, f"Failed to connect to Ollama: {str(e)}"

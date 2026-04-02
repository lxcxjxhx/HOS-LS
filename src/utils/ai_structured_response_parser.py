import json
import time
from typing import Any, Dict, Optional, Type, TypeVar
from pydantic import BaseModel, ValidationError

T = TypeVar('T', bound=BaseModel)

class AIStructuredResponseParser:
    _instance = None
    _max_retries = 3
    _retry_delay = 1

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AIStructuredResponseParser, cls).__new__(cls)
        return cls._instance

    def parse(self, response: str, model: Type[T]) -> T:
        """解析 AI 响应为结构化数据
        
        Args:
            response: AI 响应字符串
            model: Pydantic 模型类
            
        Returns:
            解析后的模型实例
            
        Raises:
            ValidationError: 如果解析失败且重试后仍然失败
        """
        retries = 0
        while retries < self._max_retries:
            try:
                # 尝试解析 JSON
                data = json.loads(response)
                # 使用 Pydantic 验证
                return model(**data)
            except (json.JSONDecodeError, ValidationError) as e:
                retries += 1
                if retries >= self._max_retries:
                    raise
                time.sleep(self._retry_delay)

    def parse_with_fallback(self, response: str, model: Type[T]) -> Optional[T]:
        """解析 AI 响应为结构化数据，失败时返回 None
        
        Args:
            response: AI 响应字符串
            model: Pydantic 模型类
            
        Returns:
            解析后的模型实例，失败时返回 None
        """
        try:
            return self.parse(response, model)
        except Exception:
            return None

    def validate_schema(self, data: Dict[str, Any], model: Type[T]) -> bool:
        """验证数据是否符合模型 schema
        
        Args:
            data: 要验证的数据
            model: Pydantic 模型类
            
        Returns:
            是否符合 schema
        """
        try:
            model(**data)
            return True
        except ValidationError:
            return False

    def set_max_retries(self, max_retries: int):
        """设置最大重试次数
        
        Args:
            max_retries: 最大重试次数
        """
        self._max_retries = max_retries

    def set_retry_delay(self, retry_delay: float):
        """设置重试延迟
        
        Args:
            retry_delay: 重试延迟（秒）
        """
        self._retry_delay = retry_delay

ai_structured_response_parser = AIStructuredResponseParser()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI结构化响应解析器 v2.0

功能：
1. 解析AI响应为结构化数据
2. 强制JSON格式验证
3. 支持重试机制
4. 失败时返回BLOCK状态（不降级）
"""

import json
import re
import time
from typing import Any, Dict, Optional, Type, TypeVar, Tuple
from pydantic import BaseModel, ValidationError

T = TypeVar('T', bound=BaseModel)


class AIResponseParseError(Exception):
    """AI响应解析错误"""
    pass


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
            AIResponseParseError: 如果解析失败且重试后仍然失败
        """
        retries = 0
        last_error = None
        
        while retries < self._max_retries:
            try:
                # 清理响应文本
                cleaned_response = self._clean_response(response)
                
                # 尝试解析 JSON
                data = json.loads(cleaned_response)
                
                # 使用 Pydantic 验证
                return model(**data)
                
            except (json.JSONDecodeError, ValidationError) as e:
                retries += 1
                last_error = e
                
                if retries >= self._max_retries:
                    raise AIResponseParseError(
                        f"AI响应解析失败（已重试{self._max_retries}次）: {str(e)}"
                    )
                
                # 尝试修复常见的JSON格式问题
                if retries == 1:
                    response = self._fix_json_format(response)
                elif retries == 2:
                    # 第二次重试，尝试更激进的修复
                    response = self._aggressive_fix_json(response)
                
                time.sleep(self._retry_delay * retries)

    def parse_strict(self, response: str, model: Type[T]) -> Tuple[bool, Optional[T], str]:
        """严格解析 AI 响应 - 不抛出异常，返回状态
        
        Args:
            response: AI 响应字符串
            model: Pydantic 模型类
            
        Returns:
            (成功, 解析结果, 错误信息)
        """
        try:
            result = self.parse(response, model)
            return True, result, ""
        except AIResponseParseError as e:
            return False, None, str(e)
        except Exception as e:
            return False, None, f"未知错误: {str(e)}"

    def _clean_response(self, response: str) -> str:
        """清理AI响应文本"""
        if not response:
            return ""
        
        # 去除markdown代码块标记
        response = response.strip()
        
        # 去除 ```json 和 ``` 标记
        if response.startswith("```json"):
            response = response[7:]
        elif response.startswith("```"):
            response = response[3:]
        
        if response.endswith("```"):
            response = response[:-3]
        
        response = response.strip()
        
        # 查找JSON内容
        json_start = response.find('{')
        json_end = response.rfind('}') + 1
        
        if json_start != -1 and json_end > json_start:
            response = response[json_start:json_end]
        
        return response.strip()

    def _fix_json_format(self, response: str) -> str:
        """尝试修复常见的JSON格式问题"""
        # 清理响应
        response = self._clean_response(response)
        
        # 修复Python风格的None/null
        response = re.sub(r'(?<=[\s\[\{\,])None(?=[\s\]\}\,])', 'null', response)
        response = re.sub(r'(?<=[\s\[\{\,])True(?=[\s\]\}\,])', 'true', response)
        response = re.sub(r'(?<=[\s\[\{\,])False(?=[\s\]\}\,])', 'false', response)
        
        # 修复尾随逗号
        response = re.sub(r',(\s*[}\]])', r'\1', response)
        
        # 修复未加引号的键
        response = re.sub(r'([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', response)
        
        return response
    
    def _aggressive_fix_json(self, response: str) -> str:
        """更激进的JSON修复 - 处理单引号等情况"""
        response = self._clean_response(response)
        
        # 尝试检测是否是Python字典格式（使用单引号）
        if response.startswith("{") and "'" in response and '"' not in response:
            # 尝试用ast.literal_eval解析Python字典
            try:
                import ast
                data = ast.literal_eval(response)
                # 转换回JSON字符串
                return json.dumps(data)
            except:
                pass
        
        # 修复单引号（仅在确定是JSON键/值边界时）
        # 这个比较复杂，简单处理：替换所有单引号为双引号
        # 但这样可能会破坏字符串内容，所以作为最后手段
        response = response.replace("'", '"')
        
        return response

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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API 客户端抽象模块

功能：
1. 提供统一的 API 客户端接口
2. 支持不同的 HTTP 方法（GET、POST、PUT、DELETE 等）
3. 支持不同的认证方式（API 密钥、OAuth、基本认证等）
4. 支持不同的序列化/反序列化格式（JSON、XML 等）
5. 支持错误处理和重试机制
6. 提供统一的接口，便于在不同的模块中使用
"""

import os
import sys
import time
import logging
import requests
from typing import Dict, Any, List, Optional, Union
from abc import ABC, abstractmethod

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接从 config_manager 模块导入，避免循环导入
from utils.config_manager import ConfigManager

logger = logging.getLogger(__name__)


class ApiClientError(Exception):
    """API 客户端异常"""
    pass


class ApiResponse:
    """API 响应封装"""
    
    def __init__(self, response: requests.Response):
        """初始化 API 响应
        
        Args:
            response: requests 响应对象
        """
        self.response = response
        self.status_code = response.status_code
        self.headers = response.headers
        self.content = response.content
        self.text = response.text
    
    def json(self) -> Dict[str, Any]:
        """解析 JSON 响应
        
        Returns:
            Dict[str, Any]: 解析后的 JSON 数据
        """
        try:
            return self.response.json()
        except Exception as e:
            raise ApiClientError(f"JSON 解析失败: {e}")
    
    def raise_for_status(self):
        """检查响应状态码
        
        Raises:
            ApiClientError: 如果状态码表示错误
        """
        try:
            self.response.raise_for_status()
        except requests.RequestException as e:
            raise ApiClientError(f"API 请求失败: {e}")


class ApiClient(ABC):
    """API 客户端抽象基类"""
    
    @abstractmethod
    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ApiResponse:
        """发送 GET 请求
        
        Args:
            endpoint: API 端点
            params: 查询参数
            headers: 请求头
            
        Returns:
            ApiResponse: API 响应
        """
        pass
    
    @abstractmethod
    def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ApiResponse:
        """发送 POST 请求
        
        Args:
            endpoint: API 端点
            data: 表单数据
            json: JSON 数据
            headers: 请求头
            
        Returns:
            ApiResponse: API 响应
        """
        pass
    
    @abstractmethod
    def put(self, endpoint: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ApiResponse:
        """发送 PUT 请求
        
        Args:
            endpoint: API 端点
            data: 表单数据
            json: JSON 数据
            headers: 请求头
            
        Returns:
            ApiResponse: API 响应
        """
        pass
    
    @abstractmethod
    def delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ApiResponse:
        """发送 DELETE 请求
        
        Args:
            endpoint: API 端点
            params: 查询参数
            headers: 请求头
            
        Returns:
            ApiResponse: API 响应
        """
        pass


class HttpClient(ApiClient):
    """HTTP API 客户端实现"""
    
    def __init__(self, base_url: str, timeout: int = 30, max_retries: int = 3, backoff_factor: float = 0.5):
        """初始化 HTTP 客户端
        
        Args:
            base_url: 基础 URL
            timeout: 超时时间（秒）
            max_retries: 最大重试次数
            backoff_factor: 重试退避因子
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def _build_url(self, endpoint: str) -> str:
        """构建完整的 URL
        
        Args:
            endpoint: API 端点
            
        Returns:
            str: 完整的 URL
        """
        if endpoint.startswith('http://') or endpoint.startswith('https://'):
            return endpoint
        return f"{self.base_url}/{endpoint.lstrip('/')}"
    
    def _request(self, method: str, endpoint: str, **kwargs) -> ApiResponse:
        """发送 HTTP 请求
        
        Args:
            method: HTTP 方法
            endpoint: API 端点
            **kwargs: 请求参数
            
        Returns:
            ApiResponse: API 响应
        """
        url = self._build_url(endpoint)
        retries = 0
        
        while retries <= self.max_retries:
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    **kwargs
                )
                return ApiResponse(response)
            except requests.RequestException as e:
                retries += 1
                if retries > self.max_retries:
                    raise ApiClientError(f"请求失败，已达到最大重试次数: {e}")
                
                # 计算退避时间
                backoff_time = self.backoff_factor * (2 ** (retries - 1))
                logger.warning(f"请求失败，{backoff_time:.2f}秒后重试: {e}")
                time.sleep(backoff_time)
    
    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ApiResponse:
        """发送 GET 请求
        
        Args:
            endpoint: API 端点
            params: 查询参数
            headers: 请求头
            
        Returns:
            ApiResponse: API 响应
        """
        return self._request('GET', endpoint, params=params, headers=headers)
    
    def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ApiResponse:
        """发送 POST 请求
        
        Args:
            endpoint: API 端点
            data: 表单数据
            json: JSON 数据
            headers: 请求头
            
        Returns:
            ApiResponse: API 响应
        """
        return self._request('POST', endpoint, data=data, json=json, headers=headers)
    
    def put(self, endpoint: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ApiResponse:
        """发送 PUT 请求
        
        Args:
            endpoint: API 端点
            data: 表单数据
            json: JSON 数据
            headers: 请求头
            
        Returns:
            ApiResponse: API 响应
        """
        return self._request('PUT', endpoint, data=data, json=json, headers=headers)
    
    def delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> ApiResponse:
        """发送 DELETE 请求
        
        Args:
            endpoint: API 端点
            params: 查询参数
            headers: 请求头
            
        Returns:
            ApiResponse: API 响应
        """
        return self._request('DELETE', endpoint, params=params, headers=headers)


class AuthenticatedHttpClient(HttpClient):
    """带认证的 HTTP 客户端"""
    
    def __init__(self, base_url: str, auth_type: str = 'api_key', auth_credentials: Union[str, Dict[str, str]] = None, **kwargs):
        """初始化带认证的 HTTP 客户端
        
        Args:
            base_url: 基础 URL
            auth_type: 认证类型 ('api_key', 'basic', 'bearer', 'oauth')
            auth_credentials: 认证凭据
            **kwargs: 其他参数
        """
        super().__init__(base_url, **kwargs)
        self.auth_type = auth_type
        self.auth_credentials = auth_credentials
        self._setup_auth()
    
    def _setup_auth(self):
        """设置认证信息"""
        if self.auth_type == 'api_key' and isinstance(self.auth_credentials, str):
            # API 密钥认证
            self.session.headers.update({
                'Authorization': f'Bearer {self.auth_credentials}'
            })
        elif self.auth_type == 'basic' and isinstance(self.auth_credentials, dict):
            # 基本认证
            username = self.auth_credentials.get('username')
            password = self.auth_credentials.get('password')
            if username and password:
                self.session.auth = (username, password)
        elif self.auth_type == 'bearer' and isinstance(self.auth_credentials, str):
            # Bearer 令牌认证
            self.session.headers.update({
                'Authorization': f'Bearer {self.auth_credentials}'
            })
        elif self.auth_type == 'oauth' and isinstance(self.auth_credentials, dict):
            # OAuth 认证
            access_token = self.auth_credentials.get('access_token')
            if access_token:
                self.session.headers.update({
                    'Authorization': f'Bearer {access_token}'
                })


class ApiClientFactory:
    """API 客户端工厂类"""
    
    @staticmethod
    def create_client(client_type: str, **kwargs) -> ApiClient:
        """创建 API 客户端
        
        Args:
            client_type: 客户端类型 ('http', 'authenticated_http')
            **kwargs: 客户端参数
            
        Returns:
            ApiClient: API 客户端实例
        """
        if client_type == 'http':
            return HttpClient(**kwargs)
        elif client_type == 'authenticated_http':
            return AuthenticatedHttpClient(**kwargs)
        else:
            raise ApiClientError(f"不支持的客户端类型: {client_type}")


class ApiClientManager:
    """API 客户端管理器"""
    
    def __init__(self):
        """初始化 API 客户端管理器"""
        self.clients = {}
    
    def register_client(self, name: str, client: ApiClient):
        """注册 API 客户端
        
        Args:
            name: 客户端名称
            client: API 客户端实例
        """
        self.clients[name] = client
    
    def get_client(self, name: str) -> ApiClient:
        """获取 API 客户端
        
        Args:
            name: 客户端名称
            
        Returns:
            ApiClient: API 客户端实例
        """
        if name not in self.clients:
            raise ApiClientError(f"未注册的客户端: {name}")
        return self.clients[name]
    
    def create_and_register_client(self, name: str, client_type: str, **kwargs):
        """创建并注册 API 客户端
        
        Args:
            name: 客户端名称
            client_type: 客户端类型
            **kwargs: 客户端参数
        """
        client = ApiClientFactory.create_client(client_type, **kwargs)
        self.register_client(name, client)
        return client


if __name__ == '__main__':
    # 测试 API 客户端
    print("测试 HTTP 客户端...")
    
    # 创建 HTTP 客户端
    client = HttpClient('https://httpbin.org')
    
    # 测试 GET 请求
    print("\n测试 GET 请求:")
    response = client.get('/get', params={'test': 'value'})
    print(f"状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    
    # 测试 POST 请求
    print("\n测试 POST 请求:")
    response = client.post('/post', json={'test': 'value'})
    print(f"状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    
    # 测试 PUT 请求
    print("\n测试 PUT 请求:")
    response = client.put('/put', json={'test': 'value'})
    print(f"状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    
    # 测试 DELETE 请求
    print("\n测试 DELETE 请求:")
    response = client.delete('/delete')
    print(f"状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    
    # 测试 API 客户端工厂
    print("\n测试 API 客户端工厂...")
    factory_client = ApiClientFactory.create_client('http', base_url='https://httpbin.org')
    response = factory_client.get('/get')
    print(f"工厂创建的客户端 - 状态码: {response.status_code}")
    
    # 测试 API 客户端管理器
    print("\n测试 API 客户端管理器...")
    manager = ApiClientManager()
    manager.create_and_register_client('httpbin', 'http', base_url='https://httpbin.org')
    manager_client = manager.get_client('httpbin')
    response = manager_client.get('/get')
    print(f"管理器获取的客户端 - 状态码: {response.status_code}")

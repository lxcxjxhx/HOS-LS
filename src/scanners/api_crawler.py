#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API爬虫模块

功能：
1. 自动抓取Web项目的接口
2. 识别API参数类型
3. 构建API调用链
4. 生成API文档
5. 支持认证和会话管理
6. 智能API端点发现
"""

import os
import re
import json
import logging
import requests
import time
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# 尝试导入BeautifulSoup
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    BeautifulSoup = None
    HAS_BS4 = False

logger = logging.getLogger(__name__)

@dataclass
class APIEndpoint:
    """API端点信息"""
    url: str
    method: str
    params: Dict[str, List[str]]
    headers: Dict[str, str]
    body: Optional[Dict[str, Any]] = None
    description: str = ""
    risk_level: str = "low"  # high, medium, low
    parameter_types: Dict[str, str] = None  # 参数类型
    response_structure: Optional[Dict[str, Any]] = None  # 响应结构
    dependencies: List[str] = None  # 依赖的其他API
    auth_required: bool = False  # 是否需要认证

class APICrawler:
    """API爬虫"""
    
    def __init__(self, base_url: str, max_depth: int = 3, timeout: int = 10, auth: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None):
        """初始化API爬虫
        
        Args:
            base_url: 基础URL
            max_depth: 最大爬取深度
            timeout: 请求超时时间
            auth: 认证信息，支持 {'username': 'xxx', 'password': 'xxx'} 或 {'token': 'xxx'}
            headers: 自定义请求头
        """
        self.base_url = base_url
        self.max_depth = max_depth
        self.timeout = timeout
        self.session = requests.Session()
        
        # 设置默认请求头
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/html, application/xhtml+xml, application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        # 合并自定义请求头
        if headers:
            default_headers.update(headers)
        
        self.session.headers.update(default_headers)
        
        # 处理认证
        if auth:
            if 'token' in auth:
                self.session.headers.update({'Authorization': f'Bearer {auth["token"]}'})
            elif 'username' in auth and 'password' in auth:
                self.session.auth = (auth['username'], auth['password'])
        
        self.visited_urls = set()
        self.api_endpoints = []
        self.api_call_chains = []  # API调用链
        self.api_dependencies = {}
        self.response_structures = {}
    
    def crawl(self) -> List[APIEndpoint]:
        """开始爬取API端点
        
        Returns:
            List[APIEndpoint]: 发现的API端点列表
        """
        # 首先尝试常见的API路径
        common_api_paths = [
            '/api', '/v1', '/v2', '/api/v1', '/api/v2',
            '/swagger', '/docs', '/api/docs', '/redoc',
            '/graphql', '/admin/api', '/api/admin'
        ]
        
        for path in common_api_paths:
            api_url = urljoin(self.base_url, path)
            if api_url not in self.visited_urls:
                self._crawl_recursive(api_url, 0)
        
        # 然后从基础URL开始爬取
        self._crawl_recursive(self.base_url, 0)
        
        # 构建API调用链
        self._build_api_call_chains()
        
        return self.api_endpoints
    
    def _crawl_recursive(self, url: str, depth: int):
        """递归爬取URL
        
        Args:
            url: 当前URL
            depth: 当前爬取深度
        """
        if depth >= self.max_depth:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # 检测是否为API响应
            if self._is_api_response(response):
                self._extract_api_endpoint(url, response)
            
            # 解析HTML，提取链接
            if 'text/html' in response.headers.get('Content-Type', '') and HAS_BS4:
                soup = BeautifulSoup(response.text, 'html.parser')
                self._extract_links(soup, url, depth)
            elif 'text/html' in response.headers.get('Content-Type', ''):
                logger.debug("BeautifulSoup not available, skipping HTML parsing")
                
        except Exception as e:
            logger.debug(f"爬取 {url} 失败：{e}")
    
    def _is_api_response(self, response: requests.Response) -> bool:
        """检测是否为API响应
        
        Args:
            response: HTTP响应
            
        Returns:
            bool: 是否为API响应
        """
        content_type = response.headers.get('Content-Type', '')
        return any(ct in content_type for ct in ['application/json', 'application/xml', 'text/json'])
    
    def _extract_api_endpoint(self, url: str, response: requests.Response, method: str = 'GET', body: Optional[Dict[str, Any]] = None):
        """提取API端点信息
        
        Args:
            url: API URL
            response: HTTP响应
            method: 请求方法
            body: 请求体
        """
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # 识别参数类型
        parameter_types = self._identify_parameter_types(params, body)
        
        # 分析响应结构
        response_structure = None
        try:
            if response.text:
                response_json = response.json()
                response_structure = self._analyze_response_structure(response_json)
        except json.JSONDecodeError:
            pass
        
        # 检测是否需要认证
        auth_required = self._detect_auth_required(response)
        
        endpoint = APIEndpoint(
            url=url,
            method=method,
            params=params,
            headers=dict(response.headers),
            body=body,
            parameter_types=parameter_types,
            response_structure=response_structure,
            dependencies=[],
            auth_required=auth_required
        )
        
        # 生成描述
        endpoint.description = self._generate_description(endpoint)
        
        # 评估风险等级
        endpoint.risk_level = self._assess_risk_level(endpoint)
        
        self.api_endpoints.append(endpoint)
        
        # 存储响应结构
        self.response_structures[url] = response_structure
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str, depth: int):
        """从HTML中提取链接
        
        Args:
            soup: BeautifulSoup对象
            base_url: 基础URL
            depth: 当前爬取深度
        """
        # 提取<a>标签
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href')
            absolute_url = urljoin(base_url, href)
            
            # 确保是同域链接
            if self._is_same_domain(absolute_url):
                self._crawl_recursive(absolute_url, depth + 1)
        
        # 提取<form>标签
        for form_tag in soup.find_all('form'):
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'GET').upper()
            
            absolute_url = urljoin(base_url, action)
            if self._is_same_domain(absolute_url):
                # 提取表单参数
                form_params = {}
                for input_tag in form_tag.find_all('input'):
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if name:
                        form_params[name] = [value]
                
                # 创建API端点
                endpoint = APIEndpoint(
                    url=absolute_url,
                    method=method,
                    params=form_params,
                    headers={}
                )
                self.api_endpoints.append(endpoint)
    
    def _is_same_domain(self, url: str) -> bool:
        """检测是否为同域链接
        
        Args:
            url: 要检测的URL
            
        Returns:
            bool: 是否为同域链接
        """
        base_domain = urlparse(self.base_url).netloc
        target_domain = urlparse(url).netloc
        return target_domain == base_domain or target_domain == ''
    
    def _identify_parameter_types(self, params: Dict[str, List[str]], body: Optional[Dict[str, Any]]) -> Dict[str, str]:
        """识别参数类型
        
        Args:
            params: URL参数
            body: 请求体参数
            
        Returns:
            Dict[str, str]: 参数类型映射
        """
        parameter_types = {}
        
        # 分析URL参数
        for param_name, param_values in params.items():
            if param_values:
                value = param_values[0]
                if value.isdigit():
                    parameter_types[param_name] = 'integer'
                elif value.lower() in ['true', 'false']:
                    parameter_types[param_name] = 'boolean'
                elif '@' in value and '.' in value:
                    parameter_types[param_name] = 'email'
                elif value.startswith('http://') or value.startswith('https://'):
                    parameter_types[param_name] = 'url'
                else:
                    parameter_types[param_name] = 'string'
        
        # 分析请求体参数
        if body:
            for param_name, value in body.items():
                if isinstance(value, int):
                    parameter_types[param_name] = 'integer'
                elif isinstance(value, bool):
                    parameter_types[param_name] = 'boolean'
                elif isinstance(value, str):
                    if '@' in value and '.' in value:
                        parameter_types[param_name] = 'email'
                    elif value.startswith('http://') or value.startswith('https://'):
                        parameter_types[param_name] = 'url'
                    else:
                        parameter_types[param_name] = 'string'
                else:
                    parameter_types[param_name] = 'object'
        
        return parameter_types
    
    def _analyze_response_structure(self, response_json: Any) -> Dict[str, Any]:
        """分析响应结构
        
        Args:
            response_json: 响应JSON
            
        Returns:
            Dict[str, Any]: 响应结构
        """
        def analyze_value(value):
            if isinstance(value, dict):
                return {k: analyze_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                if value:
                    return [analyze_value(value[0])]
                return []
            elif isinstance(value, int):
                return 'integer'
            elif isinstance(value, bool):
                return 'boolean'
            elif isinstance(value, str):
                return 'string'
            else:
                return 'unknown'
        
        return analyze_value(response_json)
    
    def _detect_auth_required(self, response: requests.Response) -> bool:
        """检测是否需要认证
        
        Args:
            response: HTTP响应
            
        Returns:
            bool: 是否需要认证
        """
        # 检查状态码
        if response.status_code in [401, 403]:
            return True
        
        # 检查响应头
        www_auth = response.headers.get('WWW-Authenticate')
        if www_auth:
            return True
        
        # 检查响应体
        try:
            if response.text:
                response_json = response.json()
                if 'error' in response_json:
                    error_msg = str(response_json['error']).lower()
                    if any(keyword in error_msg for keyword in ['auth', 'login', 'token', 'permission']):
                        return True
        except:
            pass
        
        return False
    
    def _assess_risk_level(self, endpoint: APIEndpoint) -> str:
        """评估API端点风险等级
        
        Args:
            endpoint: API端点
            
        Returns:
            str: 风险等级
        """
        path = urlparse(endpoint.url).path
        
        # 高风险路径
        high_risk_paths = ['/admin', '/api', '/login', '/auth', '/user', '/account', '/profile', '/settings']
        # 高风险参数
        high_risk_params = ['id', 'user', 'password', 'token', 'api_key', 'secret', 'auth', 'login', 'pass']
        # 高风险方法
        high_risk_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
        
        # 评估风险等级
        if any(risk_path in path for risk_path in high_risk_paths):
            return 'high'
        elif any(risk_param in endpoint.params for risk_param in high_risk_params):
            return 'medium'
        elif endpoint.method in high_risk_methods:
            return 'medium'
        elif endpoint.auth_required:
            return 'medium'
        else:
            return 'low'
    
    def _build_api_call_chains(self):
        """构建API调用链"""
        # 基于URL路径和参数关系构建调用链
        for i, endpoint1 in enumerate(self.api_endpoints):
            for j, endpoint2 in enumerate(self.api_endpoints):
                if i != j:
                    # 检查是否存在依赖关系
                    if self._has_dependency(endpoint1, endpoint2):
                        if endpoint1.url not in self.api_dependencies:
                            self.api_dependencies[endpoint1.url] = []
                        self.api_dependencies[endpoint1.url].append(endpoint2.url)
                        
                        # 构建调用链
                        chain = [endpoint1.url, endpoint2.url]
                        if chain not in self.api_call_chains:
                            self.api_call_chains.append(chain)
    
    def _has_dependency(self, endpoint1: APIEndpoint, endpoint2: APIEndpoint) -> bool:
        """检查两个API端点之间是否存在依赖关系
        
        Args:
            endpoint1: 第一个API端点
            endpoint2: 第二个API端点
            
        Returns:
            bool: 是否存在依赖关系
        """
        # 基于URL路径的依赖关系
        path1 = urlparse(endpoint1.url).path
        path2 = urlparse(endpoint2.url).path
        
        # 检查路径是否有层级关系
        if path1 in path2 or path2 in path1:
            return True
        
        # 检查参数是否有重叠
        params1 = set(endpoint1.params.keys())
        params2 = set(endpoint2.params.keys())
        if params1.intersection(params2):
            return True
        
        return False
    
    def analyze_api_endpoints(self) -> List[APIEndpoint]:
        """分析API端点，评估风险等级
        
        Returns:
            List[APIEndpoint]: 分析后的API端点列表
        """
        for endpoint in self.api_endpoints:
            # 重新评估风险等级
            endpoint.risk_level = self._assess_risk_level(endpoint)
            
            # 重新生成描述
            endpoint.description = self._generate_description(endpoint)
            
            # 添加依赖关系
            if endpoint.url in self.api_dependencies:
                endpoint.dependencies = self.api_dependencies[endpoint.url]
        
        return self.api_endpoints
    
    def _generate_description(self, endpoint: APIEndpoint) -> str:
        """生成API端点描述
        
        Args:
            endpoint: API端点
            
        Returns:
            str: 描述
        """
        path = urlparse(endpoint.url).path
        method = endpoint.method
        
        descriptions = {
            '/login': '用户登录接口',
            '/auth': '认证接口',
            '/api': 'API接口',
            '/admin': '管理后台接口',
            '/user': '用户相关接口',
            '/account': '账户相关接口',
            '/data': '数据相关接口',
            '/upload': '文件上传接口',
            '/download': '文件下载接口'
        }
        
        for key, desc in descriptions.items():
            if key in path:
                return f"{method} {desc}"
        
        return f"{method} {path}"
    
    def export_api_documentation(self, output_file: str):
        """导出API文档
        
        Args:
            output_file: 输出文件路径
        """
        api_data = []
        for endpoint in self.api_endpoints:
            api_data.append({
                'url': endpoint.url,
                'method': endpoint.method,
                'params': endpoint.params,
                'headers': endpoint.headers,
                'body': endpoint.body,
                'description': endpoint.description,
                'risk_level': endpoint.risk_level,
                'parameter_types': endpoint.parameter_types,
                'response_structure': endpoint.response_structure,
                'dependencies': endpoint.dependencies,
                'auth_required': endpoint.auth_required
            })
        
        # 添加API调用链信息
        documentation = {
            'api_endpoints': api_data,
            'api_call_chains': self.api_call_chains,
            'api_dependencies': self.api_dependencies,
            'total_endpoints': len(self.api_endpoints),
            'total_chains': len(self.api_call_chains)
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(documentation, f, indent=2, ensure_ascii=False)
        
        logger.info(f"API文档已导出到：{output_file}")

if __name__ == '__main__':
    # 测试API爬虫
    crawler = APICrawler('https://httpbin.org', max_depth=2)
    endpoints = crawler.crawl()
    analyzed_endpoints = crawler.analyze_api_endpoints()
    
    print(f"发现 {len(analyzed_endpoints)} 个API端点：")
    for i, endpoint in enumerate(analyzed_endpoints):
        print(f"\n{i+1}. {endpoint.method} {endpoint.url}")
        print(f"   描述: {endpoint.description}")
        print(f"   风险等级: {endpoint.risk_level}")
        print(f"   参数: {endpoint.params}")
    
    # 导出API文档
    crawler.export_api_documentation('api_documentation.json')

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理器

功能：
1. 统一配置管理，支持环境变量和配置文件
2. 建立分层配置体系
3. 提供默认配置和用户自定义配置
4. 配置加载优先级管理
"""

import os
import json
import yaml
from typing import Dict, Any, Optional


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_file: str = None):
        """初始化配置管理器
        
        Args:
            config_file: 配置文件路径（可选）
        """
        self.config_file = config_file
        self.config = {}  # 最终配置
        self.default_config = self._load_default_config()  # 默认配置
        self.user_config = {}  # 用户配置
        self.env_config = self._load_env_config()  # 环境变量配置
        
        # 加载配置文件
        if self.config_file and os.path.exists(self.config_file):
            self.user_config = self._load_config_file(self.config_file)
        
        # 合并配置
        self._merge_configs()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """加载默认配置"""
        return {
            # 扫描配置
            'scanner': {
                'parallel': True,
                'max_workers': 4,
                'use_gitignore': True,
                'use_cache': True
            },
            
            # 规则配置
            'rules': {
                'rules_file': None,
                'enable_ai_rules': True
            },
            
            # AI 配置
            'ai': {
                'enabled': True,
                'api_key': os.environ.get('DEEPSEEK_API_KEY', 'sk-2d8a7018de364da8a573a9f962062331'),
                'model': 'deepseek-chat',
                'timeout': 30,
                'max_tokens': 2000
            },
            
            # 报告配置
            'report': {
                'output_dir': 'reports',
                'format': 'html',
                'include_ai_suggestions': True
            },
            
            # PR 评论配置
            'pr_comment': {
                'enabled': False,
                'github_token': None
            },
            
            # 日志配置
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(levelname)s - %(message)s'
            }
        }
    
    def _load_env_config(self) -> Dict[str, Any]:
        """从环境变量加载配置"""
        env_config = {}
        
        # 扫描配置
        if 'HOS_LS_PARALLEL' in os.environ:
            env_config['scanner'] = env_config.get('scanner', {})
            env_config['scanner']['parallel'] = os.environ['HOS_LS_PARALLEL'].lower() == 'true'
        
        if 'HOS_LS_MAX_WORKERS' in os.environ:
            env_config['scanner'] = env_config.get('scanner', {})
            try:
                env_config['scanner']['max_workers'] = int(os.environ['HOS_LS_MAX_WORKERS'])
            except ValueError:
                pass
        
        # AI 配置
        if 'HOS_LS_AI_API_KEY' in os.environ:
            env_config['ai'] = env_config.get('ai', {})
            env_config['ai']['api_key'] = os.environ['HOS_LS_AI_API_KEY']
        
        if 'HOS_LS_AI_MODEL' in os.environ:
            env_config['ai'] = env_config.get('ai', {})
            env_config['ai']['model'] = os.environ['HOS_LS_AI_MODEL']
        
        # PR 评论配置
        if 'HOS_LS_GITHUB_TOKEN' in os.environ:
            env_config['pr_comment'] = env_config.get('pr_comment', {})
            env_config['pr_comment']['github_token'] = os.environ['HOS_LS_GITHUB_TOKEN']
            env_config['pr_comment']['enabled'] = True
        
        # 规则配置
        if 'HOS_LS_RULES_FILE' in os.environ:
            env_config['rules'] = env_config.get('rules', {})
            env_config['rules']['rules_file'] = os.environ['HOS_LS_RULES_FILE']
        
        return env_config
    
    def _load_config_file(self, config_file: str) -> Dict[str, Any]:
        """加载配置文件
        
        Args:
            config_file: 配置文件路径
            
        Returns:
            配置字典
        """
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.endswith('.json'):
                    return json.load(f)
                elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    return yaml.safe_load(f)
                else:
                    raise ValueError(f"不支持的配置文件格式: {config_file}")
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            return {}
    
    def _merge_configs(self):
        """合并配置（优先级：环境变量 > 用户配置 > 默认配置）"""
        # 先复制默认配置
        self.config = self._deep_copy(self.default_config)
        
        # 合并用户配置
        self._deep_merge(self.config, self.user_config)
        
        # 合并环境变量配置
        self._deep_merge(self.config, self.env_config)
    
    def _deep_copy(self, obj: Any) -> Any:
        """深拷贝对象"""
        if isinstance(obj, dict):
            return {k: self._deep_copy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy(item) for item in obj]
        else:
            return obj
    
    def _deep_merge(self, target: Dict[str, Any], source: Dict[str, Any]):
        """深度合并字典"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值
        
        Args:
            key: 配置键（支持点号分隔的路径，如 'scanner.parallel'）
            default: 默认值
            
        Returns:
            配置值
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """设置配置值
        
        Args:
            key: 配置键（支持点号分隔的路径，如 'scanner.parallel'）
            value: 配置值
        """
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, output_file: str = None):
        """保存配置到文件
        
        Args:
            output_file: 输出文件路径（默认使用初始化时的配置文件）
        """
        output_file = output_file or self.config_file
        if not output_file:
            raise ValueError("没有指定输出文件")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                if output_file.endswith('.json'):
                    json.dump(self.user_config, f, indent=2, ensure_ascii=False)
                elif output_file.endswith('.yaml') or output_file.endswith('.yml'):
                    yaml.dump(self.user_config, f, default_flow_style=False, allow_unicode=True)
                else:
                    raise ValueError(f"不支持的配置文件格式: {output_file}")
        except Exception as e:
            print(f"保存配置文件失败: {e}")
    
    def get_all(self) -> Dict[str, Any]:
        """获取所有配置
        
        Returns:
            完整配置字典
        """
        return self.config
    
    def get_scanner_config(self) -> Dict[str, Any]:
        """获取扫描器配置
        
        Returns:
            扫描器配置字典
        """
        return self.get('scanner', {})
    
    def get_ai_config(self) -> Dict[str, Any]:
        """获取 AI 配置
        
        Returns:
            AI 配置字典
        """
        return self.get('ai', {})
    
    def get_report_config(self) -> Dict[str, Any]:
        """获取报告配置
        
        Returns:
            报告配置字典
        """
        return self.get('report', {})
    
    def get_pr_comment_config(self) -> Dict[str, Any]:
        """获取 PR 评论配置
        
        Returns:
            PR 评论配置字典
        """
        return self.get('pr_comment', {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """获取日志配置
        
        Returns:
            日志配置字典
        """
        return self.get('logging', {})

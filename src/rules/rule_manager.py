#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则管理器

功能：
1. 加载和管理安全规则
2. 编译正则表达式规则
3. 处理误报过滤
4. 提供规则查询和管理接口
"""

import os
import re
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class RuleManager:
    """规则管理器"""
    
    def __init__(self, rules_file: str = None):
        """初始化规则管理器
        
        Args:
            rules_file: 规则文件路径（可选）
        """
        self.rules_file = rules_file
        self.rules = {}  # 原始规则
        self.false_positive_filters = {}  # 误报过滤规则
        self.compiled_rules = {}  # 编译后的规则
        
        # 加载规则
        if self.rules_file:
            self.load_rules()
            self.load_fp_filters()
            self.compile_rules()
    
    def load_rules(self) -> Dict[str, Any]:
        """加载规则配置"""
        if self.rules_file is None:
            self.rules_file = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'rules',
                'security_rules.json'
            )
        
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.rules = data.get('rules', {})
                return self.rules
        except Exception as e:
            logger.error(f"加载规则文件失败：{e}")
            return {}
    
    def load_fp_filters(self) -> Dict[str, Any]:
        """加载误报过滤配置"""
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.false_positive_filters = data.get('false_positive_filters', {})
                return self.false_positive_filters
        except Exception as e:
            logger.error(f"加载误报过滤配置失败：{e}")
            return {}
    
    def compile_rules(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """预编译正则表达式规则"""
        compiled = {}
        
        for category, rules in self.rules.items():
            if not isinstance(rules, dict):
                continue
            
            compiled[category] = {}
            for rule_name, rule in rules.items():
                patterns = rule.get('patterns', [])
                if not patterns:
                    continue
                
                compiled[category][rule_name] = {
                    'compiled_patterns': [],
                    'rule': rule
                }
                
                for pattern_str in patterns:
                    try:
                        compiled_pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                        compiled[category][rule_name]['compiled_patterns'].append(compiled_pattern)
                    except re.error as e:
                        logger.debug(f"编译规则失败 {pattern_str}: {e}")
        
        self.compiled_rules = compiled
        return compiled
    
    def get_rule(self, category: str, rule_name: str) -> Dict[str, Any]:
        """获取指定规则
        
        Args:
            category: 规则类别
            rule_name: 规则名称
            
        Returns:
            规则字典
        """
        return self.rules.get(category, {}).get(rule_name, {})
    
    def get_compiled_rule(self, category: str, rule_name: str) -> Dict[str, Any]:
        """获取编译后的规则
        
        Args:
            category: 规则类别
            rule_name: 规则名称
            
        Returns:
            编译后的规则字典
        """
        return self.compiled_rules.get(category, {}).get(rule_name, {})
    
    def get_categories(self) -> List[str]:
        """获取所有规则类别
        
        Returns:
            规则类别列表
        """
        return list(self.rules.keys())
    
    def get_rules_by_category(self, category: str) -> Dict[str, Any]:
        """获取指定类别的所有规则
        
        Args:
            category: 规则类别
            
        Returns:
            规则字典
        """
        return self.rules.get(category, {})
    
    def is_fp_path(self, file_path: str) -> bool:
        """检查是否是误报路径
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否是误报路径
        """
        path_patterns = self.false_positive_filters.get('path_patterns', [])
        
        for pattern in path_patterns:
            if pattern in file_path:
                return True
        
        return False
    
    def matches_exclude(self, content: str, line_number: int, exclude_patterns: List[str]) -> bool:
        """检查是否匹配排除模式
        
        Args:
            content: 文件内容
            line_number: 行号
            exclude_patterns: 排除模式列表
            
        Returns:
            是否匹配排除模式
        """
        if not exclude_patterns:
            return False
        
        lines = content.splitlines()
        start = max(0, line_number - 5)
        end = min(len(lines), line_number + 5)
        context = '\n'.join(lines[start:end])
        
        for pattern in exclude_patterns:
            try:
                if re.search(pattern, context, re.IGNORECASE):
                    return True
            except re.error:
                if pattern in context:
                    return True
        
        return False

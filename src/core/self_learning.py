#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自学习闭环模块

功能：
1. Payload进化库
2. 成功攻击模式抽象
3. 自动生成新规则
4. 攻击效果评估
"""

import os
import json
import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class AttackRecord:
    """攻击记录"""
    attack_type: str
    payload: str
    target: str
    is_successful: bool
    response: str
    timestamp: float
    severity: str
    confidence: float
    details: Dict[str, Any]

@dataclass
class AttackPattern:
    """攻击模式"""
    pattern_id: str
    attack_type: str
    pattern: str
    success_rate: float
    examples: List[str]
    severity: str
    confidence: float

@dataclass
class PayloadTemplate:
    """Payload模板"""
    template_id: str
    attack_type: str
    template: str
    variables: List[str]
    success_rate: float
    examples: List[str]

class SelfLearningEngine:
    """自学习引擎"""
    
    def __init__(self, storage_dir: str = 'self_learning'):
        """初始化自学习引擎
        
        Args:
            storage_dir: 存储目录
        """
        self.storage_dir = storage_dir
        self.attack_records = []
        self.attack_patterns = []
        self.payload_templates = []
        
        # 创建存储目录
        os.makedirs(self.storage_dir, exist_ok=True)
        
        # 加载数据
        self._load_data()
    
    def add_attack_record(self, record: AttackRecord):
        """添加攻击记录
        
        Args:
            record: 攻击记录
        """
        self.attack_records.append(record)
        self._save_attack_records()
    
    def analyze_attack_patterns(self):
        """分析攻击模式"""
        # 按攻击类型分组
        by_attack_type = defaultdict(list)
        for record in self.attack_records:
            if record.is_successful:
                by_attack_type[record.attack_type].append(record)
        
        # 分析每种攻击类型的模式
        new_patterns = []
        for attack_type, records in by_attack_type.items():
            # 提取payload模式
            patterns = self._extract_patterns(records)
            for pattern, examples, success_rate in patterns:
                pattern_id = f"{attack_type}_{int(time.time())}_{len(self.attack_patterns)}"
                new_pattern = AttackPattern(
                    pattern_id=pattern_id,
                    attack_type=attack_type,
                    pattern=pattern,
                    success_rate=success_rate,
                    examples=examples[:3],  # 只保存前3个示例
                    severity=records[0].severity,
                    confidence=min(0.9, sum(r.confidence for r in records) / len(records))
                )
                new_patterns.append(new_pattern)
        
        # 合并和去重
        self.attack_patterns = self._merge_patterns(self.attack_patterns + new_patterns)
        self._save_attack_patterns()
    
    def generate_payload_templates(self):
        """生成Payload模板"""
        new_templates = []
        
        # 基于攻击模式生成模板
        for pattern in self.attack_patterns:
            if pattern.success_rate > 0.5:
                template, variables = self._pattern_to_template(pattern.pattern)
                template_id = f"{pattern.attack_type}_{int(time.time())}_{len(self.payload_templates)}"
                new_template = PayloadTemplate(
                    template_id=template_id,
                    attack_type=pattern.attack_type,
                    template=template,
                    variables=variables,
                    success_rate=pattern.success_rate,
                    examples=pattern.examples
                )
                new_templates.append(new_template)
        
        # 合并和去重
        self.payload_templates = self._merge_templates(self.payload_templates + new_templates)
        self._save_payload_templates()
    
    def generate_new_rules(self) -> List[Dict[str, Any]]:
        """生成新规则
        
        Returns:
            List[Dict[str, Any]]: 新规则列表
        """
        new_rules = []
        
        # 基于攻击模式生成规则
        for pattern in self.attack_patterns:
            if pattern.success_rate > 0.7:
                rule = {
                    'id': f"auto_{pattern.pattern_id}",
                    'name': f"Auto-generated {pattern.attack_type} rule",
                    'pattern': pattern.pattern,
                    'severity': pattern.severity,
                    'description': f"Auto-generated rule for {pattern.attack_type} based on successful attacks",
                    'confidence': pattern.confidence,
                    'attack_type': pattern.attack_type,
                    'created_by': 'self_learning',
                    'created_at': time.time()
                }
                new_rules.append(rule)
        
        return new_rules
    
    def optimize_payloads(self, attack_type: str, count: int = 5) -> List[str]:
        """优化Payload
        
        Args:
            attack_type: 攻击类型
            count: 返回的Payload数量
            
        Returns:
            List[str]: 优化后的Payload列表
        """
        # 过滤该攻击类型的成功记录
        successful_records = [r for r in self.attack_records if r.attack_type == attack_type and r.is_successful]
        
        if not successful_records:
            return []
        
        # 按成功概率和置信度排序
        successful_records.sort(key=lambda x: (x.confidence, x.severity), reverse=True)
        
        # 提取前N个最成功的Payload
        optimized_payloads = [r.payload for r in successful_records[:count]]
        
        return optimized_payloads
    
    def _extract_patterns(self, records: List[AttackRecord]) -> List[tuple]:
        """提取攻击模式
        
        Args:
            records: 攻击记录列表
            
        Returns:
            List[tuple]: (模式, 示例, 成功率)
        """
        patterns = []
        
        # 简单的模式提取：基于payload的共同特征
        payloads = [r.payload for r in records]
        
        if len(payloads) >= 3:
            # 找到最长公共子串
            common_pattern = self._longest_common_substring(payloads)
            if len(common_pattern) > 3:
                # 计算成功率
                success_rate = len(records) / len([r for r in self.attack_records if r.attack_type == records[0].attack_type])
                patterns.append((common_pattern, payloads[:3], min(1.0, success_rate)))
        
        # 基于攻击类型的特定模式提取
        if records[0].attack_type == 'sql_injection':
            # SQL注入特定模式
            sql_patterns = [
                r"'\s*OR\s*1=1",
                r"'\s*UNION\s*SELECT",
                r"'\s*AND\s*1=0",
                r"'\s*;\s*DROP",
                r"'\s*--"
            ]
            
            for pattern in sql_patterns:
                matching_payloads = [r.payload for r in records if pattern in r.payload]
                if len(matching_payloads) >= 2:
                    success_rate = len(matching_payloads) / len(records)
                    if success_rate > 0.3:
                        patterns.append((pattern, matching_payloads[:3], success_rate))
        
        elif records[0].attack_type == 'xss':
            # XSS特定模式
            xss_patterns = [
                r"<script>",
                r"onerror=",
                r"onload=",
                r"javascript:",
                r"<iframe>"
            ]
            
            for pattern in xss_patterns:
                matching_payloads = [r.payload for r in records if pattern in r.payload]
                if len(matching_payloads) >= 2:
                    success_rate = len(matching_payloads) / len(records)
                    if success_rate > 0.3:
                        patterns.append((pattern, matching_payloads[:3], success_rate))
        
        return patterns
    
    def _pattern_to_template(self, pattern: str) -> tuple:
        """将模式转换为模板
        
        Args:
            pattern: 攻击模式
            
        Returns:
            tuple: (模板, 变量列表)
        """
        # 简单的模板生成
        variables = []
        template = pattern
        
        # 替换数字为变量
        import re
        number_patterns = re.findall(r'\d+', pattern)
        for i, number in enumerate(number_patterns):
            var_name = f"{{NUM{i}}}"
            template = template.replace(number, var_name)
            variables.append(f"NUM{i}")
        
        # 替换字符串为变量
        string_patterns = re.findall(r'"([^"]+)"', pattern)
        for i, string in enumerate(string_patterns):
            var_name = f"{{STR{i}}}"
            template = template.replace(f"\"{string}\"", var_name)
            variables.append(f"STR{i}")
        
        return template, variables
    
    def _longest_common_substring(self, strings: List[str]) -> str:
        """找到最长公共子串
        
        Args:
            strings: 字符串列表
            
        Returns:
            str: 最长公共子串
        """
        if not strings:
            return ""
        
        shortest = min(strings, key=len)
        for length in range(len(shortest), 0, -1):
            for i in range(len(shortest) - length + 1):
                candidate = shortest[i:i+length]
                if all(candidate in s for s in strings):
                    return candidate
        
        return ""
    
    def _merge_patterns(self, patterns: List[AttackPattern]) -> List[AttackPattern]:
        """合并相似的攻击模式
        
        Args:
            patterns: 攻击模式列表
            
        Returns:
            List[AttackPattern]: 合并后的攻击模式列表
        """
        merged = []
        seen = set()
        
        for pattern in patterns:
            # 检查是否与已合并的模式相似
            is_duplicate = False
            for existing in merged:
                if pattern.attack_type == existing.attack_type:
                    # 检查模式是否相似
                    if (pattern.pattern in existing.pattern or 
                        existing.pattern in pattern.pattern):
                        # 合并相似模式
                        existing.success_rate = max(existing.success_rate, pattern.success_rate)
                        existing.examples = list(set(existing.examples + pattern.examples))[:3]
                        existing.confidence = max(existing.confidence, pattern.confidence)
                        is_duplicate = True
                        break
            
            if not is_duplicate:
                merged.append(pattern)
        
        return merged
    
    def _merge_templates(self, templates: List[PayloadTemplate]) -> List[PayloadTemplate]:
        """合并相似的Payload模板
        
        Args:
            templates: Payload模板列表
            
        Returns:
            List[PayloadTemplate]: 合并后的Payload模板列表
        """
        merged = []
        
        for template in templates:
            # 检查是否与已合并的模板相似
            is_duplicate = False
            for existing in merged:
                if template.attack_type == existing.attack_type:
                    # 检查模板是否相似
                    if (template.template in existing.template or 
                        existing.template in template.template):
                        # 合并相似模板
                        existing.success_rate = max(existing.success_rate, template.success_rate)
                        existing.examples = list(set(existing.examples + template.examples))[:3]
                        is_duplicate = True
                        break
            
            if not is_duplicate:
                merged.append(template)
        
        return merged
    
    def _save_attack_records(self):
        """保存攻击记录"""
        file_path = os.path.join(self.storage_dir, 'attack_records.json')
        data = []
        for record in self.attack_records:
            data.append({
                'attack_type': record.attack_type,
                'payload': record.payload,
                'target': record.target,
                'is_successful': record.is_successful,
                'response': record.response,
                'timestamp': record.timestamp,
                'severity': record.severity,
                'confidence': record.confidence,
                'details': record.details
            })
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _save_attack_patterns(self):
        """保存攻击模式"""
        file_path = os.path.join(self.storage_dir, 'attack_patterns.json')
        data = []
        for pattern in self.attack_patterns:
            data.append({
                'pattern_id': pattern.pattern_id,
                'attack_type': pattern.attack_type,
                'pattern': pattern.pattern,
                'success_rate': pattern.success_rate,
                'examples': pattern.examples,
                'severity': pattern.severity,
                'confidence': pattern.confidence
            })
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _save_payload_templates(self):
        """保存Payload模板"""
        file_path = os.path.join(self.storage_dir, 'payload_templates.json')
        data = []
        for template in self.payload_templates:
            data.append({
                'template_id': template.template_id,
                'attack_type': template.attack_type,
                'template': template.template,
                'variables': template.variables,
                'success_rate': template.success_rate,
                'examples': template.examples
            })
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _load_data(self):
        """加载数据"""
        # 加载攻击记录
        records_file = os.path.join(self.storage_dir, 'attack_records.json')
        if os.path.exists(records_file):
            try:
                with open(records_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    record = AttackRecord(
                        attack_type=item['attack_type'],
                        payload=item['payload'],
                        target=item['target'],
                        is_successful=item['is_successful'],
                        response=item['response'],
                        timestamp=item['timestamp'],
                        severity=item['severity'],
                        confidence=item['confidence'],
                        details=item['details']
                    )
                    self.attack_records.append(record)
            except Exception as e:
                logger.error(f"加载攻击记录失败：{e}")
        
        # 加载攻击模式
        patterns_file = os.path.join(self.storage_dir, 'attack_patterns.json')
        if os.path.exists(patterns_file):
            try:
                with open(patterns_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    pattern = AttackPattern(
                        pattern_id=item['pattern_id'],
                        attack_type=item['attack_type'],
                        pattern=item['pattern'],
                        success_rate=item['success_rate'],
                        examples=item['examples'],
                        severity=item['severity'],
                        confidence=item['confidence']
                    )
                    self.attack_patterns.append(pattern)
            except Exception as e:
                logger.error(f"加载攻击模式失败：{e}")
        
        # 加载Payload模板
        templates_file = os.path.join(self.storage_dir, 'payload_templates.json')
        if os.path.exists(templates_file):
            try:
                with open(templates_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    template = PayloadTemplate(
                        template_id=item['template_id'],
                        attack_type=item['attack_type'],
                        template=item['template'],
                        variables=item['variables'],
                        success_rate=item['success_rate'],
                        examples=item['examples']
                    )
                    self.payload_templates.append(template)
            except Exception as e:
                logger.error(f"加载Payload模板失败：{e}")

if __name__ == '__main__':
    # 测试自学习引擎
    engine = SelfLearningEngine()
    
    # 添加测试攻击记录
    test_records = [
        AttackRecord(
            attack_type='sql_injection',
            payload="' OR 1=1 --",
            target="http://example.com/login",
            is_successful=True,
            response="Welcome admin",
            timestamp=time.time(),
            severity='high',
            confidence=0.9,
            details={'evidence': 'SQL error detected'}
        ),
        AttackRecord(
            attack_type='sql_injection',
            payload="' OR 1=1#",
            target="http://example.com/login",
            is_successful=True,
            response="Welcome admin",
            timestamp=time.time(),
            severity='high',
            confidence=0.85,
            details={'evidence': 'SQL error detected'}
        ),
        AttackRecord(
            attack_type='xss',
            payload="<script>alert(1)</script>",
            target="http://example.com/search",
            is_successful=True,
            response="<script>alert(1)</script>",
            timestamp=time.time(),
            severity='medium',
            confidence=0.9,
            details={'evidence': 'XSS payload detected'}
        ),
        AttackRecord(
            attack_type='xss',
            payload='<img src=x onerror=alert(1)>',
            target='http://example.com/search',
            is_successful=True,
            response='<img src=x onerror=alert(1)>',
            timestamp=time.time(),
            severity='medium',
            confidence=0.85,
            details={'evidence': 'XSS payload detected'}
        )
    ]
    
    for record in test_records:
        engine.add_attack_record(record)
    
    # 分析攻击模式
    engine.analyze_attack_patterns()
    print(f"发现 {len(engine.attack_patterns)} 个攻击模式")
    for pattern in engine.attack_patterns:
        print(f"\n攻击模式: {pattern.pattern_id}")
        print(f"  类型: {pattern.attack_type}")
        print(f"  模式: {pattern.pattern}")
        print(f"  成功率: {pattern.success_rate:.2f}")
        print(f"  示例: {pattern.examples}")
    
    # 生成Payload模板
    engine.generate_payload_templates()
    print(f"\n生成 {len(engine.payload_templates)} 个Payload模板")
    for template in engine.payload_templates:
        print(f"\nPayload模板: {template.template_id}")
        print(f"  类型: {template.attack_type}")
        print(f"  模板: {template.template}")
        print(f"  变量: {template.variables}")
        print(f"  成功率: {template.success_rate:.2f}")
    
    # 生成新规则
    new_rules = engine.generate_new_rules()
    print(f"\n生成 {len(new_rules)} 个新规则")
    for rule in new_rules:
        print(f"\n新规则: {rule['id']}")
        print(f"  名称: {rule['name']}")
        print(f"  模式: {rule['pattern']}")
        print(f"  严重程度: {rule['severity']}")
    
    # 优化Payload
    optimized_payloads = engine.optimize_payloads('sql_injection', 2)
    print(f"\n优化的SQL注入Payload:")
    for i, payload in enumerate(optimized_payloads):
        print(f"  {i+1}. {payload}")

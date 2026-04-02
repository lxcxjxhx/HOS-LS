#!/usr/bin/env python3
"""
安全规则管理模块

功能：
1. 加载和解析安全规则配置
2. 支持将规则翻译成不同工具的格式（Cursor、Trae、Kiro）
3. 提供规则查询和过滤功能
4. 支持规则集的动态更新
"""

import json
import os
from .rule_set_manager import RuleSetManager

class RuleManager:
    def __init__(self, rules_file=None):
        """初始化规则管理器"""
        if rules_file is None:
            # 默认规则文件路径
            self.rules_file = os.path.join(os.path.dirname(__file__), 'security_rules.json')
        else:
            self.rules_file = rules_file
        
        self.rules = {}
        self.tool_formats = {}
        self.rule_set_manager = RuleSetManager()
        self.load_rules()
    
    def load_rules(self):
        """加载规则配置文件"""
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.rules = data.get('rules', {})
                self.tool_formats = data.get('tool_formats', {})
            print(f"成功加载规则文件: {self.rules_file}")
        except Exception as e:
            print(f"加载规则文件失败: {e}")
            self.rules = {}
            self.tool_formats = {}
    
    def get_rules(self, category=None, severity=None):
        """获取规则列表，可按类别和严重程度过滤"""
        result = []
        
        # 遍历所有规则类别
        for category_name, category_rules in self.rules.items():
            if category and category_name != category:
                continue
            
            for rule_name, rule in category_rules.items():
                if severity and rule.get('severity') != severity:
                    continue
                
                rule_info = {
                    'id': rule_name,
                    'category': category_name,
                    'description': rule.get('description', ''),
                    'severity': rule.get('severity', 'MEDIUM'),
                    'fix': rule.get('fix', ''),
                    'patterns': rule.get('patterns', []),
                    'exclude_patterns': rule.get('exclude_patterns', [])
                }
                result.append(rule_info)
        
        return result
    
    def translate_rules(self, tool_name, categories=None, severity=None):
        """将规则翻译成特定工具的格式"""
        if tool_name not in self.tool_formats:
            return f"错误: 不支持的工具类型: {tool_name}"
        
        format_config = self.tool_formats[tool_name]
        rules = self.get_rules(categories, severity)
        
        # 构建提示词
        prompt = format_config.get('prompt_prefix', '') + '\n'
        
        for rule in rules:
            rule_text = format_config.get('rule_format', '{description}: {fix}')
            rule_text = rule_text.format(
                description=rule['description'],
                fix=rule['fix'],
                severity=rule['severity']
            )
            prompt += rule_text + '\n'
        
        prompt += '\n' + format_config.get('footer', '')
        
        return prompt
    
    def get_openclaw_rules(self):
        """获取OpenClaw特化规则"""
        return self.get_rules('openclaw_security')
    
    def get_cursor_rules(self):
        """获取Cursor特化规则"""
        return self.get_rules('cursor_security')
    
    def get_high_severity_rules(self):
        """获取高风险规则"""
        return self.get_rules(severity='HIGH')
    
    def get_rules_by_rule_set(self, rule_set_name):
        """根据规则集获取规则"""
        filtered_rules = self.rule_set_manager.filter_rules_by_rule_set(self.rules, rule_set_name)
        return filtered_rules
    
    def get_rules_for_project(self, project_path):
        """根据项目路径获取适合的规则"""
        rule_set_name = self.rule_set_manager.get_project_rule_set(project_path)
        return self.get_rules_by_rule_set(rule_set_name)
    
    def detect_project_type(self, project_path):
        """检测项目类型"""
        return self.rule_set_manager.detect_project_type(project_path)
    
    def get_project_rule_set(self, project_path):
        """获取项目对应的规则集"""
        return self.rule_set_manager.get_project_rule_set(project_path)
    
    def list_rule_sets(self):
        """列出所有规则集"""
        return self.rule_set_manager.list_rule_sets()
    
    def update_rules(self, new_rules):
        """更新规则集"""
        try:
            self.rules.update(new_rules)
            self.save_rules()
            return True
        except Exception as e:
            print(f"更新规则失败: {e}")
            return False
    
    def save_rules(self):
        """保存规则到文件"""
        try:
            data = {
                'version': '1.0',
                'rules': self.rules,
                'tool_formats': self.tool_formats
            }
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"规则已保存到: {self.rules_file}")
            return True
        except Exception as e:
            print(f"保存规则失败: {e}")
            return False

if __name__ == '__main__':
    # 测试规则管理器
    manager = RuleManager()
    
    # 测试获取所有规则
    print("\n=== 所有规则 ===")
    all_rules = manager.get_rules()
    for rule in all_rules[:5]:  # 只显示前5个
        print(f"{rule['category']} - {rule['id']}: {rule['description']} ({rule['severity']})")
    
    # 测试获取高风险规则
    print("\n=== 高风险规则 ===")
    high_rules = manager.get_high_severity_rules()
    for rule in high_rules:
        print(f"{rule['category']} - {rule['id']}: {rule['description']}")
    
    # 测试翻译规则到Cursor格式
    print("\n=== Cursor格式规则 ===")
    cursor_prompt = manager.translate_rules('cursor')
    print(cursor_prompt)
    
    # 测试翻译规则到Trae格式
    print("\n=== Trae格式规则 ===")
    trae_prompt = manager.translate_rules('trae')
    print(trae_prompt)
    
    # 测试获取OpenClaw规则
    print("\n=== OpenClaw特化规则 ===")
    openclaw_rules = manager.get_openclaw_rules()
    for rule in openclaw_rules:
        print(f"{rule['id']}: {rule['description']} - {rule['fix']}")

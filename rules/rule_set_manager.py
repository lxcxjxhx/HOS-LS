#!/usr/bin/env python3
"""
规则集管理模块

功能：
1. 加载和管理不同的规则集配置
2. 检测项目类型并选择合适的规则集
3. 根据规则集过滤规则
4. 支持自定义规则集
"""

import json
import os
import re

class RuleSetManager:
    def __init__(self, rule_sets_file=None):
        """初始化规则集管理器"""
        if rule_sets_file is None:
            # 默认规则集文件路径
            self.rule_sets_file = os.path.join(os.path.dirname(__file__), 'rule_sets.json')
        else:
            self.rule_sets_file = rule_sets_file
        
        self.rule_sets = {}
        self.project_types = {}
        self.load_rule_sets()
    
    def load_rule_sets(self):
        """加载规则集配置文件"""
        try:
            with open(self.rule_sets_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.rule_sets = data.get('rule_sets', {})
                self.project_types = data.get('project_types', {})
            print(f"成功加载规则集配置: {self.rule_sets_file}")
        except Exception as e:
            print(f"加载规则集配置失败: {e}")
            self.rule_sets = {}
            self.project_types = {}
    
    def get_rule_set(self, rule_set_name):
        """获取指定规则集"""
        return self.rule_sets.get(rule_set_name, None)
    
    def detect_project_type(self, project_path):
        """检测项目类型"""
        project_type = "default"
        max_matches = 0
        
        # 遍历项目文件，检测项目类型
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.txt')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # 检测每个项目类型的模式
                            for type_name, type_info in self.project_types.items():
                                patterns = type_info.get('detect_patterns', [])
                                matches = 0
                                
                                for pattern in patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        matches += 1
                                
                                if matches > max_matches:
                                    max_matches = matches
                                    project_type = type_name
                    except Exception as e:
                        pass
        
        return project_type
    
    def get_project_rule_set(self, project_path):
        """获取项目对应的规则集"""
        project_type = self.detect_project_type(project_path)
        if project_type in self.project_types:
            rule_set_name = self.project_types[project_type].get('rule_set', 'default')
            return rule_set_name
        return 'default'
    
    def get_enabled_rules(self, rule_set_name):
        """获取规则集中启用的规则"""
        rule_set = self.get_rule_set(rule_set_name)
        if rule_set:
            return rule_set.get('enabled_rules', [])
        return []
    
    def filter_rules_by_rule_set(self, all_rules, rule_set_name):
        """根据规则集过滤规则"""
        enabled_rules = self.get_enabled_rules(rule_set_name)
        filtered_rules = {}
        
        for rule_id in enabled_rules:
            # 解析规则ID，格式为 category.rule_name
            if '.' in rule_id:
                category, rule_name = rule_id.split('.', 1)
                if category in all_rules and rule_name in all_rules[category]:
                    if category not in filtered_rules:
                        filtered_rules[category] = {}
                    filtered_rules[category][rule_name] = all_rules[category][rule_name]
        
        return filtered_rules
    
    def create_custom_rule_set(self, name, description, enabled_rules):
        """创建自定义规则集"""
        self.rule_sets[name] = {
            "name": name,
            "description": description,
            "enabled_rules": enabled_rules
        }
        self.save_rule_sets()
        return True
    
    def update_rule_set(self, name, updates):
        """更新规则集"""
        if name in self.rule_sets:
            self.rule_sets[name].update(updates)
            self.save_rule_sets()
            return True
        return False
    
    def save_rule_sets(self):
        """保存规则集配置"""
        try:
            data = {
                'version': '1.0',
                'rule_sets': self.rule_sets,
                'project_types': self.project_types
            }
            with open(self.rule_sets_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"规则集配置已保存到: {self.rule_sets_file}")
            return True
        except Exception as e:
            print(f"保存规则集配置失败: {e}")
            return False
    
    def list_rule_sets(self):
        """列出所有规则集"""
        rule_sets = []
        for name, info in self.rule_sets.items():
            rule_sets.append({
                'name': name,
                'display_name': info.get('name', name),
                'description': info.get('description', ''),
                'rule_count': len(info.get('enabled_rules', []))
            })
        return rule_sets
    
    def list_project_types(self):
        """列出所有项目类型"""
        project_types = []
        for name, info in self.project_types.items():
            project_types.append({
                'name': name,
                'display_name': info.get('name', name),
                'rule_set': info.get('rule_set', 'default'),
                'detect_patterns': info.get('detect_patterns', [])
            })
        return project_types

if __name__ == '__main__':
    # 测试规则集管理器
    manager = RuleSetManager()
    
    # 测试列出规则集
    print("\n=== 所有规则集 ===")
    rule_sets = manager.list_rule_sets()
    for rule_set in rule_sets:
        print(f"{rule_set['name']} - {rule_set['display_name']} ({rule_set['rule_count']} 条规则)")
        print(f"  描述: {rule_set['description']}")
    
    # 测试列出项目类型
    print("\n=== 所有项目类型 ===")
    project_types = manager.list_project_types()
    for project_type in project_types:
        print(f"{project_type['name']} - {project_type['display_name']}")
        print(f"  规则集: {project_type['rule_set']}")
        print(f"  检测模式: {', '.join(project_type['detect_patterns'])}")
    
    # 测试获取规则集
    print("\n=== 获取默认规则集 ===")
    default_rule_set = manager.get_rule_set('default')
    if default_rule_set:
        print(f"名称: {default_rule_set['name']}")
        print(f"描述: {default_rule_set['description']}")
        print(f"启用的规则: {len(default_rule_set['enabled_rules'])} 条")
    
    # 测试获取启用的规则
    print("\n=== 默认规则集启用的规则 ===")
    enabled_rules = manager.get_enabled_rules('default')
    for rule in enabled_rules:
        print(f"- {rule}")

"""custom_priority_parser.py 单元测试

验证关联文件筛选功能：
1. 配置文件解析正常
2. 相关文件规则生效
3. 调用链和数据流规则解析
"""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from src.utils.custom_priority_parser import (
    CustomPriorityParser, PriorityRules, RelatedFileRules,
    CallChainRules, DataFlowRules, PriorityWeights, PriorityLevel
)


def test_load_from_dict():
    """测试从字典加载配置"""
    parser = CustomPriorityParser()
    
    config = {
        "priority_rules": {
            "custom": {
                "name": "测试规则",
                "keywords": {
                    "high_priority": ["auth", "password", "token"],
                    "medium_priority": ["config", "database"],
                    "low_priority": ["utils", "helper"]
                },
                "file_patterns": {
                    "high_priority": ["*.conf", "*.env"],
                    "medium_priority": ["*.yaml", "*.json"],
                    "low_priority": ["*.txt", "*.md"]
                },
                "path_rules": {
                    "high_priority": ["**/security/**", "**/auth/**"],
                    "medium_priority": ["**/config/**"],
                    "low_priority": ["**/docs/**"]
                }
            }
        }
    }
    
    parser.load_from_dict(config)
    rules_dict = parser.parse()
    
    assert rules_dict["name"] == "测试规则"
    assert "auth" in rules_dict["keywords"]["high_priority"]
    assert "*.conf" in rules_dict["file_patterns"]["high_priority"]
    print("[PASS] test_load_from_dict")


def test_load_from_yaml_file():
    """测试从 YAML 文件加载配置"""
    parser = CustomPriorityParser()
    
    yaml_content = """
priority_rules:
  custom:
    name: "YAML测试规则"
    keywords:
      high_priority:
        - "admin"
        - "secret"
      medium_priority:
        - "config"
    file_patterns:
      high_priority:
        - "*.xml"
        - "*.yml"
    path_rules:
      high_priority:
        - "**/api/**"
    related_file_rules:
      keywords:
        - "import"
        - "require"
      patterns:
        - "*.py"
        - "*.java"
    call_chain_rules:
      java_patterns:
        - "@Autowired"
        - "@Inject"
      python_patterns:
        - "from . import"
        - "import"
    data_flow_rules:
      java_patterns:
        - "@RequestParam"
        - "@RequestBody"
      python_patterns:
        - "request.args"
        - "request.form"
    weights:
      keyword_match: 0.5
      file_pattern: 0.3
      path_match: 0.2
    correlation_weights:
      related_file: 0.4
      call_chain: 0.4
      data_flow: 0.2
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
        f.write(yaml_content)
        temp_path = f.name
    
    try:
        parser.load_from_file(temp_path)
        rules_dict = parser.parse()
        
        assert rules_dict["name"] == "YAML测试规则"
        assert "admin" in rules_dict["keywords"]["high_priority"]
        assert "*.xml" in rules_dict["file_patterns"]["high_priority"]
        
        assert rules_dict["related_file_rules"] != {}
        assert "import" in rules_dict["related_file_rules"]["keywords"]
        assert "*.py" in rules_dict["related_file_rules"]["patterns"]
        
        assert rules_dict["call_chain_rules"] != {}
        assert "@Autowired" in rules_dict["call_chain_rules"]["java_patterns"]
        
        assert rules_dict["data_flow_rules"] != {}
        assert "@RequestParam" in rules_dict["data_flow_rules"]["java_patterns"]
        
        print("[PASS] test_load_from_yaml_file")
    finally:
        os.unlink(temp_path)


def test_priority_evaluation():
    """测试优先级评估功能"""
    parser = CustomPriorityParser()
    
    config = {
        "priority_rules": {
            "custom": {
                "name": "评估测试",
                "keywords": {
                    "high_priority": ["auth", "security"],
                    "medium_priority": ["config"],
                    "low_priority": []
                },
                "file_patterns": {
                    "high_priority": ["*.conf"],
                    "medium_priority": [],
                    "low_priority": []
                },
                "path_rules": {
                    "high_priority": ["**/security/**"],
                    "medium_priority": [],
                    "low_priority": []
                }
            }
        }
    }
    
    parser.load_from_dict(config)
    parser.parse()
    
    result = parser.get_priority("test.py")
    assert isinstance(result.priority_level, PriorityLevel)
    assert hasattr(result, 'matched_keywords')
    assert hasattr(result, 'correlation_score')
    print("[PASS] test_priority_evaluation")


def test_related_file_rules_parsing():
    """测试关联文件规则解析"""
    parser = CustomPriorityParser()
    
    config = {
        "priority_rules": {
            "custom": {
                "name": "关联文件测试",
                "keywords": {},
                "file_patterns": {},
                "path_rules": {},
                "related_file_rules": {
                    "keywords": ["service", "repository", "controller"],
                    "patterns": ["*.java", "*.py"]
                },
                "call_chain_rules": {
                    "java_patterns": ["@Autowired", "new Service("],
                    "python_patterns": ["from . import", "import"]
                },
                "data_flow_rules": {
                    "java_patterns": ["@RequestParam", "@RequestBody"],
                    "python_patterns": ["request.args", "request.json"]
                }
            }
        }
    }
    
    parser.load_from_dict(config)
    rules = parser.parse()
    
    assert rules["related_file_rules"]["keywords"] == ["service", "repository", "controller"]
    assert rules["related_file_rules"]["patterns"] == ["*.java", "*.py"]
    assert rules["call_chain_rules"]["java_patterns"] == ["@Autowired", "new Service("]
    assert rules["data_flow_rules"]["python_patterns"] == ["request.args", "request.json"]
    
    rules_obj = parser.get_rules()
    assert isinstance(rules_obj.related_file_rules, RelatedFileRules)
    assert isinstance(rules_obj.call_chain_rules, CallChainRules)
    assert isinstance(rules_obj.data_flow_rules, DataFlowRules)
    
    print("[PASS] test_related_file_rules_parsing")


def test_correlation_weights():
    """测试相关性权重配置"""
    parser = CustomPriorityParser()
    
    config = {
        "priority_rules": {
            "custom": {
                "name": "权重测试",
                "keywords": {},
                "file_patterns": {},
                "path_rules": {},
                "correlation_weights": {
                    "related_file": 0.5,
                    "call_chain": 0.3,
                    "data_flow": 0.2
                }
            }
        }
    }
    
    parser.load_from_dict(config)
    rules = parser.parse()
    
    assert rules["weights"]["related_file"] == 0.5
    assert rules["weights"]["call_chain"] == 0.3
    assert rules["weights"]["data_flow"] == 0.2
    
    print("[PASS] test_correlation_weights")


if __name__ == "__main__":
    test_load_from_dict()
    test_load_from_yaml_file()
    test_priority_evaluation()
    test_related_file_rules_parsing()
    test_correlation_weights()
    print("\n[INFO] 所有 custom_priority_parser 测试通过！")

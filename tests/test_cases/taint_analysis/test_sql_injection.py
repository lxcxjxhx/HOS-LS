"""SQL注入漏洞测试用例"""

import pytest

# 直接从文件路径导入 AnalysisContext，避免触发 __init__.py 中的 CSTAnalyzer 导入
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# 直接导入 AnalysisContext
from src.analyzers.base import AnalysisContext
from src.taint.analyzer import TaintAnalyzer
from src.exploit.generator import ExploitGenerator


def test_sql_injection_detection():
    """测试SQL注入漏洞检测"""
    # 测试代码
    code = '''
    user = input()
    query = "SELECT * FROM users WHERE name = '" + user + "'"
    execute(query)
    '''
    
    # 创建分析上下文
    context = AnalysisContext(
        file_path="test.py",
        file_content=code,
        language="python"
    )
    
    # 执行污点分析
    taint_analyzer = TaintAnalyzer()
    paths = taint_analyzer.analyze(context)
    
    # 验证是否检测到漏洞
    assert len(paths) > 0
    
    # 验证漏洞类型
    path = paths[0]
    assert path.sink.vulnerability_type == "SQL Injection"
    
    # 验证传播路径
    assert "user" in path.path
    assert "execute" in path.path


def test_sql_injection_poc():
    """测试SQL注入PoC生成"""
    # 测试代码
    code = '''
    user = input()
    query = "SELECT * FROM users WHERE name = '" + user + "'"
    execute(query)
    '''
    
    # 创建分析上下文
    context = AnalysisContext(
        file_path="test.py",
        file_content=code,
        language="python"
    )
    
    # 执行污点分析
    taint_analyzer = TaintAnalyzer()
    paths = taint_analyzer.analyze(context)
    
    # 生成PoC
    exploit_generator = ExploitGenerator()
    poc = exploit_generator.generate_poc(paths[0])
    
    # 验证PoC是否生成
    assert poc is not None
    assert "' OR 1=1 --" in poc


def test_command_injection_detection():
    """测试命令注入漏洞检测"""
    # 测试代码
    code = '''
    user_input = input()
    os.system("echo " + user_input)
    '''
    
    # 创建分析上下文
    context = AnalysisContext(
        file_path="test.py",
        file_content=code,
        language="python"
    )
    
    # 执行污点分析
    taint_analyzer = TaintAnalyzer()
    paths = taint_analyzer.analyze(context)
    
    # 验证是否检测到漏洞
    assert len(paths) > 0
    
    # 验证漏洞类型
    path = paths[0]
    assert path.sink.vulnerability_type == "Command Injection"


def test_code_injection_detection():
    """测试代码注入漏洞检测"""
    # 测试代码
    code = '''
    user_input = input()
    eval(user_input)
    '''
    
    # 创建分析上下文
    context = AnalysisContext(
        file_path="test.py",
        file_content=code,
        language="python"
    )
    
    # 执行污点分析
    taint_analyzer = TaintAnalyzer()
    paths = taint_analyzer.analyze(context)
    
    # 验证是否检测到漏洞
    assert len(paths) > 0
    
    # 验证漏洞类型
    path = paths[0]
    assert path.sink.vulnerability_type == "Code Injection"


def test_attack_chain_generation():
    """测试攻击链生成"""
    # 测试代码
    code = '''
    user = input()
    query = "SELECT * FROM users WHERE name = '" + user + "'"
    execute(query)
    '''
    
    # 创建分析上下文
    context = AnalysisContext(
        file_path="test.py",
        file_content=code,
        language="python"
    )
    
    # 执行污点分析
    taint_analyzer = TaintAnalyzer()
    paths = taint_analyzer.analyze(context)
    
    # 生成攻击链
    exploit_generator = ExploitGenerator()
    attack_chain = exploit_generator.generate_attack_chain(paths[0])
    
    # 验证攻击链格式
    assert "source" in attack_chain
    assert "path" in attack_chain
    assert "sink" in attack_chain
    assert "vulnerability" in attack_chain
    assert "poc" in attack_chain
    
    # 验证攻击链内容
    assert "用户输入" in attack_chain["source"]
    assert "execute" in attack_chain["sink"]
    assert attack_chain["vulnerability"] == "SQL Injection"
    assert attack_chain["poc"] == "' OR 1=1 --"
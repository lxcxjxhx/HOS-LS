import pytest
from src.core.langgraph_state import ScanState, create_initial_state, evaluate_complexity
from src.core.config import Config


def test_create_initial_state():
    """测试创建初始状态"""
    config = Config()
    state = create_initial_state("test.py", config)
    
    assert state.target == "test.py"
    assert state.config == config
    assert state.code_analysis_result is None
    assert state.rag == []
    assert state.attack_paths == []
    assert state.scan_result is None
    assert state.needs_rag is False
    assert state.needs_graph is False
    assert state.is_simple is False


def test_state_update():
    """测试状态更新"""
    config = Config()
    state = create_initial_state("test.py", config)
    
    # 更新状态
    updated_state = state.update(
        code_analysis_result={"complexity": "high"},
        needs_rag=True,
        is_simple=False
    )
    
    assert updated_state.code_analysis_result == {"complexity": "high"}
    assert updated_state.needs_rag is True
    assert updated_state.is_simple is False
    assert updated_state.target == "test.py"  # 确保其他字段不变


def test_evaluate_complexity():
    """测试代码复杂度评估"""
    # 测试简单代码
    simple_code = """def hello():
    print('Hello world')
"""
    complexity = evaluate_complexity(simple_code)
    assert isinstance(complexity, float)
    assert complexity < 0.5  # 简单代码复杂度低
    
    # 测试复杂代码（超过50行）
    complex_code = "def hello():\n" + "    print('Hello')\n" * 60
    complexity = evaluate_complexity(complex_code)
    assert isinstance(complexity, float)
    assert complexity > 0.2  # 60行代码的复杂度约为0.3
    
    # 测试包含高风险模式的代码
    risky_code = """def dangerous():
    eval('print("hacked")')
"""
    complexity = evaluate_complexity(risky_code)
    assert isinstance(complexity, float)


def test_state_to_dict():
    """测试状态转换为字典"""
    config = Config()
    state = create_initial_state("test.py", config)
    state_dict = state.to_dict()
    
    assert state_dict['target'] == "test.py"
    assert state_dict['needs_rag'] is False
    assert state_dict['is_simple'] is False


def test_state_from_dict():
    """测试从字典创建状态"""
    config = Config()
    state_dict = {
        'target': 'test.py',
        'config': config,
        'code_analysis_result': {'complexity': 'high'},
        'needs_rag': True,
        'is_simple': False
    }
    state = ScanState.from_dict(state_dict)
    
    assert state.target == 'test.py'
    assert state.code_analysis_result == {'complexity': 'high'}
    assert state.needs_rag is True
    assert state.is_simple is False
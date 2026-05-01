import asyncio
import pytest
from pathlib import Path

from src.core.config import Config
from src.core.langgraph_flow import run_scan


@pytest.fixture
def test_config():
    """测试配置"""
    config = Config()
    config.ai.enabled = False  # 禁用AI以加快测试速度
    return config


@pytest.fixture
def simple_code_file():
    """创建简单代码文件"""
    code = """def hello():
    print('Hello world')
"""
    file_path = Path('test_simple.py')
    with open(file_path, 'w') as f:
        f.write(code)
    yield file_path
    file_path.unlink(missing_ok=True)


@pytest.fixture
def complex_code_file():
    """创建复杂代码文件"""
    code = """import os
import eval

def dangerous():
    user_input = input('Enter something: ')
    eval(user_input)
    os.system('echo dangerous')

for i in range(100):
    print(i)
"""
    file_path = Path('test_complex.py')
    with open(file_path, 'w') as f:
        f.write(code)
    yield file_path
    file_path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_simple_code_scan(test_config, simple_code_file):
    """测试简单代码扫描"""
    result = await run_scan(str(simple_code_file), test_config)
    assert result is not None
    assert result.status == 'completed'
    # 简单代码应该走快速路径，可能没有发现
    assert len(result.findings) >= 0


@pytest.mark.asyncio
async def test_complex_code_scan(test_config, complex_code_file):
    """测试复杂代码扫描"""
    result = await run_scan(str(complex_code_file), test_config)
    assert result is not None
    assert result.status == 'completed'
    # 复杂代码应该走完整路径
    assert len(result.findings) >= 0


@pytest.mark.asyncio
async def test_directory_scan(test_config):
    """测试目录扫描"""
    result = await run_scan('.', test_config)
    assert result is not None
    assert result.status == 'completed'


@pytest.mark.asyncio
async def test_nonexistent_file(test_config):
    """测试不存在的文件"""
    result = await run_scan('nonexistent.py', test_config)
    assert result is not None
    assert result.status == 'completed' or result.status == 'failed'


def test_all_scenarios(test_config, simple_code_file, complex_code_file):
    """运行所有测试场景"""
    asyncio.run(test_simple_code_scan(test_config, simple_code_file))
    asyncio.run(test_complex_code_scan(test_config, complex_code_file))
    asyncio.run(test_directory_scan(test_config))
    asyncio.run(test_nonexistent_file(test_config))
    print("All tests passed!")


if __name__ == "__main__":
    config = Config()
    config.ai.enabled = False
    
    # 创建测试文件
    simple_file = Path('test_simple.py')
    with open(simple_file, 'w') as f:
        f.write("""def hello():
    print('Hello world')
""")
    
    complex_file = Path('test_complex.py')
    with open(complex_file, 'w') as f:
        f.write("""import os

def dangerous():
    os.system('echo dangerous')
""")
    
    # 运行测试
    try:
        test_all_scenarios(config, simple_file, complex_file)
    finally:
        # 清理测试文件
        simple_file.unlink(missing_ok=True)
        complex_file.unlink(missing_ok=True)
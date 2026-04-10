"""测试配置

pytest 配置和共享 fixture。
"""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def test_data_dir():
    """测试数据目录"""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def vulnerable_code_dir(test_data_dir):
    """漏洞代码目录"""
    return test_data_dir / "vulnerable_code"


@pytest.fixture
def safe_code_dir(test_data_dir):
    """安全代码目录"""
    return test_data_dir / "safe_code"


@pytest.fixture
def mock_config():
    """模拟配置"""
    from src.core.config import Config

    return Config(
        ai={"provider": "anthropic", "model": "claude-3-5-sonnet-20241022"},
        scan={"max_workers": 2, "cache_enabled": False, "incremental": False},
        rules={"ruleset": "default", "severity_threshold": "low"},
        report={"format": "json", "output": "./test-output"},
    )


@pytest.fixture
def rule_registry():
    """规则注册表 fixture"""
    from src.rules.registry import RuleRegistry
    
    registry = RuleRegistry()
    registry.load_builtin_rules()
    return registry


@pytest.fixture
def sample_sql_injection_code():
    """SQL 注入示例代码"""
    return '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

def search_users(name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
'''


@pytest.fixture
def sample_command_injection_code():
    """命令注入示例代码"""
    return '''
import os
import subprocess

def ping_host(host):
    os.system("ping " + host)
    
def list_files(dir_name):
    subprocess.call("ls " + dir_name, shell=True)
'''


@pytest.fixture
def sample_hardcoded_credentials():
    """硬编码凭证示例代码"""
    return '''
DATABASE_PASSWORD = "my_secret_password123"
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "django-insecure-key-do-not-use-in-production"
'''

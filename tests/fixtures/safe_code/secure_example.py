"""安全代码示例

用于测试规则不会产生误报。
"""

import os
import secrets
import subprocess
from pathlib import Path


def safe_sql_query(user_id):
    """安全的参数化查询"""
    import sqlite3
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def safe_command(host):
    """安全的命令执行"""
    result = subprocess.run(
        ["ping", "-c", "4", host],
        capture_output=True,
        text=True,
        shell=False
    )
    return result.stdout


def safe_password_storage():
    """安全的密码存储"""
    import bcrypt
    password = os.environ.get("PASSWORD")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed


def safe_random_token():
    """安全的随机令牌生成"""
    return secrets.token_hex(32)


def safe_encryption():
    """安全的加密"""
    from cryptography.fernet import Fernet
    key = os.environ.get("ENCRYPTION_KEY")
    f = Fernet(key)
    return f


def safe_config():
    """安全的配置管理"""
    from dotenv import load_dotenv
    load_dotenv()
    
    config = {
        "database_url": os.environ.get("DATABASE_URL"),
        "api_key": os.environ.get("API_KEY"),
        "secret_key": os.environ.get("SECRET_KEY"),
    }
    return config


def safe_html_output(content):
    """安全的 HTML 输出"""
    from html import escape
    return escape(content)


def safe_file_access(filename):
    """安全的文件访问"""
    base_dir = Path("/safe/directory")
    safe_path = (base_dir / filename).resolve()
    
    if not str(safe_path).startswith(str(base_dir)):
        raise ValueError("Path traversal detected")
    
    return safe_path.read_text()

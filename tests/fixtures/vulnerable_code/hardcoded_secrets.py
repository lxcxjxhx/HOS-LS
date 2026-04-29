"""硬编码凭证示例代码

用于测试硬编码凭证检测规则。
"""

DATABASE_PASSWORD = "my_secret_password123"
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "django-insecure-key-do-not-use-in-production"

DB_CONNECTION = "mysql://admin:password123@localhost/mydb"
MONGO_URI = "mongodb://user:pass123@localhost:27017/mydb"

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MbzYLdZ7ZvVy7F7V
...
-----END RSA PRIVATE KEY-----"""


def get_password():
    return "hardcoded_password"


class Config:
    PASSWORD = "admin123"
    SECRET = "my_secret"

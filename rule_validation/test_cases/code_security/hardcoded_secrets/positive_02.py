# Test Case ID: HS-P02
# Rule: code_security.hardcoded_secrets
# Test Type: positive
# Description: 硬编码数据库密码
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

DB_PASSWORD = "SuperSecret123!"
database_url = "mysql://root:SuperSecret123!@localhost:3306/mydb"

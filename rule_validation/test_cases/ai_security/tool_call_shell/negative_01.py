# Test Case ID: TS-N01
# Rule: ai_security.tool_call_shell
# Test Type: negative
# Description: 安全的工具调用（非 Shell 执行）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

async def calculate_sum(numbers):
    """AI 工具执行数学计算"""
    return sum(numbers)

async def search_database(query):
    """AI 工具搜索数据库（使用 ORM）"""
    from models import User
    results = User.query.filter_by(name=query).all()
    return results

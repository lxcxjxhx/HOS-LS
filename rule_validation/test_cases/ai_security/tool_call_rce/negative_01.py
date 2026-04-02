# Test Case ID: TCR-N01
# Rule: ai_security.tool_call_rce
# Test Type: negative
# Description: 安全的数学计算
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

async def calculate(expression):
    """AI 工具执行数学计算（安全）"""
    # 使用安全的数学解析库
    import ast
    import operator
    
    ops = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv
    }
    
    tree = ast.parse(expression, mode='eval')
    return ops[type(tree.body.op)](tree.body.left.n, tree.body.right.n)

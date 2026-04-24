#!/usr/bin/env python3
"""
Test file with command injection vulnerability
"""

import os

# 命令注入漏洞示例
def execute_command(cmd):
    # 存在命令注入漏洞
    result = os.system(cmd)
    return result

# 调用示例
result = execute_command("ls -la")
print(f"Command result: {result}")

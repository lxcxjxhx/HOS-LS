# 命令注入测试用例

import os

def vulnerable_system_command(cmd):
    # 存在命令注入漏洞的系统命令执行函数
    # 直接执行用户输入的命令
    result = os.system(cmd)
    print(f"命令执行结果: {result}")
    return result

# 测试调用
vulnerable_system_command('ls -la; echo "Command Injection"')
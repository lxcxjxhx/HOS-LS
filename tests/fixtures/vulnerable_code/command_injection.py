"""命令注入漏洞示例代码

用于测试命令注入检测规则。
"""

import os
import subprocess


def vulnerable_command_1(host):
    """os.system 字符串拼接"""
    os.system("ping " + host)


def vulnerable_command_2(filename):
    """os.system f-string"""
    os.system(f"cat {filename}")


def vulnerable_command_3(cmd):
    """subprocess shell=True"""
    subprocess.call(cmd, shell=True)


def vulnerable_command_4(user_input):
    """os.popen 拼接"""
    os.popen("ls " + user_input)


def vulnerable_command_5(code):
    """eval 执行用户输入"""
    eval(code)


def vulnerable_command_6(code):
    """exec 执行用户输入"""
    exec(code)


def safe_command_1(host):
    """安全的 subprocess 调用"""
    subprocess.run(["ping", "-c", "4", host])


def safe_command_2(filename):
    """安全的 subprocess 调用"""
    subprocess.run(["cat", filename], capture_output=True)

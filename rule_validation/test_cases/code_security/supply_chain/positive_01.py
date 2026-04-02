# Test Case ID: SC-P01
# Rule: code_security.supply_chain
# Test Type: positive
# Description: 供应链安全风险
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import requests
import subprocess

def install_package(package_name):
    """安装包 - 没有验证"""
    # 直接从外部源安装
    subprocess.run(f'pip install {package_name}', shell=True)
    
def download_file(url, destination):
    """下载文件 - 没有验证来源"""
    # 从不可信源下载
    response = requests.get(url)
    
    with open(destination, 'wb') as f:
        f.write(response.content)
        
def execute_remote_code(code_url):
    """执行远程代码 - 极度危险"""
    # 从外部获取并执行代码
    response = requests.get(code_url)
    exec(response.text)
    
def load_plugin(plugin_url):
    """加载插件 - 没有签名验证"""
    # 下载并加载未经验证的插件
    download_file(plugin_url, 'plugin.py')
    import plugin
    
    # 没有验证插件签名
    # 没有检查插件完整性

# Test Case ID: SC-B01
# Rule: code_security.supply_chain
# Test Type: boundary
# Description: 内部可信源（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import subprocess
import os

INTERNAL_PACKAGE_REPO = 'https://packages.internal.company.com'

def install_internal_package(package_name, version):
    """安装内部包 - 可信源"""
    # 仅从内部仓库安装
    subprocess.run(
        f'pip install --index-url {INTERNAL_PACKAGE_REPO} {package_name}=={version}',
        shell=True,
        env={**os.environ, 'PIP_TRUSTED_HOST': 'packages.internal.company.com'}
    )
    
def download_internal_file(file_id, destination):
    """下载内部文件"""
    # 内部文件服务器，有访问控制
    url = f'{INTERNAL_PACKAGE_REPO}/files/{file_id}'
    
    response = requests.get(
        url,
        headers={'Authorization': f'Bearer {get_internal_token()}'}
    )
    
    with open(destination, 'wb') as f:
        f.write(response.content)

# 内部网络环境，有防火墙和访问控制
# 可以信任内部源

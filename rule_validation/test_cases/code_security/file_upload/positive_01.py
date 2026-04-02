# Test Case ID: FU-P01
# Rule: code_security.file_upload
# Test Type: positive
# Description: 文件上传未验证类型
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    
    # 没有验证文件类型
    # 没有验证文件扩展名
    # 直接使用原始文件名（危险）
    filename = file.filename
    file.save(os.path.join('/uploads', filename))
    
    return 'File uploaded successfully'

# Test Case ID: FU-B01
# Rule: code_security.file_upload
# Test Type: boundary
# Description: 使用 MIME 类型验证（辅助检查）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
import os
from werkzeug.utils import secure_filename
import magic

app = Flask(__name__)

ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    
    # 读取文件内容验证 MIME 类型
    file_content = file.read()
    mime = magic.from_buffer(file_content, mime=True)
    
    if mime not in ALLOWED_MIME_TYPES:
        return 'File type not allowed', 400
    
    # 保存文件
    filename = secure_filename(file.filename)
    file.seek(0)
    file.save(os.path.join('/uploads', filename))
    
    return 'File uploaded successfully'

# Test Case ID: FU-N01
# Rule: code_security.file_upload
# Test Type: negative
# Description: 安全的文件上传验证
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from flask import Flask, request
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file', 400
    
    if not allowed_file(file.filename):
        return 'File type not allowed', 400
    
    # 安全检查文件名
    filename = secure_filename(file.filename)
    
    # 保存文件
    file.save(os.path.join('/uploads', filename))
    
    return 'File uploaded successfully'

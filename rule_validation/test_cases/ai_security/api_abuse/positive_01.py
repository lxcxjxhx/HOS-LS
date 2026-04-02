# Test Case ID: AA-P01
# Rule: ai_security.api_abuse
# Test Type: positive
# Description: AI API 滥用风险
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/generate', methods=['POST'])
def generate_text():
    """文本生成 API - 无限制"""
    prompt = request.json.get('prompt', '')
    
    # 没有速率限制
    # 没有内容过滤
    # 没有使用量监控
    
    result = ai_model.generate(prompt)
    
    return jsonify({
        'result': result,
        'tokens_used': len(result)
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_image():
    """图像分析 API - 无限制"""
    image = request.files.get('image')
    
    # 没有验证图像内容
    # 没有调用频率限制
    
    result = vision_model.analyze(image)
    return jsonify({'result': result})

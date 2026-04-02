#!/usr/bin/env python3
"""
AI 辅助安全建议生成模块

功能：
1. 分析扫描结果，识别安全问题
2. 生成针对性的安全修复建议（针对已发现问题）
3. 生成 IDE 安全提示词（预防性指导，用于下次编码时）
4. 支持不同 AI 工具的提示词格式（Cursor/Trae/Kiro）
5. 集成外部 AI 模型进行高级提示词生成
"""

import json
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from rules.rule_manager import RuleManager
except ImportError:
    RuleManager = None

class AISuggestionGenerator:
    def __init__(self):
        """初始化 AI 建议生成器"""
        self.rule_manager = RuleManager() if RuleManager else None
        
        # 使用环境变量或默认 API 密钥
        api_key = os.environ.get("DEEPSEEK_API_KEY", "sk-2d8a7018de364da8a573a9f962062331")
        
        self.ai_model_config = {
            "enabled": True,
            "type": "api",
            "api_key": api_key,
            "api_url": "https://api.deepseek.com/v1/chat/completions",
            "model": "deepseek-chat",
            "timeout": 30,
            "max_tokens": 1000
        }
        
        if os.environ.get("ENABLE_AI_MODEL", "true").lower() == "false":
            self.ai_model_config["enabled"] = False
        
        self.language_config = {
            "default_language": os.environ.get("DEFAULT_LANGUAGE", "zh"),
            "supported_languages": ["zh", "en"],
            "language_names": {"zh": "中文", "en": "English"}
        }
        
        self.network_test_cached = False
        self.network_test_result = False
    
    def _build_issue_summary(self, scan_results):
        """构建详细的问题摘要"""
        summary = []
        
        for category, issues in scan_results.items():
            if not isinstance(issues, list):
                continue
                
            for issue in issues:
                file_path = issue.get('file', 'unknown')
                problem = issue.get('issue', 'unknown')
                severity = issue.get('severity', 'unknown')
                details = issue.get('details', 'unknown')
                line_number = issue.get('line_number', 'N/A')
                code_snippet = issue.get('code_snippet', 'N/A')
                
                summary.append(f"""
【{severity.upper()}】{problem}
  文件：{file_path}
  行号：{line_number}
  详情：{details}
  代码：{code_snippet}
""")
        
        return "\n".join(summary) if summary else "未发现安全问题"
    
    def generate_security_advice(self, scan_results, language=None):
        """
        生成安全修复建议 - 针对已发现的具体安全问题
        """
        if language is None:
            language = self.language_config["default_language"]
        
        issue_summary = self._build_issue_summary(scan_results)
        
        high_risk = sum(1 for issues in scan_results.values() 
                       if isinstance(issues, list) 
                       for item in issues 
                       if item.get('severity') == 'high')
        medium_risk = sum(1 for issues in scan_results.values() 
                         if isinstance(issues, list) 
                         for item in issues 
                         if item.get('severity') == 'medium')
        low_risk = sum(1 for issues in scan_results.values() 
                      if isinstance(issues, list) 
                      for item in issues 
                      if item.get('severity') == 'low')
        
        ai_prompt = f"""你是一个专业的 AI 安全专家。请根据以下扫描结果，生成详细的安全修复建议。

扫描目标：{scan_results.get('target', 'unknown')}

风险统计：
- 高风险：{high_risk}个
- 中风险：{medium_risk}个  
- 低风险：{low_risk}个

具体安全问题：
{issue_summary}

要求：
1. 针对每个问题提供详细修复步骤和代码示例
2. 说明安全风险和修复后的验证方法
3. 使用{language if language == 'en' else '中文'}回复
4. 按优先级排序（先处理高风险）

请生成安全修复建议："""
        
        ai_response = self._call_ai_model(ai_prompt)
        
        if ai_response:
            return ai_response
        else:
            return self._get_fallback_advice(scan_results, language)
    
    def _get_fallback_advice(self, scan_results, language='zh'):
        """获取回退建议（当 AI 调用失败时使用）"""
        high_risk = sum(1 for issues in scan_results.values() 
                       if isinstance(issues, list) 
                       for item in issues 
                       if item.get('severity') == 'high')
        
        advice = {
            'zh': f"""### 一、风险评估摘要
本次扫描发现 {high_risk} 个高风险问题，需要立即处理。

### 二、针对性修复建议

#### 1. 硬编码敏感信息
**修复步骤**：
1. 创建 .env 文件
2. 使用 python-dotenv 加载
3. 代码使用 os.environ.get()

**代码示例**：
```python
# 修复前
api_key = "sk-1234567890"

# 修复后
import os
from dotenv import load_dotenv
load_dotenv()
api_key = os.environ.get("API_KEY")
```

#### 2. 危险函数使用
**修复建议**：
- 避免使用 eval()、exec()
- 使用 ast.literal_eval() 替代

#### 3. 文件权限
**修复命令**：
```bash
chmod 640 model.bin
chmod 750 models/
```

### 三、安全最佳实践
1. 使用环境变量管理敏感信息
2. 定期更新依赖库
3. 实施最小权限原则
4. 添加输入验证

### 四、后续改进
1. 集成预提交安全检查
2. 使用 bandit 进行静态分析
3. 定期安全代码审查""",
            'en': f"""### Risk Assessment
Found {high_risk} high-risk issues.

### Remediation

1. Hardcoded Secrets: Use environment variables
2. Dangerous Functions: Avoid eval(), exec()
3. File Permissions: chmod 640

### Best Practices
1. Use environment variables
2. Keep dependencies updated
3. Implement least privilege"""
        }
        
        return advice.get(language, advice['zh'])
    
    def generate_security_prompts(self, tool_name='cursor', language=None, scan_results=None):
        """
        生成 IDE 安全提示词 - 预防性指导，用于下次编码时
        """
        if language is None:
            language = self.language_config["default_language"]
        
        # 构建问题摘要
        issue_summary = """
        以下是实际扫描中发现的安全问题：
        """
        if scan_results:
            issue_summary = self._build_issue_summary(scan_results)
        
        ai_prompt = f"""你是 AI 安全专家，为{tool_name} IDE 生成精简安全提示词。

基于以下实际扫描结果：
{issue_summary}

严格要求：
1. 基于实际发现的问题，生成针对性的安全规则
2. 只生成 5 条核心安全规则（每条 1 句话 +1 个代码示例）
3. 重点关注实际发现的问题类型
4. 总字数控制在 800 字以内
5. 使用 Markdown 格式，{language if language == 'en' else '中文'}

示例格式：
## 规则名
要求：一句话说明
示例：```python
# 正确做法
```

请生成{tool_name}安全提示词（基于实际扫描结果）："""
        
        # 启用 AI 调用
        print(f"  生成{tool_name}提示词...")
        ai_response = self._call_ai_model(ai_prompt)
        
        if ai_response:
            print(f"  [OK] AI 响应成功，长度：{len(ai_response)} 字符")
            return ai_response
        else:
            print(f"  [WARN] AI 返回空内容，使用回退提示词")
            return self._get_fallback_prompts(tool_name, language)
    
    def _get_fallback_prompts(self, tool_name, language='zh'):
        """获取回退提示词"""
        
        prompts = {
            'zh': {
                'cursor': self._get_cursor_prompts_zh(),
                'trae': self._get_trae_prompts_zh(),
                'kiro': self._get_kiro_prompts_zh()
            },
            'en': {
                'cursor': self._get_cursor_prompts_en(),
                'trae': self._get_trae_prompts_en(),
                'kiro': self._get_kiro_prompts_en()
            }
        }
        
        return prompts.get(language, prompts['zh']).get(tool_name, prompts['zh']['cursor'])
    
    def _get_cursor_prompts_zh(self):
        return """# Cursor 安全提示词 - AI 工具开发安全指南

## 🎯 核心安全规则

### 规则 1：禁止硬编码敏感信息
- **要求**：不得硬编码 API 密钥、密码
- **后果**：代码泄露导致敏感信息暴露
- **正确做法**：
```python
# ❌ 错误
api_key = "sk-1234567890"

# ✅ 正确
import os
from dotenv import load_dotenv
load_dotenv()
api_key = os.environ.get("API_KEY")
```

### 规则 2：避免危险函数
- **要求**：避免 eval()、exec()
- **后果**：代码注入攻击
- **替代**：ast.literal_eval()

### 规则 3：严格输入验证
- **要求**：验证所有用户输入
- **后果**：注入攻击
- **示例**：
```python
def validate_input(user_input, max_length=100):
    if not isinstance(user_input, str):
        raise ValueError("必须是字符串")
    if len(user_input) > max_length:
        raise ValueError("输入过长")
    return user_input.strip()
```

### 规则 4：文件权限最小化
- **要求**：chmod 640
- **后果**：未授权访问

### 规则 5：网络安全
- **要求**：监听 127.0.0.1
- **禁止**：0.0.0.0

## 🔐 敏感信息管理

### .env 文件
```bash
API_KEY=your_key
SECRET_KEY=your_secret
DEBUG=False
```

### .gitignore
```
.env
*.pem
secrets/
```

## 🛡️ AI 模型安全

### 模型文件保护
```python
import os, stat
os.chmod('model.bin', stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
```

### 提示词注入防护
```python
def check_prompt_injection(prompt):
    dangerous = ['ignore previous', 'you are now']
    if any(p in prompt.lower() for p in dangerous):
        raise SecurityError("注入尝试")
```

## 📦 依赖安全

### requirements.txt
```
flask==2.3.3
requests==2.31.0
python-dotenv==1.0.0
```

### 安全检查
```bash
pip install safety
safety check
```

## ✅ 提交前检查

- [ ] 无硬编码敏感信息
- [ ] 输入已验证
- [ ] 无危险函数
- [ ] 权限正确
- [ ] 监听本地
- [ ] 依赖版本固定

安全第一！"""
    
    def _get_trae_prompts_zh(self):
        return """[安全提示] Trae 安全指南

## ⚠️ 核心要求

1. 禁止硬编码敏感信息
   [错误] api_key = "sk-xxx"
   [正确] api_key = os.environ.get("API_KEY")

2. 避免危险函数
   [禁止] eval(), exec()
   [替代] ast.literal_eval()

3. 严格输入验证
   [要求] 验证类型、长度、内容

4. 文件权限最小化
   [模型] chmod 640
   [目录] chmod 750

5. 网络安全
   [监听] 127.0.0.1
   [禁止] 0.0.0.0

## 🔐 环境变量

```bash
# .env
API_KEY=your_key
SECRET_KEY=your_secret
```

```python
from dotenv import load_dotenv
load_dotenv()
api_key = os.environ.get("API_KEY")
```

## 🛡️ AI 安全

```python
def check_prompt_injection(prompt):
    dangerous = ['ignore previous', 'you are now']
    if any(p in prompt.lower() for p in dangerous):
        raise SecurityError("注入尝试")
```

## 📦 依赖

```
flask==2.3.3
requests==2.31.0
```

## ✅ 检查清单

✓ 无硬编码敏感信息
✓ 输入已验证
✓ 无危险函数
✓ 权限正确
✓ 监听本地

[提醒] 安全第一！"""
    
    def _get_kiro_prompts_zh(self):
        return """安全提醒：Kiro 安全指南

【核心规则】

1. 禁止硬编码敏感信息
   • 错误：api_key = "sk-xxx"
   • 正确：os.environ.get("API_KEY")

2. 避免危险函数
   • 禁止：eval(), exec()
   • 替代：ast.literal_eval()

3. 严格输入验证
   • 要求：验证类型、长度

4. 文件权限最小化
   • 模型：chmod 640

5. 网络安全
   • 监听：127.0.0.1

【环境变量】

.env:
```
API_KEY=your_key
SECRET_KEY=your_secret
```

使用:
```python
from dotenv import load_dotenv
load_dotenv()
api_key = os.environ.get("API_KEY")
```

【AI 安全】

```python
dangerous = ['ignore previous', 'you are now']
if any(p in prompt for p in dangerous):
    raise SecurityError("注入尝试")
```

【依赖】

固定版本:
```
flask==2.3.3
requests==2.31.0
```

【检查清单】

□ 无硬编码敏感信息
✓ 输入已验证
✓ 无危险函数
✓ 权限正确

安全是第一位的！"""
    
    def _get_cursor_prompts_en(self):
        return """# Cursor Security Guide

## Core Rules

1. No Hardcoded Secrets
   - Use environment variables
   - Example: api_key = os.environ.get("API_KEY")

2. Avoid Dangerous Functions
   - Ban: eval(), exec()
   - Use: ast.literal_eval()

3. Input Validation
   - Validate all inputs
   - Check type, length

4. File Permissions
   - chmod 640 for models

5. Network Security
   - Listen: 127.0.0.1
   - Ban: 0.0.0.0

## Environment Variables

.env:
```
API_KEY=your_key
SECRET_KEY=your_secret
```

.gitignore:
```
.env
*.pem
```

## AI Security

```python
def check_prompt_injection(prompt):
    dangerous = ['ignore previous', 'you are now']
    if any(p in prompt.lower() for p in dangerous):
        raise SecurityError("Injection attempt")
```

## Dependencies

```
flask==2.3.3
requests==2.31.0
```

## Checklist

- [ ] No hardcoded secrets
- [ ] Input validated
- [ ] No dangerous functions
- [ ] Permissions correct

Security First!"""
    
    def _get_trae_prompts_en(self):
        return """[Security] Trae Guide

## Requirements

1. No Hardcoded Secrets
   [Right] os.environ.get("API_KEY")

2. Avoid Dangerous Functions
   [Ban] eval(), exec()

3. Input Validation
   [Require] Validate all inputs

4. File Permissions
   [Model] chmod 640

5. Network Security
   [Listen] 127.0.0.1

## Environment

```python
from dotenv import load_dotenv
load_dotenv()
api_key = os.environ.get("API_KEY")
```

## AI Security

```python
def check_injection(prompt):
    dangerous = ['ignore previous', 'you are now']
    if any(p in prompt.lower() for p in dangerous):
        raise SecurityError()
```

## Checklist

✓ No hardcoded secrets
✓ Input validated
✓ No dangerous functions

[Reminder] Security First!"""
    
    def _get_kiro_prompts_en(self):
        return """Security Reminder: Kiro

[Core Rules]

1. No Hardcoded Secrets
   • Right: os.environ.get("API_KEY")

2. Avoid Dangerous Functions
   • Ban: eval(), exec()

3. Input Validation
   • Validate all inputs

4. File Permissions
   • chmod 640

5. Network Security
   • Listen: 127.0.0.1

[Environment]

```python
from dotenv import load_dotenv
api_key = os.environ.get("API_KEY")
```

[AI Security]

```python
if 'ignore previous' in prompt:
    raise SecurityError()
```

[Checklist]

✓ No hardcoded secrets
✓ Input validated

Security is priority!"""
    
    def generate_all_tool_prompts(self, scan_results=None, language=None):
        """生成所有工具的安全提示词"""
        prompts = {}
        
        for tool_name in ['cursor', 'trae', 'kiro']:
            if scan_results:
                prompts[f'{tool_name}_advice'] = self.generate_security_advice(scan_results, language)
            prompts[f'{tool_name}_prompt'] = self.generate_security_prompts(tool_name, language, scan_results)
        
        return prompts
    
    def _call_ai_model(self, prompt):
        """调用外部 AI 模型"""
        if not self.ai_model_config["enabled"]:
            print("AI 模型已禁用")
            return None
        
        try:
            # 尝试使用 OpenAI SDK
            try:
                from openai import OpenAI
                
                print("使用 OpenAI SDK 调用 DeepSeek API...")
                
                # 创建 OpenAI 客户端
                client = OpenAI(
                    api_key=self.ai_model_config["api_key"],
                    base_url="https://api.deepseek.com/v1"
                )
                
                # 调用 chat completions API
                response = client.chat.completions.create(
                    model=self.ai_model_config["model"],
                    messages=[
                        {"role": "system", "content": "你是专业的 AI 安全专家，回答简洁精准。"},
                        {"role": "user", "content": prompt}
                    ],
                    stream=False,
                    temperature=0.5,
                    max_tokens=self.ai_model_config.get("max_tokens", 1000)
                )
                
                content = response.choices[0].message.content.strip()
                print(f"AI 模型调用成功，返回内容长度：{len(content) if content else 0}")
                return content
            except ImportError:
                print("OpenAI SDK 未安装，尝试使用 requests 库...")
                # 回退到 requests 库
                import requests
                import time
                
                # 使用网络测试缓存
                if not self.network_test_cached:
                    print("测试网络连接...")
                    start_time = time.time()
                    try:
                        response = requests.get('https://api.deepseek.com', timeout=10)
                        end_time = time.time()
                        print(f"网络连接测试成功，耗时：{end_time - start_time:.2f}秒")
                        self.network_test_result = True
                    except Exception as e:
                        print(f"网络测试失败：{e}")
                        self.network_test_result = False
                    finally:
                        self.network_test_cached = True
                
                if not self.network_test_result:
                    print("网络测试失败，跳过 AI 调用")
                    return None
                
                print(f"开始调用 AI 模型，URL: {self.ai_model_config['api_url']}")
                
                data = {
                    "model": self.ai_model_config["model"],
                    "messages": [
                        {"role": "system", "content": "你是专业的 AI 安全专家，回答简洁精准。"},
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False,
                    "temperature": 0.5,
                    "max_tokens": self.ai_model_config.get("max_tokens", 1000)
                }
                
                headers = {
                    "Authorization": f"Bearer {self.ai_model_config['api_key']}",
                    "Content-Type": "application/json"
                }
                
                print("发送 API 请求...")
                start_time = time.time()
                timeout = 60
                
                try:
                    response = requests.post(
                        self.ai_model_config["api_url"],
                        json=data,
                        headers=headers,
                        timeout=timeout
                    )
                    end_time = time.time()
                    print(f"API 请求耗时：{end_time - start_time:.2f}秒")
                    print(f"API 响应状态码：{response.status_code}")
                    
                    if response.status_code == 200:
                        result = response.json()
                        content = result.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                        print(f"AI 模型调用成功，返回内容长度：{len(content) if content else 0}")
                        return content
                    else:
                        print(f"AI 模型调用失败：{response.status_code}")
                        print(f"响应内容：{response.text[:200]}")
                        return None
                except requests.exceptions.Timeout:
                    print(f"API 请求超时，已超过 {timeout} 秒")
                    return None
                except requests.exceptions.RequestException as e:
                    print(f"API 请求异常：{e}")
                    return None
        except Exception as e:
            print(f"AI 模型调用异常：{e}")
            import traceback
            traceback.print_exc()
            return None


if __name__ == '__main__':
    generator = AISuggestionGenerator()
    
    mock_scan_results = {
        "target": "tests/test-ai-tool",
        "code_security": [
            {
                "file": "tests/test-ai-tool/test.py",
                "issue": "发现硬编码的 API 密钥",
                "severity": "high",
                "details": "匹配到：api_key = \"sk-1234567890abcdef\"",
                "line_number": 10,
                "code_snippet": "api_key = \"sk-1234567890abcdef\""
            }
        ]
    }
    
    print("\n" + "="*60)
    print("测试 1: 生成安全修复建议（针对已发现问题）")
    print("="*60)
    advice = generator.generate_security_advice(mock_scan_results)
    print(advice[:1000] + "..." if len(advice) > 1000 else advice)
    
    print("\n" + "="*60)
    print("测试 2: 生成 Cursor 安全提示词（预防性指导）")
    print("="*60)
    cursor_prompt = generator.generate_security_prompts('cursor')
    print(cursor_prompt[:1000] + "..." if len(cursor_prompt) > 1000 else cursor_prompt)
    
    print("\n" + "="*60)
    print("测试 3: 生成所有工具的提示词")
    print("="*60)
    all_prompts = generator.generate_all_tool_prompts(mock_scan_results)
    for tool_name, prompt in all_prompts.items():
        print(f"\n{tool_name}:")
        print(prompt[:500] + "..." if len(prompt) > 500 else prompt)

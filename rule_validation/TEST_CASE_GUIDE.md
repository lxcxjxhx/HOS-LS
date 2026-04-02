# HOS-LS 测试用例编写指南

> **版本**: v1.0  
> **创建时间**: 2026-03-30  
> **适用范围**: 所有 HOS-LS 安全规则测试用例

---

## 📋 目录

- [概述](#概述)
- [文件命名规范](#文件命名规范)
- [文件头注释格式](#文件头注释格式)
- [测试用例设计原则](#测试用例设计原则)
- [测试类型详解](#测试类型详解)
- [最佳实践示例](#最佳实践示例)
- [常见错误避免](#常见错误避免)
- [质量检查清单](#质量检查清单)

---

## 概述

### 目标读者

本指南面向：
- 安全工程师编写测试用例
- 代码审查人员审核测试质量
- AI 系统生成标准化测试
- 新成员快速上手测试编写

### 测试用例作用

测试用例用于：
1. **验证规则准确性** - 确保规则正确检测目标漏洞
2. **防止回归** - 规则更新后保证功能不退化
3. **文档化行为** - 明确规则的检测范围和边界
4. **质量度量** - 量化评估规则性能

---

## 文件命名规范

### 基本格式

```
{test_type}_{number}.{extension}
```

### 命名规则

| 测试类型 | 前缀 | 示例 | 说明 |
|---------|------|------|------|
| **阳性测试** | `positive_` | `positive_01.py` | 应该被检测到的漏洞代码 |
| **阴性测试** | `negative_` | `negative_01.py` | 不应该被检测的安全代码 |
| **边界测试** | `boundary_` | `boundary_01.py` | 边缘情况的代码 |

### 编号规则

- 从 `01` 开始顺序编号
- 每种测试类型独立编号
- 示例：`positive_01.py`, `positive_02.py`, `negative_01.py`

### 文件扩展名

根据测试代码类型选择：
- `.py` - Python 代码
- `.js` - JavaScript 代码
- `.yaml` / `.yml` - YAML 配置
- `.json` - JSON 配置
- `.txt` - 文本文件（如 requirements.txt）
- `.java` - Java 代码
- `.go` - Go 代码

---

## 文件头注释格式

### 必填字段

每个测试文件**必须**包含以下注释字段：

```python
# Test Case ID: {RULE_ID}-{TYPE}-{NUMBER}
# Rule: {rule_id}
# Test Type: positive|negative|boundary
# Description: {简短描述}
# Expected Detection: true|false
# Expected Severity: CRITICAL|HIGH|MEDIUM|LOW
# Code Type: vulnerable|safe|test|example
```

### 字段说明

#### Test Case ID
- **格式**: `{RULE_ID}-{TYPE}-{NUMBER}`
- **说明**: 测试用例唯一标识符
- **示例**: `HS-P01` (Hardcoded Secrets - Positive - 01)

#### Rule
- **格式**: 完整的规则 ID
- **说明**: 对应的检测规则
- **示例**: `code_security.hardcoded_secrets`

#### Test Type
- **可选值**: `positive` | `negative` | `boundary`
- **说明**: 测试类型

#### Description
- **要求**: 简明扼要，≤50 字符
- **说明**: 描述测试场景
- **示例**: `硬编码 OpenAI API 密钥`

#### Expected Detection
- **可选值**: `true` | `false`
- **说明**: 是否期望被检测到
- **规则**:
  - `positive`: `true`
  - `negative`: `false`
  - `boundary`: 通常 `true`，特殊情况说明

#### Expected Severity
- **可选值**: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `N/A`
- **说明**: 期望的严重程度等级
- **规则**:
  - `positive/boundary`: 填写具体等级
  - `negative`: 填写 `N/A`

#### Code Type
- **可选值**: `vulnerable` | `safe` | `test` | `example`
- **说明**: 代码类型分类
- **规则**:
  - `positive/boundary`: `vulnerable`
  - `negative`: `safe` 或 `test`

### 完整示例

```python
# Test Case ID: HS-P01
# Rule: code_security.hardcoded_secrets
# Test Type: positive
# Description: 硬编码 OpenAI API 密钥
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

api_key = "sk-1234567890abcdef1234567890abcdef"
```

---

## 测试用例设计原则

### 通用原则

#### 1. 单一职责
- 每个测试文件只测试**一个场景**
- 避免在一个文件中测试多个功能
- 保持代码简洁（建议 ≤20 行）

#### 2. 明确预期
- 清晰定义期望结果
- 避免模棱两可的场景
- 确保验证脚本能明确判断

#### 3. 可重复性
- 测试结果可重复
- 不依赖外部环境
- 避免时间敏感性代码

#### 4. 独立性
- 测试之间相互独立
- 无依赖关系
- 可单独执行

#### 5. 真实性
- 基于真实案例
- 反映实际场景
- 避免人为编造

---

## 测试类型详解

### 阳性测试（Positive Tests）

**目标**: 验证规则能正确检测漏洞代码

#### 设计要求

每规则 **3-5 个** 阳性测试：

1. **典型场景** (2 个)
   - 最常见的漏洞形式
   - 来自真实项目或 CVE
   - 代表最常见的利用方式

2. **变体场景** (1 个)
   - 不同的编码风格
   - 代码混淆形式
   - 不同的命名习惯

3. **复杂场景** (1 个)
   - 多层嵌套
   - 条件判断
   - 函数调用

#### 示例

```python
# Test Case ID: HS-P01
# Rule: code_security.hardcoded_secrets
# Test Type: positive
# Description: 硬编码 OpenAI API 密钥
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

api_key = "sk-1234567890abcdef1234567890abcdef"
```

```python
# Test Case ID: HS-P02
# Rule: code_security.hardcoded_secrets
# Test Type: positive
# Description: 硬编码数据库密码
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

DB_PASSWORD = "SuperSecret123!"
database_url = "mysql://root:SuperSecret123!@localhost:3306/mydb"
```

---

### 阴性测试（Negative Tests）

**目标**: 验证规则不会误报安全代码

#### 设计要求

每规则 **2-3 个** 阴性测试：

1. **安全实现** (2 个)
   - 使用安全 API
   - 遵循最佳实践
   - 正确的配置方式

2. **测试/示例代码** (1 个)
   - 测试文件中的代码
   - 文档示例
   - Mock 数据

#### 示例

```python
# Test Case ID: HS-N01
# Rule: code_security.hardcoded_secrets
# Test Type: negative
# Description: 使用环境变量（安全做法）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import os
api_key = os.environ.get("OPENAI_API_KEY")
db_password = os.getenv("DB_PASSWORD")
```

```python
# Test Case ID: HS-N02
# Rule: code_security.hardcoded_secrets
# Test Type: negative
# Description: 使用 dotenv 加载配置
# Expected Detection: false
# Expected Severity: N/A
# Code Type: test

from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.environ.get("API_KEY")
```

---

### 边界测试（Boundary Tests）

**目标**: 验证规则在边缘情况下的行为

#### 设计要求

每规则 **1-2 个** 边界测试：

1. **长度边界**
   - 最短字符串（可能漏检）
   - 最长字符串（性能测试）

2. **格式边界**
   - 特殊字符
   - 编码格式变体
   - 格式异常

3. **上下文边界**
   - 临界状态
   - 模糊场景

#### 示例

```python
# Test Case ID: HS-B01
# Rule: code_security.hardcoded_secrets
# Test Type: boundary
# Description: 短密钥（边界情况）
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

# 短密钥，可能因为长度不足而漏检
api_key = "sk-123"
password = "pwd"
```

```python
# Test Case ID: SI-B01
# Rule: injection_security.sql_injection
# Test Type: boundary
# Description: 复杂 SQL 语句（可能误报）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 复杂的 ORM 查询，可能被误报为 SQL 注入
query = User.query.filter(
    and_(
        User.name == 'john',
        or_(
            User.age > 18,
            User.status == 'active'
        )
    )
).all()
```

---

## 最佳实践示例

### 示例 1: 硬编码密钥检测

#### 阳性测试组

```python
# positive_01.py - 直接赋值
api_key = "sk-1234567890abcdef1234567890abcdef"
```

```python
# positive_02.py - 字典存储
credentials = {
    "api_key": "sk-1234567890abcdef",
    "password": "SuperSecret123!"
}
```

```python
# positive_03.py - 函数参数
def connect(password="default123"):
    pass
```

#### 阴性测试组

```python
# negative_01.py - 环境变量
import os
api_key = os.environ.get("API_KEY")
```

```python
# negative_02.py - 配置文件
from dotenv import load_dotenv
load_dotenv()
api_key = os.getenv("API_KEY")
```

#### 边界测试组

```python
# boundary_01.py - 短密钥
api_key = "sk-123"  # 长度不足
```

---

### 示例 2: SQL 注入检测

#### 阳性测试组

```python
# positive_01.py - 字符串拼接
username = input("Enter username: ")
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```

```python
# positive_02.py - format 方法
query = "SELECT * FROM users WHERE username = '{}'".format(username)
cursor.execute(query)
```

#### 阴性测试组

```python
# negative_01.py - 参数化查询
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

```python
# negative_02.py - ORM 查询
user = User.query.filter_by(username=username).first()
```

---

## 常见错误避免

### ❌ 错误 1: 测试场景不明确

```python
# 错误示例 - 混合多个场景
api_key = "sk-123"  # 硬编码密钥
password = os.environ.get("PWD")  # 环境变量
```

**问题**: 同时测试阳性和阴性场景，无法明确判断

**正确做法**: 拆分为两个测试文件

---

### ❌ 错误 2: 依赖外部环境

```python
# 错误示例 - 依赖外部文件
with open('config.json') as f:
    config = json.load(f)
api_key = config['api_key']
```

**问题**: 测试文件不存在时失败

**正确做法**: 使用内联数据

---

### ❌ 错误 3: 代码过于复杂

```python
# 错误示例 - 100+ 行代码
class ComplexTest:
    def __init__(self):
        # ... 50 行代码
    def setup(self):
        # ... 30 行代码
    def run(self):
        # ... 20 行代码
```

**问题**: 难以理解测试意图

**正确做法**: 保持简洁（≤20 行）

---

### ❌ 错误 4: 缺少必要注释

```python
# 错误示例 - 没有注释
api_key = "sk-123"
```

**问题**: 无法理解测试目的

**正确做法**: 添加完整文件头注释

---

### ❌ 错误 5: 预期结果模糊

```python
# 错误示例 - 模棱两可
# Expected Detection: maybe
```

**问题**: 验证脚本无法判断

**正确做法**: 明确 `true` 或 `false`

---

## 质量检查清单

### 提交前自检

在提交测试用例前，请确保满足以下所有条件：

#### 格式规范 ✅

- [ ] 文件命名正确（positive_01.py 等）
- [ ] 包含完整的文件头注释
- [ ] 所有必填字段都有值
- [ ] 字段值格式正确

#### 内容质量 ✅

- [ ] 测试场景单一明确
- [ ] 代码简洁（≤20 行）
- [ ] 预期结果清晰
- [ ] 基于真实案例或有实际价值

#### 验证通过 ✅

- [ ] 运行验证脚本通过
- [ ] 结果符合预期
- [ ] 无意外行为
- [ ] 与其他测试不冲突

#### 文档完整 ✅

- [ ] Description 清晰描述场景
- [ ] Code Type 正确分类
- [ ] Severity 合理评估
- [ ] 必要时添加额外注释

### 审查清单

**审查人员使用**:

#### 完整性审查

- [ ] 阳性测试 ≥3 个
- [ ] 阴性测试 ≥2 个
- [ ] 边界测试 ≥1 个
- [ ] 覆盖典型场景

#### 准确性审查

- [ ] 预期检测正确
- [ ] 严重程度合理
- [ ] 代码类型准确
- [ ] 无错误预期

#### 质量审查

- [ ] 代码规范
- [ ] 注释完整
- [ ] 场景真实
- [ ] 无硬编码路径

#### 覆盖度审查

- [ ] 覆盖主要利用方式
- [ ] 覆盖常见变体
- [ ] 覆盖边缘情况
- [ ] 无明显遗漏

---

## 工具和资源

### 验证工具

```bash
# 运行单个测试
python rule_validation/run_validation.py \
  --test-cases rule_validation/test_cases/code_security/hardcoded_secrets/

# 运行所有测试
python rule_validation/run_validation.py

# 生成 HTML 报告
python rule_validation/run_validation.py --format html
```

### 参考资源

- [测试框架 README](README.md)
- [质量指标体系](../../docs/QUALITY_METRICS.md)
- [规则文档](../../rules/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE 列表](https://cwe.mitre.org/)

---

## 版本历史

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| v1.0 | 2026-03-30 | 初始版本 |

---

**维护**: HOS-LS Security Team  
**反馈**: 如有问题或建议，请提交 Issue 或联系安全团队

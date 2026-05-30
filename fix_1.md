# HOS-LS 扫描优化问题记录

## 扫描轮次: #4 (第四轮 - 问题#4修复验证 + 50文件测试)
- **日期**: 2026-05-30
- **靶场**: c:\1AAA_PROJECT\HOS\HOS-LS\real-project\bizspring-open-main
- **文件数**: 20 + 50 (测试模式)
- **模型**: deepseek-v4-flash
- **输出**: test_scan_loop_20files_v3.html, test_scan_loop_50files_v3.html
- **20文件去重**: 原始 19 -> 去重后 18
- **50文件去重**: 原始 34 -> 去重后 30

---

## 修复效果总结

### ✅ 已修复并验证通过的问题

| 问题 | 描述 | 修复状态 | 验证结果 |
|------|------|----------|----------|
| #1 | CWE索引构建失败 | ✅ 已修复 | 优雅降级，不再报error |
| #2 | AI行号定位失败（注释块误判） | ✅ 已修复 | 新增COMMENT_CORRECTED状态 |
| #3 | 信号ID不一致 | ✅ 已修复 | Agent-2和Agent-3使用相同signal_id |
| #4 | AI JSON解析失败（title缺失） | ✅ 已修复 | prompt统一字段名+schema自动修复 |
| #6 | 关键词匹配行号偏差过大 | ✅ 已修复 | 偏差超限标记UNVERIFIED |
| #8 | 加固建议未完全分离 | ✅ 已修复 | HARDENING_ADVICE_KEYWORDS已扩展 |

### ⏳ 仍存在的问题

| 问题 | 描述 | 严重程度 | 状态 |
|------|------|----------|------|
| #5 | 置信度不一致 | 中 | 已缓解 |
| #7 | TRAE Sandbox缓存限制 | 低 | 环境限制 |

---

## 本轮修复详情

### 问题 #4: AI JSON 解析失败 ✅ 已修复
- **根因**: Agent-2（risk_enumeration）模板使用`risk_type`字段，但VULNERABILITY_SCHEMA要求`title`字段
- **修复方案**:
  1. **Prompt统一**: 修改risk_enumeration.jinja2模板，添加`title`字段到输出JSON示例
  2. **Schema自动修复**: 增强schema_validator.py的`_fix_item_structure`函数，智能填充缺失的`title`字段
- **代码变更**:
  - `prompts/templates/risk_enumeration.jinja2` 第1/20/29行
  - `src/ai/pure_ai/schema_validator.py` 第668-690行（新增title智能填充逻辑）
- **智能填充逻辑**:
  1. 优先使用`title`字段
  2. 回退到`risk_type` → `vulnerability` → `vuln_type`
  3. 从`description`提取前30字符
  4. 从`location`提取文件名
  5. 默认值：'安全风险'
- **验证结果**: 
  - 20文件扫描：信号ID统一为RISK-001格式，title字段正确填充
  - 50文件扫描：信号ID格式一致，title字段完整

---

## 历史修复记录

### 问题 #1: CWE 索引构建失败 ✅ 已修复
- **修复方案**: 在 `_ensure_cwe_index` 函数中添加表存在检查
- **代码变更**: `src/nvd/nvd_query_adapter.py` 第131-143行
- **验证结果**: 日志从 `CWE索引构建失败: no such table: cwe` 变为 `CWE表不存在，跳过CWE索引构建（降级模式）`

### 问题 #2: AI 行号定位失败 ✅ 已修复
- **修复方案**: 新增多行注释块检测和自动校正逻辑
- **代码变更**: `src/ai/pure_ai/line_number_mapper.py` 新增3个函数
- **验证结果**: 当AI报告行号在注释块内时，自动搜索附近有效代码行并标记为COMMENT_CORRECTED

### 问题 #3: 信号ID不一致 ✅ 已修复
- **修复方案**: 统一使用Agent-2返回的原始信号ID
- **代码变更**: `src/ai/pure_ai/multi_agent_pipeline.py` 第1149行
- **验证结果**: 信号覆盖率从50%提升到100%

### 问题 #6: 关键词匹配行号偏差过大 ✅ 已修复
- **修复方案**: 偏差超限时回退到AI原始行号并标记为UNVERIFIED
- **代码变更**: `src/ai/pure_ai/line_number_mapper.py` verify_and_correct函数
- **验证结果**: 偏差超过tolerance时不再使用偏差很大的行号

### 问题 #8: 加固建议未完全分离 ✅ 已修复
- **修复方案**: 扩展HARDENING_ADVICE_KEYWORDS列表
- **代码变更**: `src/reporting/generator.py` 第54-59行
- **新增关键词**: 错误处理、加密功能未实现、encryption、加密、ip跳过、ip bypass、请求头伪造等

---

## 优化效果对比

| 指标 | 第一轮(20文件) | 第二轮(20文件) | 第三轮(50文件) | 第四轮(50文件) |
|------|----------------|----------------|----------------|----------------|
| 原始发现 | 10 | 13 | 25 | 34 |
| 去重后 | 8 | 12 | 21 | 30 |
| CWE错误 | 每个文件 | 0 (优雅降级) | 0 (优雅降级) | 0 (优雅降级) |
| 信号覆盖率 | 50% | 100% | 100% | 100% |
| AI行号偏差 | 18行 | 已校正 | 已校正 | 已校正 |
| 加固建议分离 | 部分 | 完全 | 完全 | 完全 |
| JSON解析失败 | 频繁 | 频繁 | 频繁 | ✅ 已修复 |

---

## 仍需优化的问题

### 问题 #5: 可疑均匀置信度检测
- **类型**: AI 幻觉 / 置信度计算问题
- **严重程度**: 中
- **状态**: 已部分缓解（使用动态置信度，取较低的证据计算值）

### 问题 #7: TRAE Sandbox 缓存写入限制
- **类型**: 环境限制（非代码BUG）
- **严重程度**: 低
- **状态**: 已知问题，需要配置Sandbox规则允许写入 `.hos-ls` 目录

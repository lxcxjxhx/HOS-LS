# HOS-LS 项目结构

## 已完成的优化（共 5 轮提交）

| 轮次 | Commit | 主要变更 |
|------|--------|---------|
| 1️⃣ | `eafda04` | 冗余清理 + scanner/schema/chain/priority 拆分 |
| 2️⃣ | `1f35e5d` | scanner 工具/发现/规则 + multi_agent常量+类 + ResultConverter |
| 3️⃣ | `a22a12d` | scanner.py _analyze_files 提取 |
| 4️⃣ | `0b4bac3` | multi_agent_pipeline.py 信号追踪提取 |
| 5️⃣ | `661928b` | 修复 SemanticConsistencyError 导入 |

## 效果数据

| 文件 | 原来 | 现在 | 减少 |
|------|------|------|------|
| scanner.py | 4580 | 2101 | **-54%** |
| schema_validator.py | 2739 | 1262 | **-54%** |
| dependency_chain_analyzer.py | 2037 | 1162 | **-43%** |
| priority_engine.py | 1833 | 667 | **-64%** |
| multi_agent_pipeline.py | 4161 | 2808 | **-33%** |
| exploit_generator.py | 2053 | 892 | **-57%** |

## 新增模块（28+ 新文件）

### 核心拆分
- `core/remote_scanner.py` — 远程扫描器
- `core/scanner_tools.py` — 工具预扫描
- `core/scanner_finding.py` — 发现处理
- `core/scanner_rules.py` — 规则分析
- `core/scanner_analyze.py` — 语义分析
- `core/analyze_files.py` — 文件分析

### 多 Agent 流水线
- `pure_ai/pipeline_constants.py` — 常量配置
- `pure_ai/known_file_registry.py` — 文件注册表
- `pure_ai/evidence_chain.py` — 证据链
- `pure_ai/pipeline_llm.py` — LLM 生成/解析
- `pure_ai/signal_tracking.py` — 信号追踪

### 分析器拆分
- `analyzers/dependency_models.py` — 依赖数据模型
- `analyzers/dependency_cve_checker.py` — CVE 检查器
- `analyzers/exploit_types.py` — 利用数据模型
- `analyzers/exploit_templates.py` — 利用模板库
- `analyzers/exploit_scorer.py` — 利用评分器

### 其他
- `utils/priority_models.py` — 优先级数据模型
- `pure_ai/result_converter.py` — 结果转换器
- `pure_ai/line_number_validator.py` — 行号验证器

## 当前大文件 Top 10

| 文件 | 行数 | 建议 |
|------|------|------|
| multi_agent_pipeline.py | 2808 | 可提取 Agent 0-6 到独立文件 |
| pure_ai_analyzer.py | 2963 | 可提取 batch/checkpoint |
| scanner.py | 2101 | ✅ 已大幅拆分 |
| context_builder.py | 1524 | 内聚性较高，拆分收益有限 |
| file_prioritizer.py | 1363 | 同上 |
| tiered_analysis_pipeline.py | 1328 | 可提取正则模式库 |
| schema_validator.py | 1262 | ✅ 已拆分 |
| reporting/generator.py | 1199 | 可提取统计函数 |
| risk_quantifier.py | 1187 | 可提取评分器 |
| dependency_chain_analyzer.py | 1162 | ✅ 已拆分 |
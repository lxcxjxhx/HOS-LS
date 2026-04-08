<div align="center">

# 🔒 HOS-LS v0.3.1.5

## AI 生成代码安全扫描工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**English** | [中文](README_CN.md)

</div>

***

## 📋 快速导航

- [🤖 纯净AI模式（--pure-ai）](#-纯净ai模式--pure-ai) - 低配置首选，开箱即用
- [🔒 正式模式（完整版）](#-正式模式完整版) - 全功能，高性能硬件推荐

***

## 🤖 纯净AI模式（--pure-ai）

### 什么是 --pure-ai 模式？

`--pure-ai` 是 HOS-LS 推出的轻量级纯 AI 深度语义解析模式。它采用多 Agent 流水线架构，默认使用 deepseek-reasoner 模型，无需依赖 Neo4j、FAISS、GraphRAG 等重型组件，即可提供高质量的代码安全扫描服务。

### 为什么推出 --pure-ai 模式？

根据客户反馈，正式模式对于电脑性能依赖过高，需要较高配置的硬件才能流畅运行。为了让更多开发者能够轻松使用 HOS-LS，我们特别推出了 `--pure-ai` 模式，它具有以下特点：

- **低性能依赖**：不依赖图数据库、向量存储等重型组件
- **开箱即用**：只需配置 API 密钥即可开始使用
- **多语言支持**：支持 Python、JavaScript、TypeScript、Java、C/C++ 等多种语言
- **高质量分析**：7 个专业 Agent 协同工作，提供深度安全分析

### 核心优势对比

| 特性 | 纯净AI模式（--pure-ai） | 正式模式（完整版） |
|------|---------------------|-----------------|
| **硬件要求** | 普通配置即可 | 推荐高性能配置 |
| **依赖组件** | 仅需 AI API | Neo4j、FAISS、PostgreSQL 等 |
| **启动速度** | ⚡ 快速启动 | 🐢 需要初始化多个组件 |
| **内存占用** | 低 | 较高 |
| **AI 分析** | ✅ 7 Agent 流水线 | ✅ 强 Multi-Agent 架构 |
| **RAG 知识库** | ❌ | ✅ |
| **攻击链分析** | ✅ | ✅ |
| **CVE 集成** | ❌ | ✅ |
| **适用场景** | 日常开发、快速扫描 | 深度安全审计、大型项目 |

### 7个专业 Agent 详解

`--pure-ai` 模式采用 7 个专业 Agent 协同工作，形成完整的安全分析流水线：

#### Agent 0: 上下文分析
- **职责**：构建代码上下文，分析文件依赖关系
- **功能**：
  - 读取文件内容
  - 识别相关文件
  - 分析 import 语句
  - 追踪函数调用关系

#### Agent 1: 代码理解
- **职责**：深度理解代码逻辑和意图
- **功能**：
  - 分析代码结构
  - 识别业务逻辑
  - 理解数据流
  - 建立代码语义模型

#### Agent 2: 风险枚举
- **职责**：枚举潜在安全风险点
- **功能**：
  - 识别危险函数调用
  - 检测可疑代码模式
  - 标记高风险区域
  - 生成初步风险列表

#### Agent 3: 漏洞验证
- **职责**：验证风险是否为真实漏洞
- **功能**：
  - 逐项验证风险点
  - 分析利用可能性
  - 评估影响范围
  - 筛选有效漏洞

#### Agent 4: 攻击链分析
- **职责**：构建完整攻击路径
- **功能**：
  - 分析漏洞间关联
  - 构建攻击链条
  - 评估攻击复杂度
  - 识别关键攻击路径

#### Agent 5: 对抗验证
- **职责**：从攻击者角度验证漏洞
- **功能**：
  - 模拟攻击场景
  - 测试绕过可能性
  - 评估防御有效性
  - 强化验证结果

#### Agent 6: 最终裁决
- **职责**：综合所有分析结果，做出最终判断
- **功能**：
  - 整合所有 Agent 输出
  - 评估漏洞严重性
  - 生成修复建议
  - 输出最终报告

### 快速上手（30秒）

#### 1. 安装

```bash
# 使用 pip 安装
pip install hos-ls
```

#### 2. 配置 API 密钥

```bash
# Windows
set DEEPSEEK_API_KEY=sk-your-api-key-here

# Linux/Mac
export DEEPSEEK_API_KEY=sk-your-api-key-here
```

#### 3. 开始扫描

```bash
# 测试命令
cd PATH ; python -m src.cli.main --debug scan PATH\nanobot-0.1.4.post6 --pure-ai -o nanobot-security-report

# 扫描当前目录（纯净AI模式）
hos-ls scan --pure-ai

# 扫描指定项目
hos-ls scan /path/to/project --pure-ai

# 生成 HTML 报告
hos-ls scan --pure-ai --format html --output report.html

# 测试模式（只扫描前10个文件）
hos-ls scan --pure-ai --test 10
```

### 详细使用指南

#### 命令行参数

```bash
hos-ls scan --pure-ai [OPTIONS] [PATH]

Arguments:
  PATH                 要扫描的目录或文件 [默认: 当前目录]

Options:
  --format, -f         输出格式: html, json, markdown, sarif [默认: html]
  --output, -o         输出文件路径
  --ruleset, -r        规则集: owasp-top10, cwe-top25, all, v3 [默认: v3]
  --severity, -s       最低严重级别: critical, high, medium, low
  --workers, -w        并行工作进程数 [默认: 4]
  --incremental        增量扫描（使用缓存）
  --test, -t           测试模式，指定扫描文件数量
  --config, -c         配置文件路径
  --verbose, -v        详细输出
  --help, -h           显示帮助信息
```

#### 配置文件

创建 `.hos-ls.yaml` 配置文件：

```yaml
# 纯AI模式配置
pure_ai:
  enabled: true
  provider: deepseek          # AI 提供商: anthropic, openai, deepseek
  model: deepseek-reasoner    # AI 模型
  api_key: ${DEEPSEEK_API_KEY}
  base_url: https://api.deepseek.com
  temperature: 0.0
  max_tokens: 4096
  timeout: 60

# 扫描配置
scan:
  max_workers: 4
  cache_enabled: true
  incremental: true
  timeout: 300
  max_file_size: 10485760  # 10MB
  exclude_patterns:
    - "*.min.js"
    - "*.min.css"
    - "node_modules/**"
    - "__pycache__/**"
    - ".git/**"
    - ".venv/**"
    - "venv/**"
    - "dist/**"
    - "build/**"
  include_patterns:
    - "*.py"
    - "*.js"
    - "*.ts"
    - "*.java"
    - "*.cpp"
    - "*.c"
    - "*.h"
    - "*.go"
    - "*.rs"

# 报告配置
report:
  format: html
  output: ./security-report
  include_code_snippets: true
  include_fix_suggestions: true

# 全局配置
debug: false
verbose: false
quiet: false
```

#### 使用示例

```bash
# 基本扫描
hos-ls scan --pure-ai

# 扫描指定目录
hos-ls scan /path/to/project --pure-ai

# 生成 JSON 报告
hos-ls scan --pure-ai --format json --output report.json

# 只扫描高严重级别问题
hos-ls scan --pure-ai --severity high

# 使用 8 个工作进程
hos-ls scan --pure-ai --workers 8

# 增量扫描（使用缓存）
hos-ls scan --pure-ai --incremental

# 测试模式（只扫描前 20 个文件）
hos-ls scan --pure-ai --test 20

# 详细输出
hos-ls scan --pure-ai --verbose
```

#### 环境变量

```bash
# AI API 密钥
export ANTHROPIC_API_KEY="your-key"
export OPENAI_API_KEY="your-key"
export DEEPSEEK_API_KEY="your-key"

# 配置路径
export HOS_LS_CONFIG_PATH="/path/to/config.yaml"

# 日志级别
export HOS_LS_LOG_LEVEL="DEBUG"
```

### 支持的 AI 模型

`--pure-ai` 模式支持多种 AI 模型：

| 提供商 | 模型 | 说明 |
|-------|------|------|
| **DeepSeek** | deepseek-reasoner | 推荐，推理能力强 |
| **DeepSeek** | deepseek-chat | 快速响应 |
| **OpenAI** | gpt-4 | 高质量分析 |
| **OpenAI** | gpt-4-turbo | 平衡速度和质量 |
| **Anthropic** | claude-3-5-sonnet | 长文本处理优秀 |
| **Anthropic** | claude-3-opus | 最高质量 |

***

## 🔒 正式模式（完整版）

> **注意**：正式模式提供完整功能，但对硬件配置要求较高。推荐 16GB+ 内存、支持 CUDA 的 GPU。如果您的配置有限，建议使用 [纯净AI模式（--pure-ai）](#-纯净ai模式--pure-ai)。

## 📖 简介

HOS-LS (HOS - Language Security) 是一款专为 **AI 生成代码** 设计的安全扫描工具。它结合了静态分析、AI 语义分析和攻击模拟等多种技术，帮助开发者在代码进入生产环境前发现潜在的安全漏洞。

### v0.3.1.4 新特性
- ✅ **NVD RAG 系统优化**: 字段级语义切块和 token 级二次切块，解决长文本处理问题
- ✅ **BAAI bge 系列模型支持**: 提升嵌入质量和检索准确性
- ✅ **多进程架构优化**: 并行处理 CVE 数据，导入速度提升 50%
- ✅ **BM25 混合检索实现**: 融合向量搜索和 BM25 算法，提高检索质量
- ✅ **Rerank 功能**: 结果重新排序，提升相关性
- ✅ **NaN 检测和过滤**: 消除无效嵌入向量，提高系统稳定性
- ✅ **内存管理优化**: 批处理参数优化，内存使用降低 30%
- ✅ **性能优化**: GPU 批量嵌入加速（10x）、Blockify 压缩（内存降低 50%）
- ✅ **内存使用优化**: LazyGraphRAG 模式，避免图爆炸，支持无限扩展
- ✅ **CLI 响应速度提升**: Async 任务处理（3x 速度提升）、三级进度条
- ✅ **完整 LangGraph StateGraph**: 实现条件边和 Critic 循环
- ✅ **强 Multi-Agent 架构**: CST/AST/Taint/RAG/Semantic 多Agent协同工作，支持证据融合和可回流推理
- ✅ **证据驱动系统**: 统一所有 Agent 输出格式，实现证据融合和置信度评估
- ✅ **可回流推理机制**: 支持低置信度结果的自动回流分析，提高分析质量
- ✅ **Fusion Agent**: 核心证据融合组件，整合多Agent输出为统一证据格式
- ✅ **Semantic Agent**: AI 语义理解增强，提供深度漏洞分析
- ✅ **Attack Agent**: 基于污点路径生成完整攻击链
- ✅ **Validation Agent**: 结果校验和质量控制，支持循环重试
- ✅ **DSPy 自动优化**: 自动生成并优化 Prompt，推理质量提升 30-78%
- ✅ **LangSmith + DeepEval 评估闭环**: 实现自动评分和反馈
- ✅ **OWASP LLM 2025 安全检查**: 检测提示注入、数据泄露等风险
- ✅ **Neo4j 5.15.0+ with GraphRAG**: 启用 ai.* Cypher 函数
- ✅ **FAISS + LlamaIndex 混合检索**: 提升检索准确性
- ✅ **RAG + 图融合集成**: 结合向量搜索和图数据库查询
- ✅ **攻击链分析增强**: 构建完整的攻击路径
- ✅ **持续优化机制**: 基于评估结果自动调整系统配置
- ✅ **安全风险评估**: 实时评估输入代码的安全风险
- ✅ **高风险拒绝处理**: 自动拒绝高安全风险的输入
- ✅ **混合 RAG 架构**: PostgreSQL 结构化存储 + 向量存储，解决大规模 NVD 数据问题
- ✅ **NVD 数据导入优化**: 流式处理、批量 embedding、断点续传、去重机制
- ✅ **数据拆分设计**: 将 NVD JSON 拆分为结构化数据和 embedding 块，提高检索准确性
- ✅ **混合检索查询层**: 支持结构化搜索、语义搜索和混合搜索
- ✅ **攻击链分析增强**: 漏洞到代码模式映射、攻击链 RAG、exploit 知识注入

### 为什么选择 HOS-LS？

| 特性       | HOS-LS   | 传统 SAST 工具 |
| -------- | -------- | ---------- |
| AI 代码理解  | ✅ 深度语义分析 | ❌ 仅语法分析    |
| 函数级切片  | ✅ AST 精准切片 | ❌ 全文扫描      |
| 多阶段扫描  | ✅ 轻量定位+精扫 | ❌ 单阶段全量    |
| 误报率      | 🎯 低误报率  | ⚠️ 高误报率    |
| AI 模型支持  | ✅ 多模型支持  | ❌ 无        |
| CVE 集成    | ✅ NVD+ExploitDB | ❌ 无        |
| 攻击路径分析   | ✅ 可视化攻击图 | ❌ 无        |
| 增量扫描     | ✅ 支持     | ⚠️ 部分支持    |
| CI/CD 集成 | ✅ 开箱即用   | ⚠️ 需配置     |

***

## ✨ 核心特性

### 🔍 多维度安全分析

- **静态分析 (SAST)**: 基于 AST/CST 的深度代码分析
- **函数级代码切片**: Python/JS/TS 语法解析，每个函数独立分析
- **AI 语义分析**: 集成 Claude、OpenAI、DeepSeek 等 AI 模型
- **多阶段扫描**: Phase 1 轻量定位 → Phase 2 精准扫描
- **规则驱动 Prompt**: 结构化检测规则，可扩展
- **攻击图引擎**: 构建完整的攻击路径图
- **漏洞验证**: 自动验证漏洞可利用性
- **RAG 知识库**: 基于向量存储的安全知识检索，支持语义搜索和知识图谱
- **CVE 数据集成**: NVD JSON Feed + ExploitDB 映射，自动增量同步
- **网络搜索集成**: 实时搜索相关安全信息，增强漏洞检测能力
- **GPU 加速 Embedding**: PyTorch GPU 加速，提升嵌入生成速度 5-10 倍
- **Neo4j 图数据库**: 增量图构建，支持复杂攻击链查询和关系分析
- **FAISS 向量检索**: GPU 加速的相似度搜索，用于 CVE 相似漏洞查找
- **LangGraph 流程控制**: 可决策的状态机流程，按需执行扫描步骤，提高效率
- **多Agent 协作系统**: 5个核心Agent协同工作，实现智能漏洞分析
- **DSPy 自动优化**: 自动生成并优化Prompt，支持Few-shot自动选择
- **动态决策流程**: 根据用户输入自动决定是否需要RAG、图查询、链路分析
- **Critic 质量把关**: 支持循环重试，提升报告质量
- **Repair Agent**: 自动生成修复建议
- **混合 RAG 架构**: PostgreSQL 结构化存储 + 向量存储，解决大规模 NVD 数据问题
- **NVD 数据处理**: 流式解压、批量 embedding、断点续传、去重机制
- **数据拆分设计**: 将 NVD JSON 拆分为结构化数据和 embedding 块，提高检索准确性
- **NVD 字段级语义切块**: 按描述、引用、配置等字段进行切块，保留语义完整性
- **Token 级二次切块**: 400/80 块大小和重叠，优化长文本处理
- **BAAI bge 系列模型支持**: 提升嵌入质量和检索准确性
- **多进程架构**: 并行处理 CVE 数据，提高导入速度
- **BM25 混合检索**: 融合向量搜索和 BM25 算法，提高检索质量
- **Rerank 功能**: 结果重新排序，提升相关性
- **NaN 检测和过滤**: 消除无效嵌入向量，提高系统稳定性
- **内存管理优化**: 批处理参数优化，降低内存使用
- **混合检索查询层**: 支持结构化搜索、语义搜索和混合搜索
- **攻击链分析增强**: 漏洞到代码模式映射、攻击链 RAG、exploit 知识注入

### 🚀 大型项目优化

- **文件优先级评估**: 基于文件名语义分析，智能筛选重要文件
- **函数级切片分析**: 每个函数独立分析，保留完整上下文
- **多阶段 AI 分析**: 仅对可疑点进行深度分析，大幅节省 Token
- **智能文件类型识别**: 扩展支持配置文件、脚本、文档等更多文件类型
- **增强问题识别**: 覆盖更多安全问题种类，提高检测全面性
- **并发扫描调度**: async 并发、自动重试、速率限制

### 🛡️ 全面的安全规则

| 规则类别   | 数量      | 覆盖范围                      |
| ------ | ------- | ------------------------- |
| 注入漏洞   | 15+     | SQL、命令、LDAP、XPath 等       |
| 认证授权   | 12+     | 弱密码、会话管理、权限绕过             |
| 数据保护   | 10+     | 敏感数据泄露、加密缺陷               |
| 配置安全   | 8+      | 不安全配置、默认凭证                |
| 代码质量   | 10+     | 硬编码、调试代码、异常处理             |
| **总计** | **70+** | OWASP Top 10 + CWE Top 25 + v3 新规则 |

### 🌐 多语言支持

| 语言         | AST 分析 | AI 分析 | 函数级切片 | 漏洞检测 |
| ---------- | :----: | :---: | :----: | :--: |
| Python     |    ✅   |   ✅   |   ✅    |   ✅  |
| JavaScript |    ✅   |   ✅   |   ✅    |   ✅  |
| TypeScript |    ✅   |   ✅   |   ✅    |   ✅  |
| Java       |    ✅   |   ✅   |   🚧    |   ✅  |
| C/C++      |    ✅   |   ✅   |   🚧    |   ✅  |
| Go         |   🚧   |   ✅   |   ❌    |   ✅  |
| Rust       |   🚧   |   ✅   |   ❌    |   ✅  |

### 🤖 AI 能力

- **多模型支持**: Claude 3.5、GPT-4、DeepSeek 等
- **规则驱动 Prompt**: 结构化检测规则，可扩展
- **两阶段扫描**: 轻量定位（低 Token）→ 精扫（高准确率）
- **智能误报过滤**: AI 辅助判断漏洞真实性
- **修复建议生成**: 自动生成安全修复代码
- **语义理解**: 理解 AI 生成代码的意图

### 📊 CVE 数据管理

- **NVD JSON Feed**: 官方数据源，自动同步
- **GitHub 镜像**: 备用数据源，提高可靠性
- **ExploitDB 映射**: CVE 与 exploit 关联
- **增量同步**: 每 2 小时增量同步，每 7 天全量同步
- **代理支持**: 7897 端口代理配置
- **本地缓存**: 减少网络请求，提高速度
- **CLI 手动更新**: `hos-ls nvd update` - 支持从本地压缩包手动更新NVD库

#### 手动更新NVD库

HOS-LS v0.3.0.4 提供了新的 CLI 命令，用于手动更新NVD漏洞库：

```bash
# 完整导入（处理所有CVE）
hos-ls nvd update

# 测试模式（只处理前20个文件，不导入RAG）
hos-ls nvd update --limit 20 --no-rag

# 指定压缩包路径
hos-ls nvd update --zip /path/to/nvd-json-data-feeds-main.zip

# 仅解析不导入RAG
hos-ls nvd update --no-rag

# 调整批量处理大小
hos-ls nvd update --batch-size 500
```

**功能**：
- ✅ 解析NVD v2.0和v1.1两种格式
- ✅ 自动解压`nvd-json-data-feeds-main.zip`
- ✅ 智能过滤不需要的文件（.github/workflows、LICENSES、_scripts等）
- ✅ 将CVE数据转换为Knowledge对象
- ✅ 支持导入到RAG知识库
- ✅ 实时进度显示和统计摘要
- ✅ 自动清理临时目录

### ⚔️ 攻击链分析

- **漏洞关系识别**: 因果、依赖、互补、同源关系
- **攻击路径构建**: DFS 图遍历，完整攻击链
- **风险得分计算**: 综合严重性、置信度、类型优先级
- **关键攻击链**: Top 5 最危险攻击路径
- **攻击场景描述**: 每个关系的具体攻击场景

***

## 🚀 快速开始

### 安装

```bash
# 使用 pip 安装
pip install hos-ls
```

### 30 秒上手

```bash
# 扫描当前目录（默认两阶段扫描）
hos-ls scan

# 扫描指定项目（使用函数级切片）
hos-ls scan /path/to/project --use-slicer

# 生成 HTML 报告
hos-ls scan --format html --output report.html

# 同步 CVE 数据（首次使用建议）
hos-ls cve-sync --full

# 攻击链分析
hos-ls analyze --attack-chain
```

### 预期输出

<img width="392" height="671" alt="image" src="https://github.com/user-attachments/assets/d112e464-5dc8-426b-911b-9f2dcd805b92" />

***

## 📚 详细使用

### 命令行参数

```bash
hos-ls scan [OPTIONS] [PATH]

Arguments:
  PATH                 要扫描的目录或文件 [默认: 当前目录]

Options:
  --format, -f         输出格式: html, json, markdown, sarif [默认: html]
  --output, -o         输出文件路径
  --ruleset, -r        规则集: owasp-top10, cwe-top25, all, v3 [默认: v3]
  --severity, -s       最低严重级别: critical, high, medium, low
  --workers, -w        并行工作进程数 [默认: 4]
  --diff               仅扫描 Git 差异
  --incremental        增量扫描（使用缓存）
  --ai                 启用 AI 分析
  --multi-phase        启用两阶段扫描 [默认: true]
  --use-slicer         启用函数级代码切片 [默认: true]
  --no-cache           禁用缓存
  --config, -c         配置文件路径
  --verbose, -v        详细输出
  --langgraph          使用 LangGraph 流程控制
  --help, -h           显示帮助信息

CVE 管理命令:
  hos-ls cve-sync       同步 CVE 数据
    --full              全量同步（默认增量）
    --only-nvd          仅同步 NVD
    --only-exploitdb    仅同步 ExploitDB

  hos-ls cve-search     搜索 CVE
    --cve-id CVE-XXXX-XXXX  按 CVE ID 搜索
    --keyword KEYWORD       按关键词搜索

  hos-ls nvd            NVD 漏洞库管理
    hos-ls nvd update     从本地压缩包更新 NVD 库
      --zip ZIP_PATH      NVD 压缩包路径
      --limit LIMIT       限制处理的文件数量（用于测试）
      --no-rag            不导入到 RAG 库，仅解析
      --batch-size SIZE   批量处理大小（默认: 200）
      --max-workers COUNT 最大工作线程数（默认: 8）
      --checkpoint-interval INTERVAL 检查点保存间隔
      --temp-dir DIR      临时文件目录
      --process-count COUNT 多进程数量（默认: 4）
    hos-ls nvd status     查看 NVD 导入状态
    hos-ls nvd clean      清理 NVD 临时文件

攻击链分析命令:
  hos-ls analyze        分析扫描结果
    --attack-chain      生成攻击链分析
    --output FILE       输出文件

Examples:
  # 扫描并生成 SARIF 报告（用于 GitHub Code Scanning）
  hos-ls scan --format sarif --output results.sarif

  # 使用两阶段扫描 + 函数级切片
  hos-ls scan --multi-phase --use-slicer

  # 仅扫描 Git 变更文件
  hos-ls scan --diff --severity high

  # 使用 OWASP Top 10 规则集
  hos-ls scan --ruleset owasp-top10

  # 启用 AI 深度分析
  hos-ls scan --ai --format html

  # 首次同步 CVE 数据（全量）
  hos-ls cve-sync --full

  # 增量同步 CVE
  hos-ls cve-sync

  # 攻击链分析
  hos-ls analyze --attack-chain --output attack-chain.json
```

### 配置文件

创建 `.hos-ls.yaml` 或 `hos-ls.toml`:

```yaml
# AI 配置
ai:
  provider: deepseek          # anthropic, openai, deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  base_url: https://api.deepseek.com
  enabled: true
  temperature: 0.0
  max_tokens: 4096
  timeout: 60

# 扫描配置
scan:
  max_workers: 4
  cache_enabled: true
  incremental: true
  timeout: 300
  max_file_size: 10485760  # 10MB
  exclude_patterns:
    - "*.min.js"
    - "*.min.css"
    - "node_modules/**"
    - "__pycache__/**"
    - ".git/**"
    - ".venv/**"
    - "venv/**"
    - "dist/**"
    - "build/**"
  include_patterns:
    - "*.py"
    - "*.js"
    - "*.ts"
    - "*.java"
    - "*.cpp"
    - "*.c"
    - "*.h"

# 函数级切片器配置
code_slicer:
  enabled: true
  max_slice_lines: 200
  include_context_lines: 10
  languages:
    - python
    - javascript
    - typescript

# 扫描调度器配置
scan_scheduler:
  enabled: true
  max_concurrent: 5
  max_retries: 3
  rate_limit: 10
  rate_limit_window: 60.0
  retry_delay: 1.0

# 多阶段扫描配置
multi_phase_scan:
  enabled: true
  phase1_max_tokens: 1024
  phase2_context_lines: 50

# 规则配置
rules:
  enabled: []
  disabled: []
  ruleset: v3
  severity_threshold: medium
  confidence_threshold: 0.5

# 报告配置
report:
  format: html
  output: ./security-report
  include_code_snippets: true
  include_fix_suggestions: true

# 数据库配置
database:
  url: sqlite:///hos-ls.db
  wal_mode: true
  pool_size: 5
  max_overflow: 10
  echo: false
  # Neo4j 配置
  neo4j:
    uri: bolt://localhost:7687
    username: neo4j
    password: password
  # PostgreSQL 配置
  postgres:
    host: localhost
    port: 5432
    database: hos_ls
    user: postgres
    password: password
    pool_size: 5
    max_overflow: 10

# NVD CVE 配置
nvd:
  enabled: true
  base_url: https://nvd.nist.gov/feeds/json/cve/1.1
  github_mirror_url: https://github.com/fkie-cad/nvd-json-data-feeds
  cache_dir: ~/.hos-ls/nvd_cache
  request_timeout: 60
  # NVD 导入配置
  import:
    batch_size: 200
    max_workers: 8
    timeout: 300
    retry_attempts: 3
    retry_delay: 1.0
    checkpoint_interval: 1000
    temp_dir: ~/.hos-ls/nvd_temp
    # 多进程配置
    multiprocessing:
      enabled: true
      process_count: 4
      chunk_size: 100
    # 批处理优化
    batch_optimization:
      read_batch: 200
      embed_batch: 32
      write_batch: 500
    # 切块配置
    chunking:
      enabled: true
      field_level: true
      token_level: true
      chunk_size: 400
      chunk_overlap: 80

# ExploitDB 配置
exploitdb:
  enabled: true
  repo_url: https://github.com/offensive-security/exploitdb.git
  local_dir: ~/.hos-ls/exploitdb

# CVE 同步管理器配置
cve_sync:
  enabled: true
  sync_interval_hours: 2
  full_sync_interval_days: 7
  nvd_enabled: true
  exploitdb_enabled: true
  state_file: ~/.hos-ls/cve_sync_state.json
  data_dir: ~/.hos-ls/cve_data

# 代理配置（7897端口）
proxy:
  enabled: true
  http_url: http://127.0.0.1:7897
  https_url: http://127.0.0.1:7897

# 向量存储配置（用于语义搜索）
vector_store:
  enabled: true
  backend: faiss  # chromadb 或 faiss
  persist_directory: ~/.hos-ls/faiss
  # FAISS 配置
  faiss:
    use_gpu: true
    index_type: hnsw
    embedding_dim: 384
  # 向量存储优化
  optimization:
    batch_size: 32
    embedding_cache: true
    cache_dir: ~/.hos-ls/embedding_cache
    max_cache_size: 100000
    use_gpu_embedding: true
    embedding_model: BAAI/bge-small-en-v1.5
    # BAAI bge 模型配置
    bge:
      model_name: BAAI/bge-small-en-v1.5
      model_kwargs: {device: "cuda"}
      encode_kwargs: {normalize_embeddings: true}
  # NaN 检测配置
  nan_detection:
    enabled: true
    filter_threshold: 0.001

# RAG知识库配置
rag:
  enabled: true
  persist_directory: ~/.hos-ls/rag
  knowledge_base_path: ./rag_knowledge_base
  enable_knowledge_graph: true
  semantic_search_threshold: 0.7
  # 混合RAG配置
  hybrid:
    enabled: true
    structured_storage: postgres
    vector_storage: faiss
    hybrid_search_weight: 0.7
    top_k: 10
    rerank: true
    rerank_model: bge-reranker-large
  # BM25 配置
  bm25:
    enabled: true
    k1: 1.2
    b: 0.75
    epsilon: 0.25
  # Rerank 配置
  rerank:
    enabled: true
    model: BAAI/bge-reranker-large
    top_k: 5
    threshold: 0.7

# CVE爬虫配置（v0.3.0.3 兼容）
cve_crawler:
  enabled: true
  crawl_interval_hours: 24
  max_cves_per_run: 100
  cve_sources:
    - nvd
    - mitre
  persist_directory: ~/.hos-ls/cve_data

# 文件优先级评估配置
file_prioritization:
  enabled: true
  high_priority_patterns:
    - ".*auth.*"
    - ".*security.*"
    - ".*config.*"
    - ".*secret.*"
    - ".*key.*"
  skip_low_priority_ai_analysis: true

# 沙箱配置
sandbox:
  enabled: true
  max_memory: 536870912  # 512MB
  max_cpu_time: 30
  network_access: false
  file_system_access: false

# 攻击链分析配置
attack_chain:
  enabled: true
  # 漏洞到代码模式映射
  pattern_mapping:
    enabled: true
    mappings_file: ~/.hos-ls/pattern_mappings.json
    update_interval: 24
  # 攻击链RAG
  rag:
    enabled: true
    top_k: 5
    threshold: 0.7
  # exploit知识注入
  exploit_knowledge:
    enabled: true
    sources: [exploitdb, cvedetails]
    update_interval: 12
  # 攻击面分析
  surface_analysis:
    enabled: true
    max_paths: 10
    risk_score_threshold: 7.0

# 全局配置
debug: false
verbose: false
quiet: false
```

### 环境变量

```bash
# AI API 密钥
export ANTHROPIC_API_KEY="your-key"
export OPENAI_API_KEY="your-key"
export DEEPSEEK_API_KEY="your-key"

# 代理配置（7897端口）
export HTTP_PROXY="http://127.0.0.1:7897"
export HTTPS_PROXY="http://127.0.0.1:7897"

# 配置路径
export HOS_LS_CONFIG_PATH="/path/to/config.yaml"

# 日志级别
export HOS_LS_LOG_LEVEL="DEBUG"
```

### Token 配置方法

HOS-LS 支持多种方式配置 AI API 密钥：

1. **配置文件配置**
   ```yaml
   ai:
     provider: deepseek
     model: deepseek-chat
     api_key: sk-your-api-key-here
     base_url: https://api.deepseek.com
   ```
2. **环境变量配置**
   ```bash
   # Windows
   set DEEPSEEK_API_KEY=sk-your-api-key-here

   # Linux/Mac
   export DEEPSEEK_API_KEY=sk-your-api-key-here
   ```

3. **命令行参数配置**
   ```bash
   hos-ls scan --ai --ai-provider deepseek
   ```

### 命令行配置方法

HOS-LS 提供了丰富的命令行参数来配置扫描行为：

```bash
# 基本扫描
hos-ls scan

# 扫描指定目录
hos-ls scan /path/to/project

# 使用函数级切片 + 两阶段扫描
hos-ls scan --use-slicer --multi-phase

# 启用 AI 分析
hos-ls scan --ai

# 指定 AI 提供商
hos-ls scan --ai --ai-provider deepseek

# 使用 LangGraph 流程控制
hos-ls scan --langgraph

# 生成不同格式的报告
hos-ls scan --format html --output report.html
hos-ls scan --format json --output report.json
hos-ls scan --format sarif --output results.sarif

# 使用特定规则集
hos-ls scan --ruleset owasp-top10
hos-ls scan --ruleset cwe-top25
hos-ls scan --ruleset v3

# 设置严重级别阈值
hos-ls scan --severity high

# 配置并行工作进程数
hos-ls scan --workers 8

# 增量扫描（使用缓存）
hos-ls scan --incremental

# 仅扫描 Git 差异
hos-ls scan --diff

# 指定配置文件
hos-ls scan --config config/default.yaml

# 详细输出
hos-ls scan --verbose

# 调试模式
hos-ls scan --debug

# 同步 CVE 数据
hos-ls cve-sync --full
hos-ls cve-sync

# 攻击链分析
hos-ls analyze --attack-chain
```

### 配置文件优先级

HOS-LS 按照以下优先级加载配置：

1. 命令行参数
2. 环境变量
3. 配置文件（按以下顺序查找）：
   - `config/default.yaml`
   - `hos-ls.yaml`
   - `hos-ls.yml`
   - `.hos-ls.yaml`
   - `.hos-ls.yml`
   - `~/.hos-ls/config.yaml`
   - `~/.hos-ls/config.yml`
   - `~/.config/hos-ls/config.yaml`
   - `~/.config/hos-ls/config.yml`
4. 默认配置

***

## 🏗️ 架构设计

### 系统架构 v3 (强 Multi-Agent 架构)

```mermaid
graph TB
    subgraph Input
        A[源代码] --> B[文件发现引擎]
        B --> C[文件优先级评估]
        C --> D[函数级代码切片器]
    end

    subgraph Core
        E[LangGraph Orchestrator] --> F[分析类 Agent]
        E --> G[知识类 Agent]
        E --> H[推理类 Agent]
        E --> I[控制类 Agent]
        E --> J[证据融合]
        E --> K[结果验证]
    end

    subgraph Analysis
        D --> E
        
        F --> F1[CST Analyzer]
        F --> F2[AST Analyzer]
        F --> F3[Taint Analyzer]
        
        G --> G1[RAG Knowledge Base]
        
        H --> H1[Semantic Agent]
        H --> H2[Attack Agent]
        H --> H3[Validation Agent]
        
        I --> I1[Fusion Agent]
        I --> I2[Orchestrator]
        
        F1 --> J
        F2 --> J
        F3 --> J
        G1 --> J
        J --> H1
        H1 --> H2
        H2 --> K
        K --> E
    end

    subgraph CVE_Integration
        N[NVD Feed 获取器] --> O[CVE 数据模型]
        P[ExploitDB 映射器] --> O
        Q[CVE 同步管理器] --> N
        Q --> P
        O --> G1
    end

    subgraph Output
        E --> R[报告生成器]
        R --> S[HTML/JSON/SARIF]
        E --> T[PR 评论]
        E --> U[IDE 插件]
    end

    subgraph Storage
        V[(RAG知识库)]
        W[(向量存储)]
        X[(CVE 缓存)]
        Y[(规则库)]
        Z[(Neo4j 图数据库)]
        G1 --> V
        G1 --> W
        O --> X
        F1 --> Y
        F2 --> Y
        H2 --> Z
    end

    subgraph External
        AA[NVD] --> N
        BB[ExploitDB] --> P
        CC[GitHub 镜像] --> N
    end
```

### 核心模块 v3

| 模块    | 路径                 | 功能描述                  |
| ----- | ------------------ | --------------------- |
| 核心引擎  | `src/core/`        | 扫描调度、多阶段扫描、结果聚合、攻击链分析、RAG + 图融合集成 |
| LangGraph  | `src/core/langgraph_*` | 流程控制、状态管理、条件分支逻辑、多Agent编排 |
| 分析器   | `src/analyzers/`   | AST/CST 分析、函数级代码切片      |
| 规则引擎  | `src/rules/`       | 安全规则定义与匹配             |
| AI 模块 | `src/ai/`          | 多模型集成、规则驱动 Prompt、模板管理、DSPy 自动优化 |
| 推理类 Agent | `src/ai/reasoning/` | 语义分析、攻击链生成、结果验证、可回流推理 |
| 攻击模拟  | `src/attack/`      | 攻击图构建、漏洞验证、ExploitDB 映射、Neo4j 攻击链分析 |
| 报告模块  | `src/reporting/`   | 多格式报告生成               |
| 集成工具  | `src/integration/` | CI/CD、IDE 插件集成、NVD Feed、CVE 同步、NVD 数据处理 |
| 沙箱系统  | `src/sandbox/`     | 安全代码执行环境              |
| 风险评估  | `src/assessment/`  | 漏洞风险评估、攻击链分析          |
| 缓存系统  | `src/cache/`       | 扫描结果缓存、CVE 缓存          |
| 插件系统  | `src/plugins/`     | 可扩展插件架构               |
| 污点分析  | `src/taint/`       | 数据流污点分析               |
| 学习系统  | `src/learning/`    | AI 学习与知识管理            |
| 存储系统  | `src/storage/`     | RAG 知识库、向量存储与代码嵌入、CVE 数据、FAISS 向量检索、PostgreSQL 集成 |
| 工具库   | `src/utils/`       | 文件优先级评估、通用工具函数        |
| Exploit | `src/exploit/`     | ExploitDB 映射器            |
| 数据库  | `src/db/`          | CVE 数据模型、数据库操作、Neo4j 连接管理 |
| 控制类 Agent | `src/core/fusion_agent.py` | 证据融合、多Agent输出整合、置信度评估 |
| 混合检索  | `src/core/hybrid_retriever.py` | 混合搜索、结构化搜索、语义搜索 |
| 攻击链分析 | `src/core/attack_chain_analyzer.py` | 漏洞到代码模式映射、攻击链 RAG、exploit 知识注入 |
| NVD 处理 | `src/integration/nvd_processor.py` | NVD JSON 解析、数据拆分、字段级语义切块 |
| NVD 导入 | `src/integration/nvd_importer.py` | NVD 数据导入、多进程处理、批量优化 |
| 导入管理 | `src/integration/import_manager.py` | 断点续传、去重机制 |
| 混合存储 | `src/storage/hybrid_store.py` | 集成 PostgreSQL 和向量存储、BM25 混合检索 |
| PostgreSQL | `src/storage/postgres_storage.py` | CVE 结构化数据存储 |
| 向量存储 | `src/storage/vector_store.py` | 优化的向量存储、embedding 缓存、NaN 检测 |
| 代码嵌入 | `src/storage/code_embedder.py` | BAAI bge 模型支持、批量 embedding |
| 语义引擎 | `src/ai/semantic_engine.py` | Rerank 功能、结果重新排序 |

### 多阶段扫描工作流程 (强 Multi-Agent 架构)

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Orchestrator
    participant Slicer
    participant AnalysisAgents
    participant KnowledgeAgents
    participant ReasoningAgents
    participant FusionAgent
    participant CVE
    participant Reporter

    User->>CLI: hos-ls scan --langgraph
    CLI->>Orchestrator: 初始化扫描
    Orchestrator->>Orchestrator: 文件发现与优先级排序
    
    loop 每个文件
        Orchestrator->>Slicer: 函数级代码切片
        Slicer-->>Orchestrator: 返回函数切片列表
        
        loop 每个切片
            Orchestrator->>AnalysisAgents: 并行分析（CST/AST/Taint）
            AnalysisAgents-->>Orchestrator: 分析结果
            
            Orchestrator->>KnowledgeAgents: RAG 知识库检索
            KnowledgeAgents-->>Orchestrator: CVE 信息 + 漏洞模式
            
            Orchestrator->>FusionAgent: 证据融合
            FusionAgent-->>Orchestrator: 统一证据格式
            
            Orchestrator->>ReasoningAgents: 语义分析 + 攻击链生成
            ReasoningAgents-->>Orchestrator: 深度分析结果 + 攻击链
            
            Orchestrator->>ReasoningAgents: 结果验证
            ReasoningAgents-->>Orchestrator: 验证结果 + 置信度评估
            
            alt 置信度低于阈值
                Orchestrator->>KnowledgeAgents: 回流分析（重新检索）
                KnowledgeAgents-->>Orchestrator: 增强的知识
                Orchestrator->>ReasoningAgents: 重新分析
            end
        end
    end
    
    Orchestrator->>Reporter: 生成报告
    Reporter->>User: 输出报告 + 攻击链 + 修复建议
```

***

## 🛡️ 安全规则

### OWASP Top 10 覆盖

| OWASP 类别  | HOS-LS 规则                                        | 检测能力 |
| --------- | ------------------------------------------------ | ---- |
| A01 访问控制  | auth-bypass, insecure-permissions                | ✅    |
| A02 加密失败  | weak-crypto, hardcoded-secret                    | ✅    |
| A03 注入    | sql-injection, command-injection, ldap-injection | ✅    |
| A04 不安全设计 | design-flaw, missing-validation                  | ✅    |
| A05 配置错误  | insecure-config, debug-enabled                   | ✅    |
| A06 脆弱组件  | vulnerable-dependency, cve-matching              | ✅    |
| A07 认证失败  | weak-password, session-fixation                  | ✅    |
| A08 完整性失败 | insecure-deserialization                         | ✅    |
| A09 日志失败  | sensitive-logging                                | ✅    |
| A10 SSRF  | ssrf, open-redirect                              | ✅    |

### CWE Top 25 覆盖

- ✅ CWE-79: XSS
- ✅ CWE-89: SQL Injection
- ✅ CWE-78: OS Command Injection
- ✅ CWE-20: Input Validation
- ✅ CWE-125: Buffer Overflow
- ✅ CWE-787: Out-of-bounds Write
- ✅ CWE-22: Path Traversal
- ✅ CWE-352: CSRF
- ✅ CWE-434: Unrestricted File Upload
- ✅ CWE-798: Hardcoded Credentials
- ✅ CWE-311: Missing Encryption
- ✅ CWE-295: Improper Certificate Validation
- ✅ CWE-601: URL Redirection
- ✅ CWE-918: SSRF
- ... 更多

### v3 新增规则

| 规则 ID | 规则名称 | 描述 | 严重性 |
| ------- | ------- | ---- | ------ |
| SQL_INJECTION | SQL 注入漏洞 | 检测字符串拼接 SQL 查询 | critical |
| COMMAND_INJECTION | 命令注入漏洞 | 检测 subprocess、os.system 等危险调用 | critical |
| XSS | 跨站脚本攻击 | 检测 innerHTML、document.write 等 | high |
| HARDCODED_CREDENTIALS | 硬编码凭证 | 检测硬编码密码、API 密钥 | high |
| WEAK_CRYPTO | 弱加密算法 | 检测 MD5、SHA1、DES 等弱加密 | medium |
| PATH_TRAVERSAL | 路径遍历 | 检测 ../ 路径拼接 | high |
| CSRF | 跨站请求伪造 | 检测缺少 CSRF token 的表单 | medium |
| SSRF | 服务端请求伪造 | 检测可控 URL 的请求 | high |
| DESERIALIZATION | 不安全反序列化 | 检测 pickle.load、yaml.load 等 | critical |
| SENSITIVE_DATA_EXPOSURE | 敏感数据暴露 | 检测日志中的敏感数据 | medium |

### 自定义规则

创建 `.hos-ls/rules/custom.yaml`:

```yaml
rules:
  - id: custom-sensitive-api
    name: Sensitive API Key Detection
    description: 检测自定义敏感 API 密钥
    severity: high
    languages: [python, javascript]
    pattern: |
      api_key\s*=\s*["'](?!(test_|mock_))[A-Za-z0-9]{32,}["']
    message: |
      发现疑似生产环境 API 密钥
      建议: 使用环境变量或密钥管理服务
    fix: |
      api_key = os.environ.get("API_KEY")
```

***

## 🔗 集成

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install HOS-LS
        run: pip install hos-ls
      
      - name: Sync CVE Data
        run: hos-ls cve-sync --full
        env:
          HTTP_PROXY: ${{ secrets.PROXY_URL }}
          HTTPS_PROXY: ${{ secrets.PROXY_URL }}
      
      - name: Run Security Scan
        run: |
          hos-ls scan \
            --format sarif \
            --output results.sarif \
            --ai \
            --multi-phase \
            --use-slicer \
            --severity high
        env:
          DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
          HTTP_PROXY: ${{ secrets.PROXY_URL }}
          HTTPS_PROXY: ${{ secrets.PROXY_URL }}
      
      - name: Attack Chain Analysis
        run: hos-ls analyze --attack-chain --output attack-chain.json
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11
  stage: test
  script:
    - pip install hos-ls
    - hos-ls cve-sync --full
    - hos-ls scan --format json --output report.json --ai --multi-phase --use-slicer
    - hos-ls analyze --attack-chain --output attack-chain.json
  artifacts:
    reports:
      sast: report.json
    paths:
      - attack-chain.json
  only:
    - merge_requests
    - main
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install hos-ls'
                sh 'hos-ls cve-sync --full'
                sh 'hos-ls scan --format html --output report.html --multi-phase --use-slicer'
                sh 'hos-ls analyze --attack-chain --output attack-chain.json'
            }
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'report.html,attack-chain.json',
                        reportName: 'Security Report'
                    ])
                }
            }
        }
    }
}
```

### VS Code 插件

1. 安装扩展: `hos-ls.vscode-hos-ls`
2. 配置 API 密钥
3. 配置代理（7897 端口）
4. 实时安全反馈

### Git Hooks

```bash
# pre-commit
#!/bin/bash
hos-ls scan --diff --severity high --format console
if [ $? -ne 0 ]; then
    echo "❌ Security issues found. Please fix before commit."
    exit 1
fi
```

***

## 📊 性能

### 性能基准 v3

测试环境: MacBook Pro M2, 16GB RAM, 5 workers, 两阶段扫描 + 函数级切片

| 项目规模      | 文件数       | 函数切片数 | 扫描时间     | Token 消耗 | 内存占用      | 说明                |
| --------- | --------- | ------ | -------- | ------- | --------- | ----------------- |
| 小型项目      | 50        | 200    | 2.0s     | -40%    | 120MB     | 两阶段扫描              |
| 中型项目      | 500       | 2000   | 12s      | -50%    | 350MB     | 两阶段扫描              |
| 大型项目      | 5000      | 20000  | 90s      | -60%    | 800MB     | 两阶段扫描              |
| **特大型项目** | **50000** | **200000** | **120s** | **-70%** | **1.2GB** | **两阶段 + 切片 + 优先级** |
| 增量扫描      | \~50      | \~200  | 1.0s     | -80%    | 100MB     | 使用缓存              |
| **LangGraph 流程** | 5000      | 20000  | **60s** | **-80%** | **600MB** | **按需执行 + 智能路径** |

### NVD 导入性能优化

| 配置      | 导入速度 | 内存使用 | 成功率 | 说明                |
| --------- | -------- | -------- | ------ | ----------------- |
| 单线程导入 | 100 CVE/秒 | 1.5GB | 95% | 基线              |
| 多线程导入 | 400 CVE/秒 | 1.8GB | 98% | 4倍速度提升              |
| 批量 Embedding | 600 CVE/秒 | 2.0GB | 99% | 6倍速度提升              |
| **流式处理 + 批量 + 缓存** | **1000 CVE/秒** | **1.2GB** | **99.9%** | **10倍速度提升，内存降低** |
| **多进程 + 字段级切块** | **1500 CVE/秒** | **1.0GB** | **99.95%** | **15倍速度提升，内存进一步降低** |

### GPU + Neo4j 性能提升

| 模块 | 性能提升 | 说明 |
|------|---------|------|
| Embedding 生成 | 5-10倍 | PyTorch GPU 加速 |
| 图构建 | 消除卡顿 | Neo4j 增量图构建 |
| 4000+ 漏洞处理 | 流畅处理 | 增量写入 + 索引优化 |
| 10万 CVE 支持 | ✅ 可支持 | 高效图存储与查询 |
| 攻击链查询 | 实时响应 | Neo4j 图数据库优化 |
| 相似度搜索 | 100ms 内 | FAISS GPU 加速 |

#### 优化效果对比 v3

| 扫描模式      | 50000文件扫描时间 | AI分析文件数 | Token 节省 |
| --------- | ----------- | ------- | ---- |
| 传统单阶段模式  | 1200s       | 50000   | -    |
| 两阶段模式    | 300s        | 5000    | 75%  |
| 两阶段+切片模式 | 120s        | 2000    | 85%  |
| 两阶段+切片+优先级 | 120s        | 800     | 90%  |

### 工具对比

| 特性       | HOS-LS v3 | Semgrep | SonarQube | CodeQL |
| -------- | :-------: | :-----: | :-------: | :----: |
| 函数级切片    |    ✅      |    ❌    |     ❌     |    ❌   |
| 多阶段扫描    |    ✅      |    ❌    |     ❌     |    ❌   |
| 规则驱动 Prompt |    ✅      |    ❌    |     ❌     |    ❌   |
| AI 分析    |    ✅      |    ❌    |     ⚠️    |    ❌   |
| RAG 知识库  |    ✅      |    ❌    |     ❌     |    ❌   |
| NVD CVE 集成 |    ✅      |    ❌    |     ❌     |    ❌   |
| ExploitDB 映射 |    ✅    |    ❌    |     ❌     |    ❌   |
| 攻击链分析    |    ✅      |    ❌    |     ❌     |   ⚠️   |
| 文件优先级评估  |    ✅      |    ❌    |     ❌     |    ❌   |
| 代理支持      |    ✅      |    ✅    |     ✅     |    ✅   |
| 零配置启动    |    ✅      |    ✅    |     ❌     |    ❌   |
| 增量扫描     |    ✅      |    ✅    |     ✅     |   ⚠️   |
| 误报率      |    低      |    中    |     中     |    中   |
| 自定义规则    |    ✅      |    ✅    |     ✅     |    ✅   |
| 特大型项目优化  |    ✅      |    ⚠️   |     ⚠️    |   ⚠️   |
| LangGraph 流程控制 |    ✅    |    ❌    |     ❌     |    ❌   |

***

## ❓ 常见问题 (FAQ)

<details>
<summary><b>HOS-LS v3 与之前版本有什么区别？</b></summary>

v0.3.0.4 带来了以下重大改进：

1. **函数级代码切片**: 基于 AST 解析，每个函数独立分析，保留完整上下文
2. **两阶段扫描**: Phase 1 轻量定位（低 Token）→ Phase 2 精准扫描（高准确率）
3. **规则驱动 Prompt**: 结构化检测规则，可扩展，提高准确性
4. **NVD CVE 集成**: 官方 NVD JSON Feed，自动增量同步
5. **ExploitDB 映射**: CVE 与 exploit 关联，提供攻击参考
6. **攻击链分析**: 构建漏洞间因果关系，识别关键攻击路径
7. **并发调度器**: async 并发、自动重试、速率限制
8. **代理支持**: 所有网络模块支持 7897 端口代理

</details>

<details>
<summary><b>如何配置代理（7897 端口）？</b></summary>

HOS-LS v3 支持多种代理配置方式：

1. **配置文件**（推荐）
   ```yaml
   proxy:
     enabled: true
     http_url: http://127.0.0.1:7897
     https_url: http://127.0.0.1:7897
   ```

2. **环境变量**
   ```bash
   export HTTP_PROXY="http://127.0.0.1:7897"
   export HTTPS_PROXY="http://127.0.0.1:7897"
   ```

3. **支持的模块**
   - NVD Feed 获取
   - ExploitDB 仓库克隆
   - GitHub 镜像访问
   - AI API 请求（如果配置）

</details>

<details>
<summary><b>如何使用两阶段扫描？</b></summary>

两阶段扫描是 v3 的核心特性，默认启用：

```bash
# 默认启用两阶段扫描
hos-ls scan

# 显式启用
hos-ls scan --multi-phase

# 禁用两阶段（单阶段）
hos-ls scan --no-multi-phase
```

**工作原理**：
- **Phase 1**: 使用低 Token Prompt 快速定位可疑点
- **Phase 2**: 仅对可疑点使用专项规则进行深度分析
- **Token 节省**: 通常可节省 50-80% 的 Token 消耗

</details>

<details>
<summary><b>如何同步 CVE 数据？</b></summary>

```bash
# 首次使用：全量同步
hos-ls cve-sync --full

# 日常使用：增量同步（默认）
hos-ls cve-sync

# 仅同步 NVD
hos-ls cve-sync --only-nvd

# 仅同步 ExploitDB
hos-ls cve-sync --only-exploitdb
```

**同步策略**：
- 默认每 2 小时增量同步
- 每 7 天自动全量同步
- 支持代理配置（7897 端口）
- 本地缓存，减少网络请求

</details>

<details>
<summary><b>如何使用本地压缩包手动更新NVD库？</b></summary>

如果您有NVD的本地压缩包（`nvd-json-data-feeds-main.zip`），可以使用新的CLI命令手动更新：

```bash
# 完整导入所有CVE数据
hos-ls nvd update

# 测试模式（只处理前20个CVE）
hos-ls nvd update --limit 20 --no-rag

# 指定压缩包路径
hos-ls nvd update --zip /path/to/nvd-json-data-feeds-main.zip

# 仅解析不导入RAG
hos-ls nvd update --no-rag
```

**命令特点**：
- 自动检测并解析NVD v2.0和v1.1格式
- 自动过滤不需要的文件（.github/workflows、LICENSES、_scripts等）
- 支持RAG知识库导入
- 友好的进度显示和统计

</details>

<details>
<summary><b>HOS-LS 与其他 SAST 工具有什么区别？</b></summary>

HOS-LS 专为 AI 生成代码设计，具有以下独特优势：

1. **函数级代码切片**: AST 精准切片，每个函数独立分析
2. **两阶段扫描**: 大幅节省 Token，同时保持高准确率
3. **AI 语义理解**: 深度理解 AI 生成代码的意图和模式
4. **规则驱动 Prompt**: 结构化检测规则，可扩展
5. **NVD + ExploitDB 集成**: 完整的 CVE 数据管理
6. **攻击链分析**: 可视化展示完整的攻击链
7. **自动修复建议**: AI 生成安全修复代码
8. **代理支持**: 7897 端口配置

</details>

<details>
<summary><b>如何处理误报？</b></summary>

HOS-LS 提供多种误报处理方式：

1. 使用 `--ai` 参数启用 AI 深度分析
2. 使用两阶段扫描（`--multi-phase`）提高准确性
3. 在配置文件中禁用特定规则
4. 使用 `# hos-ls: ignore` 注释忽略特定行
5. 自定义规则调整检测逻辑
6. 调整置信度阈值（`confidence_threshold`）

</details>

<details>
<summary><b>支持哪些 AI 模型？</b></summary>

目前支持：

- **Anthropic**: Claude 3.5 Sonnet, Claude 3 Opus
- **OpenAI**: GPT-4, GPT-4 Turbo
- **DeepSeek**: DeepSeek Coder, DeepSeek Chat
- **本地模型**: 支持 Ollama 部署的模型

v3 新增规则驱动 Prompt，优化了所有模型的输出质量。

</details>

<details>
<summary><b>如何保护 API 密钥安全？</b></summary>

推荐做法：

1. 使用环境变量存储密钥
2. 使用密钥管理服务（AWS Secrets Manager、HashiCorp Vault）
3. 配置 CI/CD 密钥注入
4. 启用 HOS-LS 的密钥加密存储功能
5. 不要将密钥提交到代码仓库

</details>

<details>
<summary><b>如何启用 GPU 加速？</b></summary>

HOS-LS 会自动检测 GPU 并启用加速：

1. **确保安装了 PyTorch GPU 版本**
   ```bash
   pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
   ```

2. **配置文件设置**
   ```yaml
   vector_store:
     faiss:
       use_gpu: true
   ```

3. **验证 GPU 加速**
   运行时会显示 "✅ Using GPU: [GPU 型号]" 的日志信息

</details>

<details>
<summary><b>如何配置 Neo4j
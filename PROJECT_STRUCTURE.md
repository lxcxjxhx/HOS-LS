# HOS-LS 项目目录结构

## 概况

```
hos-ls/
├── src/               # 核心源代码 (276 文件, ~4.2 MB)
├── tests/             # 测试套件
├── dynamic_code/      # 动态 POC 验证代码
├── prompts/           # 提示词模板
├── config/            # 默认配置文件
├── rag_knowledge_base/# RAG 知识库数据
├── bench/             # 基准测试
├── scripts/           # 辅助脚本
├── .github/           # CI/CD 工作流
└── [根文件]           # pyproject.toml, Dockerfile, README.md 等
```

---

## src/ 目录结构

```
src/
│
├── core/                          # 核心扫描引擎
│   ├── scanner.py                 # [#1] SecurityScanner 主类 (4274行 → 需进一步拆分)
│   ├── scanner_tools.py           # [新增] _tool_prescan + _fallback_local_build 函数
│   ├── remote_scanner.py          # RemoteSecurityScanner + create_scanner 工厂
│   ├── sal.py                     # SAL (Sink-Anchored Locator) 锚
│   ├── dep.py                     # DEP (Differential Evidence Protocol)
│   ├── config.py                  # 配置解析 (606行)
│   ├── engine.py                  # ScanEngine / ScanResult / ScanMode
│   ├── scan_state.py              # 扫描状态管理
│   ├── scan_cache.py              # 扫描缓存
│   ├── scan_scheduler.py          # 扫描调度器
│   ├── types.py                   # 类型定义
│   ├── file_filter.py             # 文件过滤
│   ├── chunk_processor.py         # 代码分块处理
│   ├── preloader.py               # 预加载器
│   ├── related_file_preloader.py  # 关联文件预加载
│   ├── fusion_agent.py            # 融合 Agent
│   ├── multi_stage_scanner.py     # 多阶段扫描 (575行)
│   ├── result_aggregator.py       # 结果聚合 (525行)
│   ├── plan_generator.py          # 计划生成
│   ├── registry.py                # 模块注册表
│   ├── config_center.py           # 配置中心
│   ├── langgraph_flow.py          # LangGraph 流程 (942行)
│   ├── langgraph_flow_v2.py       # LangGraph V2 流程
│   ├── langgraph_state.py         # LangGraph 状态定义
│   ├── attack_chain_analyzer.py   # 攻击链分析
│   ├── hybrid_retriever.py        # [待迁移→移除] CVE 混合检索
│   └── __init__.py                # 导出 SecurityScanner, RemoteSecurityScanner, create_scanner
│
├── diff/                          # [新增] 差分证据分析
│   ├── sink_validators/           #   Sink 级前提验证器
│   │   └── __init__.py
│   └── __init__.py
│
├── benchmarks/                    # [新增] 评测基准适配器
│   └── __init__.py
│
├── ai/                            # AI 分析层
│   ├── providers/                 #   LLM 提供商适配
│   │   ├── deepseek.py
│   │   ├── openai.py
│   │   ├── aliyun.py
│   │   └── anthropic.py
│   ├── pure_ai/                   #   纯 AI 分析管线
│   │   ├── multi_agent_pipeline.py  # [#2] MultiAgentPipeline (3645行 → 需拆分)
│   │   ├── schema_validator.py      # [#3] SchemaValidator (1442行，LineNumberValidator已提取)
│   │   ├── line_number_validator.py  # [新增] LineNumberValidator (1297行，从schema_validator提取)
│   │   ├── context_builder.py       # [#4] ContextBuilder (1524行)
│   │   ├── file_prioritizer.py      # [#5] AI 文件优先级 (1363行)
│   │   ├── agent_voting.py          # Agent 投票 (895行)
│   │   ├── self_consistency.py      # 自一致性 (678行)
│   │   ├── line_number_mapper.py    # 行号映射 (522行)
│   │   ├── analysis_cache.py        # [重命名] 分析缓存 (原 cache.py)
│   │   ├── checkpoint_manager.py
│   │   ├── context_memory.py
│   │   ├── concurrency.py
│   │   ├── cost_tracker.py
│   │   ├── cwe_prompt_selector.py
│   │   ├── dynamic_agent.py
│   │   ├── environment.py
│   │   ├── incremental_index.py
│   │   ├── json_utils.py
│   │   ├── prompt_evolver.py
│   │   ├── schema.py
│   │   └── rag/                    # RAG 知识库
│   │       ├── knowledge_base.py   # (1258行)
│   │       ├── code_embedder.py    # (931行)
│   │       ├── vector_store.py
│   │       ├── faiss_vector_store.py
│   │       ├── hybrid_retriever.py
│   │       ├── hybrid_store.py
│   │       ├── self_learning.py
│   │       ├── bm25_index.py
│   │       ├── query_rewriter.py
│   │       ├── reranker.py
│   │       ├── postgres_storage.py
│   │       ├── graph_integrator.py
│   │       ├── embedding_optimizer.py
│   │       ├── embedding_trainer.py
│   │       ├── rule_matcher.py
│   │       ├── semantic_chunker.py
│   │       └── vector_store_base.py
│   ├── pure_ai_analyzer.py       # [#6] PureAIAnalyzer (2912行 → 需拆分)
│   ├── models.py                 # 数据模型
│   ├── client.py                 # AI 客户端
│   ├── balance.py                # 余额查询
│   ├── cost_estimator.py         # 费用预估
│   ├── prompt_engine.py          # 提示词引擎
│   ├── token_tracker.py          # Token 追踪
│   ├── prompts.py                # 提示词常量
│   └── errors.py                 # AI 异常
│
├── analyzers/                     # 代码分析器
│   ├── exploit_generator.py       # [#7] 利用生成 (1668行)
│   ├── dependency_chain_analyzer.py # [#8] 依赖链分析 (1619行)
│   ├── tiered_analysis_pipeline.py # [#9] 三层分析管道 (1328行)
│   ├── finding_verifier.py        # Finding 验证 (1084行)
│   ├── input_tracer.py            # 输入追踪 (1062行)
│   ├── risk_quantifier.py         # 风险量化 (1187行)
│   ├── code_vuln_scanner.py       # 代码漏洞扫描 (993行)
│   ├── sarif_standardizer.py      # SARIF 标准化 (1035行)
│   ├── ast_analyzer.py            # AST 分析 (876行)
│   ├── cst_analyzer.py            # CST 分析 (857行)
│   ├── code_slicer.py             # 代码切片
│   ├── line_level_locator.py      # 行级定位
│   ├── sast_prefilter.py          # SAST 前置过滤
│   ├── config_scanner.py          # 配置扫描
│   ├── config_finding_enhancer.py
│   ├── context_analyzer.py
│   ├── port_scanner.py
│   ├── port_file_mapper.py
│   ├── unified_finding_validator.py
│   ├── verification_adapter.py
│   ├── verification_pipeline.py
│   └── verification/              # POC 验证引擎
│       ├── ast_transpiler_engine.py
│       ├── poc_generator.py
│       ├── virtual_runtime.py
│       ├── multi_lang_mocks.py
│       ├── result_reviewer.py
│       ├── transpiler_quality_verifier.py
│       ├── java_to_python_converter.py
│       └── ...
│
├── cli/                           # 命令行界面
│   ├── main.py                    # [#10] CLI 入口 + 所有命令 (2327行 → 需拆分)
│   ├── panel/                     #   配置面板 (TUI)
│   └── serial_port/               #   串口工具
│
├── utils/                         # 工具模块
│   ├── priority_engine.py         # [#11] 优先级引擎 (1676行)
│   ├── file_discovery.py          # 文件发现
│   ├── file_prioritizer.py        # 文件优先级
│   ├── custom_priority_parser.py  # 自定义优先级解析 (761行)
│   ├── ai_file_prioritizer.py     # AI 文件优先级
│   ├── cache_manager.py           # 缓存管理
│   ├── logger.py                  # 日志
│   └── ...
│
├── reporting/                     # 报告生成
│   ├── generator.py               # [#12] 报告生成器 (1175行)
│   ├── category.py                # 漏洞分类
│   ├── formatter.py               # 格式化
│   ├── template_engine.py         # 模板引擎
│   └── templates/                 # HTML/Markdown 模板
│
├── rules/                         # 规则引擎
│   ├── registry.py                # 规则注册表
│   ├── loader.py                  # 规则加载
│   ├── base.py                    # 规则基类
│   └── builtin/                   # 内置规则（注入/认证/加密等）
│
├── integration/                   # 外部集成
│   ├── nvd_importer.py            # NVD 导入
│   ├── nvd_processor.py           # NVD 处理
│   ├── cve_crawler.py             # CVE 爬取
│   ├── vulnerability_crawler.py   # 漏洞爬取
│   ├── data_preloader.py          # 数据预加载
│   ├── remote.py                  # 远程扫描服务
│   ├── templates.py               # 扫描模板
│   ├── remote_scan/               # 远程扫描协议
│   └── ...
│
├── nvd/                           # NVD 漏洞库
│   ├── downloader.py
│   ├── sync.py
│   ├── cli.py
│   ├── query_cache.py
│   ├── nvd_query_adapter.py
│   ├── db/
│   ├── etl/
│   └── query/
│
├── assessment/                    # 风险评估
│   ├── risk_engine.py             # (539行)
│   ├── vulnerability_assessor.py  # (859行)
│   ├── evidence_chain.py          # 证据链
│   └── reachability_analyzer.py   # 可达性
│
├── plugins/                       # 插件系统
│   ├── base.py
│   ├── manager.py
│   ├── registry.py
│   ├── config_loader.py
│   └── builtin/                   # 内置插件
│
├── db/                            # 数据库
│   ├── connection.py
│   ├── models.py
│   └── neo4j_connection.py
│
├── cache/                         # 缓存管理
│   ├── manager.py                 # CacheManager (通用)
│   ├── analysis_cache.py
│   └── incremental_scan_cache.py
│
├── execution/                     # POC 执行
│   ├── poc_runner.py
│   └── venv_manager.py
│
├── translation/                   # 代码翻译
│   └── code_translator.py
│
├── security/                      # 安全工具
│   ├── api_key_manager.py
│   └── security_checker.py
│
├── analysis/                      # 威胁情报
│   └── threat_intelligence.py
│
├── vulnerability/                 # 漏洞数据库客户端
│   ├── nvd_database.py
│   ├── osv_client.py
│   └── github_advisory_client.py
│
├── vuln_data/                     # 漏洞数据
│   ├── nvd_adapter.py
│   ├── library_matcher.py
│   └── vulnerability_data_manager.py
│
├── i18n/                          # 国际化
│   ├── locale.py
│   └── translations.py
│
└── config/                        # 动态配置
    └── dynamic_config.py
```

---

## 模块依赖层次

```
Layer 0: 基础定义
  src/core/types.py, src/ai/models.py, src/core/sal.py, src/core/dep.py
  src/diff/*, src/benchmarks/*

Layer 1: 工具层
  src/utils/*, src/cache/*, src/i18n/*, src/security/*

Layer 2: 分析层
  src/analyzers/*, src/assessment/*, src/rules/*

Layer 3: AI 分析
  src/ai/*, src/translation/*, src/analysis/*

Layer 4: 扫描编排
  src/core/scanner.py, src/core/*

Layer 5: 集成与报告
  src/integration/*, src/nvd/*, src/reporting/*

Layer 6: 入口
  src/cli/main.py, src/plugins/*
```

---

## 已完成的结构优化

| 操作 | 文件 | 状态 |
|------|------|------|
| 删除 | `bench-runs/` (旧历史冗余) | ✅ |
| 删除 | `envs/` (空目录) | ✅ |
| 删除 | `src/ai/cache.py` (未使用的死代码) | ✅ |
| 重命名 | `src/ai/pure_ai/cache.py` → `analysis_cache.py` | ✅ |
| 提取 | `RemoteSecurityScanner` + `create_scanner` 到 `remote_scanner.py` | ✅ |
| 更新 | `core/__init__.py` 导出新模块 | ✅ |
| 提取 | `line_number_validator.py` 从 `schema_validator.py` (2345→1297行) | ✅ |
| 拆分 | `dependency_chain_analyzer.py` → `dependency_models.py` + `dependency_cve_checker.py` (2037→1397行) | ✅ |
| 拆分 | `priority_engine.py` → `priority_models.py` (1833→784行) | ✅ |
| 提取 | `scanner.py` 工具方法 → `scanner_tools.py` / `scanner_finding.py` / `scanner_rules.py` / `scanner_analyze.py` | ✅ |
| 提取 | `scanner.py` _analyze_files(1127行) → `analyze_files.py` | ✅ |
| 拆分 | `multi_agent_pipeline.py` → `pipeline_constants.py` / `known_file_registry.py` / `evidence_chain.py` | ✅ |
| 提取 | `pure_ai_analyzer.py` → `result_converter.py` | ✅ |
| 拆分 | `multi_agent_pipeline.py` → `pipeline_llm.py` (_generate_with_retry + _parse_json_response) | ✅ |
| 拆分 | `exploit_generator.py` (2053→1136行) → `exploit_types.py` / `exploit_templates.py` / `exploit_scorer.py` | ✅ |
| 提取 | `cli/main.py` (2327行) → `commands/` 子目录 (7个命令文件) | ✅ |
| 创建 | `src/core/sal.py` (SAL 骨架) | ✅ |
| 创建 | `src/core/dep.py` (DEP 骨架) | ✅ |
| 创建 | `src/diff/` (差分证据分析模块) | ✅ |
| 创建 | `src/benchmarks/` (评测基准适配器) | ✅ |

## 建议下一步拆分优先级 (Top 10 大文件)

| 优先级 | 文件 | 当前行数 | 建议方式 |
|--------|------|---------|----------|
| P0 | `src/core/scanner.py` | 2565 | 提取 scan() 方法到 scanner_run.py |
| P1 | `src/ai/pure_ai/multi_agent_pipeline.py` | 3816 | 提取 Agent 0-6 运行器到 agents/ 子目录 |
| P2 | `src/ai/pure_ai_analyzer.py` | 3290 | 提取 analyze_batch/resume/incremental |
| P3 | `src/cli/main.py` | 2327 | ✅ 已完成 (命令拆分到 commands/) |
| P4 | `src/ai/pure_ai/schema_validator.py` | 1442 | ✅ 已完成 |
| P5 | `src/analyzers/dependency_chain_analyzer.py` | 1397 | ✅ 已完成 |
| P6 | `src/analyzers/exploit_generator.py` | 1136 | ✅ 已完成 (提取 types/templates/scorer) |
| P7 | `src/utils/priority_engine.py` | 784 | ✅ 已完成 |
| P8 | `src/ai/pure_ai/context_builder.py` | 1524 | 提取 SIR / 数据流模块 |
| P9 | `src/analyzers/tiered_analysis_pipeline.py` | 1328 | 提取正则模式库 |

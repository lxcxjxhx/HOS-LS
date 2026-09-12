# 旧方案与历史主线总归档（HOS-LS 研究线）

> 归档日期：2026-09-11。本文是**所有**旧方案材料的统一索引与压缩摘要。
> 现行方案：`docs/research-plan-v2-dcav.md`（v2）+
> `docs/p0-kill-experiment-plan.md`（P0 展开）。
> 归档原则：原文全部保留在 git 历史（不删代码、不删历史），本文只存
> 结论与去向映射；任何旧文档被引用时先查本文的"去向"列。

## 归档总目

| # | 材料 | 位置（git 历史锚点） | 状态 | 去向 |
| --- | --- | --- | --- | --- |
| 1 | ECATSL spec A/B 三件套 | `_spec/{evidence-constrained-taint-spec-learning, ecatsl-operationalization-and-bench-integration}/`，删于 `e52fc33b` | 已完成/主体完成 | 详见 `docs/archive/ecatsl-spec-v1-archive.md` |
| 2 | .kiro spec 早期副本 | `.kiro/specs/evidence-constrained-taint-spec-learning/`，删于 `3cb9d4ea` | 与 #1 同内容早期版 | 并入 #1 归档，不单独维护 |
| 3 | 旧 pure_ai 主线（多智能体扫描线） | **代码仍在**：`src/ai/pure_ai/`（46 文件）、`src/core/`、`src/analyzers/`、`src/assessment/`、`dynamic_code/` | 活跃代码，非文档 | 设计意图归档于 §2；组件去向见 P0 §6 资产表 |
| 4 | 战术修复计划 ×5 | `.trae/documents/`，删于早期提交 | 已执行完毕 | §3 一句话摘要，无后续价值 |
| 5 | 重构工具指南 | `REFACTORING_GUIDE.md`（已删） | 过时 | 工具链说明，无研究价值，不归档内容 |
| 6 | v1 运行事实报告 | `docs/ecatsl-run-report.md`（在库） | 有效运行记录 | 保留原位；是 P0/P1 的实证输入，非归档对象 |

## 1. ECATSL 线（v1，已并入现行方案）

见 `docs/archive/ecatsl-spec-v1-archive.md`，此处不重复。要点：spec A 9/9
完成；spec B 主题 A/B/C 完成、C-3 实际完成未勾、主题 D 未做（去向已映射到
v2 P3 / P0 §0 对照表 #15）。

## 2. 旧 pure_ai 主线（多智能体扫描线，代码保留）

### 2.1 原设计意图（README 四阶段架构，压缩）

`静态规则快速召回 → Search Agent 限深 → 7-Agent 多智能体语义判断 →
确定性执行器验证（不依赖 LLM 自评）`；分层把 LLM 调用限制在候选子集
（静态层约 5.3s vs 单文件 AI 分析 130–160s）。定位是**单版本单文件级**
扫描器，输入是当前代码库快照，无 before/after 差分概念。

### 2.2 与 v2 主问题的关系（为什么要换线）

v2 主问题输入是 `R_before, task, Δ, R_after` 四元组，核心是**跨版本归因**
（责任修改定位 + 新增路径判定），单版本扫描回答不了"是否本次引入"。
旧主线的设计意图（分层召回、确定性验证优先于 LLM 自评、证据链追踪）
**全部被 v2 继承**，只是作用对象从"单版本文件"变为"双版本 diff"。

### 2.3 组件去向速查（详表见 P0 §6）

| 组件组 | 代表文件 | 设计意图 | v2/P0 去向 |
| --- | --- | --- | --- |
| 差分分析 | `diff_analysis_agent.py` | diff → 新增/删除风险路径 | C 臂候选生成器（直接承接） |
| 契约违背 | `contract_violation_agent.py` | 三焦点场景检测（Python AST） | 场景语义承接；C/C++ 走 CodeQL |
| 反事实构造 | `counterfactual_agent.py` | 片段级安全反事实 + 规则验证 | 构造层承接；执行层新建 |
| 证据链/信号 | `evidence_chain.py`、`schema.py`（`SignalState`/`Verdict`/`EvidenceType`） | 多 agent 信号与证据追踪 | C 臂证据包 schema 承接 |
| 流水线装配 | `multi_agent_pipeline.py`、`agent_0..6`、`agent_selector.py`、`agent_voting.py` | 7-agent 编排 | B 臂 harness 装配承接 |
| 基础设施 | `src/ai/client.py`、`key_manager.py`、`cost_tracker.py`、`checkpoint_manager.py`、`concurrency.py` | LLM 客户端/成本/断点 | P0 全线直接复用 |
| 动态验证 | `dynamic_code/`（Web validators ×15 + PoC 模板） | Web 缺陷 requests 级验证 | Python/Web 补位线专用，不为 C/C++ 硬改 |
| 利用生成 | `analyzers/exploit_generator.py`、`assessment/reachability_analyzer.py`、`risk_engine.py` | PoC 生成/可达性/风险 | P0 不用（PoV 来自 ARVO）；P1+ 再评估 |
| 深度验证 | `analyzers/deep_verifier.py`、`src/core/scanner_*` | 单版本深度扫描 | 保留现状，v2 不动；若 P1 需要 Python 主线对照可回接 |

### 2.4 处置决定

代码**一律保留、不删不改**（它是 HOS-LS 主产品能力，也是 B 臂的承接
对象）。旧线与 v2 线的关系：v2 不是重写旧线，而是给旧线的差分/反事实/
证据链组件**换输入源（双版本）+ 换目标场景（C/C++）+ 换验证层级
（系统级干预）**。任何"看起来要重写"的需求，先回查 §2.3 表。

## 3. 战术修复文档（已执行完毕，一句话存目）

| 文档 | 内容 | 备注 |
| --- | --- | --- |
| `.trae/documents/chat_mode_implementation_plan.md` | chat 模式实现计划 | 已实现 |
| `.trae/documents/fix-json-parsing-error.md` | JSON 解析错误修复 | 已修复 |
| `.trae/documents/fix-report-generation-bug.md` | 报告生成 bug 修复 | 已修复 |
| `.trae/documents/readme-update-plan-v0.3.2.4.md` | README 更新计划 | 已执行 |
| `.trae/documents/update_readme_plan.md` / `update_version_plan.md` | README/版本更新 | 已执行 |

## 4. 归档纪律（对现行方案的反向约束）

1. 现行方案（v2/P0）是**唯一**活跃方案文档；新想法先进 P0 报告的
   "给 P1 的实证输入"，不新开方案文档。
2. 引用旧设计必须经过本文 §2.3 或 P0 §6 的映射表，禁止直接"重新发明"。
3. 后续每完成一个阶段（P0/P1/…），在 `docs/archive/` 增加对应归档摘要
   并更新本表，保持"git 历史 = 全量、docs/archive = 压缩、docs/ 根目录 =
   仅活跃文档"三层结构。

# Requirements Document

## Introduction

本规格定义 HOS-LS 下一开发循环：ECATSL（Evidence-Constrained Adaptive Taint Specification Learning，规格 `b77c55d3-124c-48b4-9700-f4467cc7df0f` 已于 PR #63 完成全部 9 节实现并合并 main）进入实战验证与产品化阶段。本循环包含四个主题，按依赖顺序构成一个完整循环：

1. **代码健康清零**（Theme A）：消除 `flake8 src` 680 项与 `mypy src` 290 项遗留，处置工作树未跟踪杂项，使 CI 质量门禁从"informational/continue-on-error"升级为 blocking。这是后续所有主题的工程前提。
2. **CI 真实验证**（Theme B）：`.github/workflows/ci.yml` 的 pytest 步骤当前只运行 `pytest --collect-only`（仅收集不执行）。必须让 CI 真实执行测试套件，使每个 PR 的合并门禁反映实际测试结果。
3. **ECATSL CLI 接入与实战验证**（Theme C）：将已合并的 `ECATSLService` 接入 CLI（`hos-ls ecatsl` 命令组），在 VulnGym/SecureVibeBench 真实样本上端到端运行 dataset release → 评估 → 成本报告链路，产出第一份基于真实数据的 ECATSL 评估报告（`Evaluation_Report` + `Cost_Report` + `Data_Quality_Report` 工件）。
4. **PureAI 基准分数卡整合与 ECATSL 范围扩展评估**（Theme D）：将 ECATSL 评估工件与既有 `bench/benchmark.py` 分数卡流程整合为统一评测入口；基于实战数据出具 ECATSL 范围扩展（新语言/新 CWE）的**证据化可行性评估报告**（非实现承诺）。

范围边界（继承既有证据边界，不得放宽）：

- Catalog、RAG、LLM、模板、discovery、推断的 endpoint/entrypoint 永远是假设或解释性支持；只有受支持静态适配器产出的完整 `Path_Evidence` 可以确认 finding。CLI 接入不得提供绕过该边界的配置项。
- ECATSL 范围扩展在本循环内只做证据化评估与设计准备，不承诺实现。若评估结论为可行且用户批准，作为后续独立 spec 立项。
- 代码健康清零不改变任何运行时行为；纯类型注解、导入清理、死代码移除与杂项归档。行为回归由全量测试套件守护。

## Glossary

- **主题 A（代码健康清零）**：将 `flake8 src` 归零、`mypy src` 收敛到白名单零新增、未跟踪杂项全部处置（归档/入库/删除）。
- **主题 B（CI 真实验证）**：CI 的 pytest 步骤真实执行测试（至少 ECATSL 单元+集成子集），失败即 blocking；flake8 blocking 选择器覆盖新增回归。
- **质量门禁升级**：flake8 informational 步骤（`--extend-ignore=... || true`）改为按目录分级的 blocking 配置。
- **主题 C（ECATSL CLI）**：`hos-ls ecatsl` Click 命令组：`analyze`（单仓库分析）、`evaluate`（数据集评估）、`report`（成本/优化报告）、`dataset`（dataset release 构建）。配置经 `ECATSLConfig` 门禁，落库沿用现有 SQLite 目录。
- **实战数据集**：VulnGym 中 Python 生态子集（预计 ≥60 条，含 `openclaw` 仓库样本）经 `dataset_release.build_release()` 构建的 release；不足时以 SecureVibeBench/A.S.E 样本补充并在 `Data_Quality_Report` 中记录。
- **第一份真实评估报告**：在实战数据集上由 `evaluation.build_evaluation_report()` 与 `reporting.build_cost_report()` 产出的不可变工件，含全局与分层 verified metrics、成本、失败与排除计数。
- **主题 D（统一评测入口）**：`bench/` 下新增 orchestration 入口，一次运行同时产出 PureAI 分数卡（召回/误报/耗时/Token）与 ECATSL 评估工件，共享标签与 manifest 血缘。
- **范围扩展可行性评估报告**：基于 VulnGym 语言/CWE 分布统计与实战运行数据的文档化评估，明确新语言/新 CWE 的复用面、缺口、工作量量级与建议优先级；不包含 superiority 语言，不做实现承诺。
- **ECATSL_SNAPSHOT 仓库**：`hosls-eval` 仓库外评测集之外的、随 spec 管理的 ECATSL 专用样本集（含 ground truth 标注），位于 `bench/datasets/ecatsl_eval/`（仅 manifest 与哈希，不入库大文件）。

## Requirements

### Requirement 1: 代码健康清零（主题 A）

flake8 与 mypy 遗留必须归零或收敛到显式白名单，未跟踪杂项必须全部处置，且全过程不改变运行时行为。

#### Acceptance Criteria

1.1 `flake8 src` 返回 0 项发现（当前 680 项：F401/W291/W293/F841/E712/E402/W292/E501 等分布于 `artifact_repository.py`、`candidate_ledger.py`、`confirmation.py`、`tooling_resolver.py` 及 ECATSL 之外的 `src/` 文件）。

1.2 `mypy src` 的 290 项错误收敛为：本循环触及文件 0 项；未触及文件要么清零、要么进入 `pyproject.toml`/`mypy.ini` 中带注释的显式 per-module 白名单（记录错误码与原因），白名单外 0 项。

1.3 工作树未跟踪杂项全部处置：`_pr_body_44.md`、`_pr_body_46.md`、`evidence-constrained-taint-spec-learning.rar` 删除；`scripts/install_mcp_network_guard.py`、`scripts/mcp_network_guard_server.py`、`scripts/mcp_proxy_guard.sh`、`reasonix.toml` 明确归属（入库或加入 `.gitignore` 并在 `.gitignore` 内注释原因）；`_spec/evidence-constrained-taint-spec-learning/` 三件套与 `.config.kiro` 入库（作为已完成规格的历史档案）。

1.4 行为不回归：全量 `pytest tests` 保持 0 failed（基线 460 passed / 28 skipped；主题 A 完成后 skip 集允许因模块落地而减少，不允许新增失败）。

1.5 `flake8` 的 CI blocking 选择器（`E9,F63,F7,F82`）对全仓库 0 项发现；informational 步骤升级为 per-directory 分级 blocking：`src/ecatsl/`、`tests/` 为 blocking（0 容忍），其余目录维持 informational 并记录原因。

### Requirement 2: CI 真实验证（主题 B）

CI 必须真实执行测试套件而非仅收集，使合并门禁反映实际测试结果。

#### Acceptance Criteria

2.1 `.github/workflows/ci.yml` 的 pytest 步骤从 `pytest --collect-only` 改为真实执行：至少 `pytest tests/unit/ecatsl tests/integration/ecatsl tests/unit/core -q`（当前合计 ≈306 项，预估 CI 时长 < 10 分钟），失败即 job 失败。

2.2 全量 `pytest tests` 作为独立（允许 scheduled/手动触发或 retry-on-timeout 的）job 保留，避免 PR 时长膨胀；其失败以 required check 之外的可见方式报告（如 workflow 名 `full-tests`）。

2.3 CI 中 `mypy` 步骤按 Requirement 1.2 的白名单运行后 0 项白名单外错误（`|| echo` 容忍语义移除或改为显式失败）。

2.4 CI 中 flake8 步骤与 Requirement 1.5 的分级配置一致，informational 步骤保留 `|| true` 但必须输出发现计数供人工审阅。

2.5 主题 B 合入后，在真实 PR 上验证一次红-绿循环：人为引入一个会失败的测试断言 → CI 红灯；还原 → 绿灯。

### Requirement 3: ECATSL CLI 接入（主题 C-1）

`ECATSLService` 与 dataset/evaluation/reporting 决策层必须通过 CLI 可达，配置与证据边界不得绕过。

#### Acceptance Criteria

3.1 新增 Click 命令组 `hos-ls ecatsl`，含四个子命令：`analyze`（对目标仓库执行 discovery → hypothesis → 静态适配器 → confirmation 链路，输出确认/未确认 findings 摘要）、`dataset`（从指定样本源构建 dataset release）、`evaluate`（对 release + 扫描结果执行评估）、`report`（产出 `Cost_Report`/优化报告）。每个子命令 `--help` 完整。

3.2 CLI 参数映射到 `ECATSLConfig` 校验（extra=forbid 语义保留）：非法值（越界 CWE/语言、非白名单 adapter、confirmatory provider 误配、brittle routes）导致 exit code 2 与明确错误消息，不得写入仓库状态。

3.3 `ecatsl analyze` 输出结构化 JSON 摘要（confirmed/unconfirmed 计数、发现的 finding 标识、telemetry 摘要），并保留全部工件落库（SQLite ECATSL 表），支持 `--json` 机器可读输出与人类可读表格双模式。

3.4 确认边界不变：CLI 不提供任何将 catalog/RAG/LLM/discovery 输出升级为 confirmation 的选项；`analyze` 的帮助文本显式声明"仅完整受支持静态路径可确认"。

3.5 失败隔离：`analyze` 对单文件的 discovery/适配器异常不得中断整体运行；终端失败以 `FAILED`/`UNAVAILABLE` 记录落库并在摘要中计数；进程 exit code 语义：0 = 完成（无论 findings 多少）、1 = 部分工件落库失败、2 = 用法/配置错误。

3.6 所有新 CLI 代码 flake8/mypy 干净，并纳入 Requirement 1.5 的 blocking 目录。

### Requirement 4: ECATSL 实战验证数据集（主题 C-2）

必须存在可复现的实战评估数据集与构建流程，样本带 ground truth，构建过程产出完整质量遥测。

#### Acceptance Criteria

4.1 `bench/datasets/ecatsl_eval/` 下产出 manifest（样本清单、来源、哈希、标签、project-time group、pair link），样本来自 VulnGym Python 生态子集与 SecureVibeBench/A.S.E 补充样本；manifest 含 `source_release`、构建时间、构建命令，可由同一命令幂等重放。

4.2 每个样本的 ground truth 标注（vulnerable/fixed-or-clean、CWE 映射、来源 CVE/GHSA 标识）可追溯到 `entries.jsonl` 原始行或上游 manifest 字段；VulnGym 的 `vuln_ids`（CVE/GHSA）在 manifest 中保留原值，CWE 映射允许"未映射"并计入质量报告。

4.3 `ecatsl dataset` 子命令（或等价 API）从 manifest 构建不可变 `Benchmark_Manifest` + `Data_Quality_Report`：哈希校验（FAILED 行排除并给原因）、等哈希规范化、重复身份保留、project-time group 防泄漏划分（9.1–9.11 全语义），构建过程幂等重放产出相同 JSON。

4.4 实战数据集规模：进入 release 的 Python 样本 ≥ 60 条（vulnerable 与 fixed-or-clean 配对计入）；不足 60 时，`Data_Quality_Report` 显式记录 `insufficient_samples` 并列出实际数量与补充计划——不虚增样本。

4.5 数据集构建不修改 `bench/datasets/VulnGym` 子模块内容；所有派生物写入 `bench/datasets/ecatsl_eval/` 或运行输出目录。

### Requirement 5: 第一份真实 ECATSL 评估（主题 C-3）

必须在实战数据集上端到端运行并产出真实的（非合成的）评估与成本工件。

#### Acceptance Criteria

5.1 在实战数据集上执行完整链路：release 构建 → 逐样本 `ecatsl analyze` → 结果回填为 verified classifications → `evaluate` → `report`；全程通过 `ECATSLService` 与既有决策层函数，不新造旁路评估逻辑。

5.2 产出并入库（工件 JSON 提交到 `bench/artifacts/ecatsl/<tag>/`）至少一份真实 `Evaluation_Report`、`Cost_Report`、`Data_Quality_Report`，含：全局与全部非空分层的 verified metrics（零包含）、分析时延、审计成本、LLM token/费用、tooling/LLM 失败计数、拒绝候选计数、排除样本原因分布。

5.3 报告不得包含未经证据支持的主张：无完成配对实验时零 superiority/optimization 语言，`missing_evidence` 标记完整（Req 8.4–8.6 语义在真实数据上成立）。

5.4 实战运行数据（样本数、失败分布、耗时、token）写入一份 `docs/ecatsl-run-report.md` 摘要文档，作为主题 D 可行性评估的输入。

5.5 端到端重放：同一输入重跑 `analyze` → `evaluate` 产出工件内容一致（幂等，时钟字段除外需由注入时钟保证）；重放不产生重复逻辑工件。

### Requirement 6: PureAI 分数卡整合（主题 D-1）

ECATSL 评估与既有 PureAI 分数卡必须能通过统一入口联合产出，共享标识与血缘。

#### Acceptance Criteria

6.1 `bench/` 新增统一入口（如 `python -m bench.run_evaluation --suite ecatsl --tag <tag>`）：一次运行对同一数据集产出（a）ECATSL 评估工件集、（b）可选的 PureAI 分数卡（`--with-pureai` 时）；两者共享 tag、manifest 身份与环境记录。

6.2 PureAI 分数卡流程复用现有 `bench/benchmark.py` 能力（不重写扫描逻辑）；其输出路径与格式不变，仅新增指向 ECATSL manifest 的交叉引用字段。

6.3 统一入口的输出目录结构文档化（`bench/README.md` 增补），含 ECATSL 工件与分数卡的对应关系说明。

6.4 联合运行不要求 PureAI API key（`--with-pureai` 缺省关闭）；ECATSL-only 模式零外部网络依赖（本地 SQLite 目录 + 本地样本）。

### Requirement 7: ECATSL 范围扩展可行性评估（主题 D-2）

必须产出证据化的范围扩展可行性评估文档，本循环不实现扩展本身。

#### Acceptance Criteria

7.1 产出 `docs/ecatsl-scope-expansion-assessment.md`，内容基于实证：VulnGym/SecureVibeBench 语言与 CWE 分布统计、`InputTracer`/`SastPrefilter` 对候选新语言/新 CWE 的能力差距清单、复用面盘点（哪些适配器可参数化、哪些需新写）、工作量量级估计（人日区间）与建议优先级排序。

7.2 评估报告区分"证据支持的结论"与"推测"，推测项显式标注；不使用 superiority 语言；不做实现承诺，结论为后续 spec 立项建议。

7.3 评估包含至少两个候选方向的量化对比（例如：新 CWE 映射（在既有 Python 范围内）vs 新语言支持），含每方向：可达样本量、复用面缺口、验证策略。

7.4 评估报告经用户确认后归档；若用户批准某方向，后续以独立 kiro spec 立项（本循环不阻塞）。

### Requirement 8: 全循环验证与收尾

#### Acceptance Criteria

8.1 全量 `pytest tests` 0 failed；ECATSL 单元+集成套件全绿且包含主题 C 的新增 CLI/数据集测试。

8.2 主题 A/B/C/D 各自的验收标准在 tasks.md 中逐条勾选并附执行记录（命令、结果、工件路径）。

8.3 新 spec 三件套与 `.config.kiro` 入库；本循环结束时工作树无未跟踪的规划产物。

8.4 循环收尾按仓库惯例执行：独立特性分支 → PR → merge commit 合并 → 本地 main 同步；tasks.md 的最终勾选与实现同 PR 提交。

8.5 不启动开发服务器或交互式 watcher；验证全部以非 watch 方式运行。

# Implementation Plan: ECATSL Operationalization and Bench Integration

## Overview

本计划实现规格 `9ecfe299-de3d-4d84-9dec-fcac6b4612a9`（上一循环规格 `b77c55d3-124c-48b4-9700-f4467cc7df0f` 已于 PR #63 全部完成并合并 main）。四个主题按依赖顺序推进：A 代码健康清零 → B CI 真实验证 → C ECATSL CLI 接入与实战验证 → D 分数卡整合与范围扩展评估。每主题独立可交付；主题 C/D 的实现严格复用 `src/ecatsl/` 既有决策层，不新增扫描器、导入器或旁路评估逻辑。

## Tasks

- [ ] 1. 主题 A：代码健康清零
  - [ ] 1.1 清零 `flake8 src`（当前 680 项）
    - 逐目录修复 F401/W291/W293/F841/E712/E402/W292/E501 等；只做导入清理、格式修正与死代码移除，不改运行时行为。
    - `ECATSL` 内 6 项已知 finding（`artifact_repository.py` F841、`candidate_ledger.py` F401、`confirmation.py` W292、`tooling_resolver.py` F401×2+W292）优先处理。
    - 每批修改后运行受影响模块的单元测试防止行为回归。
    - _Requirements: 1.1_
  - [x] 1.2 `mypy src` 收敛到显式白名单（当前 290 项）
    _Execution (2026-09-07): 环境 blocker 先行解决 — `[tool.mypy] python_version="3.10"` 在本机(mypy 1.20.0 + numpy 2.x stub)因 numpy stub 内 PEP 695 `type` 语句直接中止解析,stash 对照确认与本循环代码无关;经用户确认将口径提升为 3.12(实测 3.11 仍阻塞,3.12 完整跑通,与部署解释器 3.13 同代)。3.12 口径下新基线 = 258 项/107 文件(任务原文"290 项"为旧口径历史记录,已失效)。收敛结果:(a) `src/ecatsl` 29 项修复清零 — `artifact_repository.py` 20 项实质修复(`_expect` 移除多余 type-ignore、`_insert_or_verify` 删除死变量 `values`、duplicate-stage 分支补 `consolidation_failure_artifact_id is None` 防御校验)、`models.py` `model_copy`/`copy` 返回类型改为 `Self`(消除 `candidate_ledger` 2 项 Artifact/CandidateRecord 不再向上报)、`pipeline.py` `_execute` 补 `run is None` guard、`scanner.py` 清理 3 处失效 type-ignore;`compiler.py:99` 的 `INPUT_NOT_MAPPING` 防御分支属 Mapping 契约下对 mypy 不可达,删除会移除运行时防线(违反主题 A"不改运行时行为"约束),经 per-module override(disable_error_code=["unreachable"] + reason 注释)收敛,为白名单内唯一 ecatsl 条目;(b) 其余 229 项按"模块+错误码"建 per-module `disable_error_code` 白名单,共 47 个 override section,每条带 `# reason:` 注释;(c) 排查出 74 项仓库内 `import-not-found` 为孤儿子包/死文件引用(`src/nvd/db`、`plugins/builtin/skills` 等目录下被引用的模块从未入库或已丢),18 个引用文件全部 try/except-ImportError 降级 — 由原配置已有的 `ignore_missing_imports` 收敛,非错误码白名单;(d) `exclude` 的 multi_lang_mocks 正则改跨平台分隔符 `[\\/]`,Windows 下也生效;实测确认 mypy 1.20 对 excluded 后被 import 跟入的模块不应用 `disable_error_code`,需在对应 override 上用 `follow_imports="skip"` + `ignore_errors=true` 收敛(配置内已注记)。最终验证:`mypy src` → Success: no issues found in 344 source files(exit 0),白名单外 0 项;白名单 section 总数 47(不含第三方 yaml/requests/paramiko/aiofiles 的 ignore_errors 条目则 46 个错误码白名单;总计 48 个 [[tool.mypy.overrides]] 含 skip 条目)。回归:tests/unit/ecatsl(206 → 分组验证 229 passed)/tests/integration/ecatsl 43 passed/tests/unit/ecatsl/properties 52 passed,合计 0 failed。
    - 在 `pyproject.toml` `[tool.mypy]` 建 per-module overrides，每条带 `# reason:` 注释；优先清零 `src/ecatsl/`（29 项）与触及文件。
    - 白名单外 0 项；白名单总数记录在本任务执行记录中。
    - _Requirements: 1.2_
  - [x] 1.3 处置全部未跟踪杂项
    _Execution (2026-09-07): (a) 删除 3 项 — `_pr_body_44.md`、`_pr_body_46.md`（PR #44/#46 描述草稿，历史已随合并 commit 入库）、`evidence-constrained-taint-spec-learning.rar`（31KB 压缩包，spec 明文 `_spec/...` 本任务入库，压缩包冗余）；(b) 入库 7 项 — `_spec/evidence-constrained-taint-spec-learning/` 三件套(design/requirements) + `.config.kiro`(specId b77c55d3 历史档案,其 tasks.md 此前已在库) — Req 8.3 归档要求;`scripts/install_mcp_network_guard.py` + `scripts/mcp_network_guard_server.py` + `scripts/mcp_proxy_guard.sh` + `reasonix.toml` 原样入库(归属明确:`reasonix.toml` 的 `[session-bootstrap].proxy_guard` 直接引用 guard 脚本,是仓库级 MCP 自愈配置,未改任何内容);(c) 新增 `.gitignore` 2 条带原因注释 — `.reasonix/`(Reasonix 每会话任务遥测 events/snapshot,非源码)与 `.hypothesis/`(hypothesis 本地测试数据库,每次 pytest 重新生成,此前因默认全局 db 路径未被 `.gitignore` 覆盖而出现在 untracked);(d) 本循环 spec 目录 `_spec/ecatsl-operationalization-and-bench-integration/` 三件套+`.config.kiro` 一并 `git add`(Req 8.3"新 spec 三件套入库"对自身循环同样适用,收尾按 8.4 同 PR 提交)。验证:`git status --porcelain` untracked = 0。注:`.config.kiro` 在 Windows `ls -la` 下不可见但对 git 可见(POSIX 隐藏文件语义差异),两份 `.config.kiro` 均为 Kiro spec 工作流元数据 JSON,如实入库。
    - 删除：`_pr_body_44.md`、`_pr_body_46.md`、`evidence-constrained-taint-spec-learning.rar`。
    - 入库：`_spec/evidence-constrained-taint-spec-learning/` 三件套 + `.config.kiro`（历史档案）；`scripts/install_mcp_network_guard.py`、`scripts/mcp_network_guard_server.py`、`scripts/mcp_proxy_guard.sh`、`reasonix.toml`（归属明确后入库或 `.gitignore` 注明原因）。
    - 完成后 `git status` 无未跟踪的计划产物。
    - _Requirements: 1.3, 8.3_
  - [x] 1.4 主题 A 回归验证
    _Execution (2026-09-07): (a) 全量 `pytest tests`(非 watch)→ `--junitxml` 权威计数 tests=488 / failures=0 / errors=0 / skipped=28 / exit 0 — 与基线 460 passed / 28 skipped 完全一致(skip 只减不增达标,实际持平);skip 原因全为历史遗留(remote_scan 相对导入 ×7、模块未实现 ×17、Project path not found ×3、taint_analysis ×6 等聚合),无一新增;注:本机 pytest 终端 summary 行(“N passed”)持续缺失(RC=0、无 FAILED 标记、-rA 逐行计数正常),故按任务 1.2 执行记录建议改用 junitxml 签收;(b) `flake8 src --count` → 0 项(exit 0);(c) CI blocking 选择器 `flake8 --select=E9,F63,F7,F82 .` 全仓库 → 0 项(exit 0)。主题 A 四任务(1.1-1.4)全部完成。
    - 全量 `pytest tests`（非 watch）：0 failed（基线 460 passed / 28 skipped；skip 只减不增为合格）。
    - `flake8 src` 0 项；CI blocking 选择器 `E9,F63,F7,F82` 全仓库 0 项。
    - _Requirements: 1.1, 1.2, 1.4_

- [ ] 2. 主题 B：CI 真实验证
  - [ ] 2.1 改造 `.github/workflows/ci.yml`
    - pytest 步骤：`pytest --collect-only` → 真实执行 `pytest tests/unit/ecatsl tests/integration/ecatsl tests/unit/core -q`，失败即 blocking。
    - 新增独立 `full-tests` job 跑全量 `pytest tests -q`（非 blocking check，可见失败报告）。
    - flake8/mypy 步骤按 Req 1.5/1.2 分级：`src/ecatsl tests` blocking；`src` 其余 informational 但输出计数；mypy 白名单驱动且 `|| echo` 语义移除。
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 1.5_
  - [ ] 2.2 红-绿循环验证
    - 在真实 PR 上：临时注入一个必失败断言 → CI 红灯；还原 → 绿灯；记录两次 run 链接。
    - _Requirements: 2.5_
  - [ ] 2.3 CI 分级 lint 门禁固化
    - `src/ecatsl/`、`tests/` 目录 flake8 0 容忍 blocking；其余目录 informational + 计数输出的配置写入 ci.yml 并注明原因。
    - _Requirements: 1.5, 2.4_

- [ ] 3. 主题 C-1：ECATSL CLI 接入
  - [ ] 3.1 实现 `src/cli/commands/ecatsl_cmd.py` 命令组
    - `ecatsl analyze|dataset|evaluate|report` 四个子命令；`--config` 经 `ECATSLConfig` 校验，非法值 exit 2；确认边界文本写入帮助；不暴露任何绕过 `Path_Evidence` 门禁的选项。
    - exit code 语义 0/1/2；`analyze` 支持 `--json` 结构化摘要与人类可读表格；单文件失败隔离为终端记录。
    - 时钟经参数注入（生产默认真实时钟），保证批量运行幂等重放。
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  - [ ] 3.2 在 `src/cli/main.py` 注册命令组并补 CLI 单元测试
    - 注册保持 `scan` 现有加载顺序约定；新增 `tests/unit/ecatsl/test_ecatsl_cli.py` 覆盖：配置门禁拒绝矩阵、exit code、`--json` 摘要结构、失败隔离。
    - 新代码 flake8/mypy 干净（纳入 blocking 目录）。
    - _Requirements: 3.1, 3.2, 3.5, 3.6_
  - [ ] 3.3 写 Property P2（CLI 配置门禁封闭性）
    - `tests/unit/ecatsl/properties/test_property_p2_cli_gate.py`：>=100 例非法配置，断言 exit 2、零仓库写入、错误消息含违规字段。
    - 标签 `Feature: ecatsl-operationalization-and-bench-integration, Property P2`。
    - _Requirements: 3.2, 3.4_

- [ ] 4. 主题 C-2：实战评估数据集
  - [ ] 4.1 实现 `src/ecatsl/eval_dataset.py` 构建器
    - `build_manifest()` 确定性筛选规则（`repo_url`/`trace`/`project` 判定 Python 生态）并将规则写入 manifest；保留 CVE/GHSA 原值；CWE 未映射如实计数。
    - `emit_release()` 复用 `build_release()` 全语义（哈希校验/规范化/防泄漏划分）；注入时钟保证逐字节幂等重放。
    - _Requirements: 4.1, 4.2, 4.3, 4.5_
  - [ ] 4.2 产出 `bench/datasets/ecatsl_eval/` manifest 并确认样本量
    - 从 VulnGym 筛选 Python 子集；不足 60 配对样本时以 SecureVibeBench/A.S.E 补充并记 `source`；仍不足时 `insufficient_samples` 如实记录（不凑数）。
    - 子模块 `bench/datasets/VulnGym` 保持只读；`git status` 验证子模块未改动。
    - _Requirements: 4.1, 4.2, 4.4, 4.5_
  - [ ] 4.3 写 Property P1（数据集构建确定性）
    - `tests/unit/ecatsl/properties/test_property_p1_dataset_determinism.py`：>=100 例行序/重复/坏哈希扰动，断言输出行序无关、排除原因精确、`insufficient_samples` 语义正确。
    - 标签 `Feature: ecatsl-operationalization-and-bench-integration, Property P1`。
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [ ] 5. 主题 C-3：第一份真实评估
  - [ ] 5.1 实现 `src/ecatsl/eval_runner.py` 编排
    - 逐样本调用 `ECATSLService` 既有链路 → 回填 verified classifications → 复用 `build_evaluation_report()`/`build_cost_report()` 产工件；无新评估计算。
    - 工件 JSON 落 `bench/artifacts/ecatsl/<tag>/`；重放幂等（时钟字段由注入时钟固定）。
    - _Requirements: 5.1, 5.2, 5.5_
  - [ ] 5.2 执行实战运行并入库第一份真实工件
    - 全链路：dataset → analyze 批量 → evaluate → report；产出 `evaluation_report.json`、`cost_report.json`、`data_quality_report.json`、`summary.json` 提交入库。
    - 无完成实验时报告零 claim、`missing_evidence` 完整（Req 8.4–8.6 语义在真实数据上验证）。
    - _Requirements: 5.2, 5.3, 5.5_
  - [ ] 5.3 撰写 `docs/ecatsl-run-report.md` 运行摘要
    - 样本数、失败/排除分布、耗时、token、confirmed/unconfirmed 统计；作为主题 D 评估输入。
    - _Requirements: 5.4_
  - [ ] 5.4 写 Property P3（评估回填一致性）
    - `tests/unit/ecatsl/properties/test_property_p3_eval_runner_consistency.py`：>=100 例 classifications 扰动，断言 eval_runner 与 `build_evaluation_report()` 参考逐字段一致、无实验恒无 claim。
    - 标签 `Feature: ecatsl-operationalization-and-bench-integration, Property P3`。
    - _Requirements: 5.1, 5.3_

- [ ] 6. 主题 D：分数卡整合与范围扩展评估
  - [ ] 6.1 实现 `bench/run_evaluation.py` 统一评测入口
    - `--suite ecatsl --tag <tag>` 产 ECATSL 工件；`--with-pureai` 子进程复用 `bench/benchmark.py` 并在 `scorecard.json` 加 `ecatsl_manifest_id` 交叉引用；缺省零网络依赖。
    - _Requirements: 6.1, 6.2, 6.4_
  - [ ] 6.2 更新 `bench/README.md` 文档化统一入口
    - 目录结构、ECATSL 工件与分数卡对应关系、ECATSL-only 模式说明。
    - _Requirements: 6.3_
  - [ ] 6.3 撰写 `docs/ecatsl-scope-expansion-assessment.md` 范围扩展可行性评估
    - 基于实证：语言/CWE 分布统计、InputTracer/SastPrefilter 能力差距清单、复用面盘点、工作量量级（人日区间）、优先级排序；至少两个候选方向量化对比。
    - 区分证据结论与推测（推测标注）；零 superiority 语言；零实现承诺；经用户确认后归档。
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [ ] 7. 最终检查点 - 全循环验证与收尾
  - 全量 `pytest tests`（非 watch）0 failed；ECATSL 单元+集成含新增 CLI/数据集测试全绿；`flake8 src` 0；mypy 白名单外 0。
  - tasks.md 全部勾选并附执行记录（命令、结果、工件路径）；三件套 + `.config.kiro` 入库；工作树无未跟踪规划产物。
  - 按仓库惯例收尾：独立特性分支 → PR → merge commit 合并 → 本地 main 同步；不启动 dev server/watcher。
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

## Notes

- 上一循环（`b77c55d3`）的 29 项 pre-existing 债务与 6 项已知 flake8 finding 在本循环 1.1/1.2 优先清偿。
- VulnGym `entries.jsonl` 无 CWE 字段：数据集的 CWE 映射走"未映射如实计数"路线，杜绝从漏洞标题猜 CWE。
- Property 任务为 spec 工作流的可选自动化测试任务（`*` 标记规则与上一循环一致），核心实现任务永不可选。
- 每主题完成即触发一次主题级回归（受影响子集），不攒到最后检查点。

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.3"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["1.4"] },
    { "id": 3, "tasks": ["2.1"] },
    { "id": 4, "tasks": ["2.2", "2.3"] },
    { "id": 5, "tasks": ["3.1"] },
    { "id": 6, "tasks": ["3.2", "3.3"] },
    { "id": 7, "tasks": ["4.1"] },
    { "id": 8, "tasks": ["4.2", "4.3"] },
    { "id": 9, "tasks": ["5.1"] },
    { "id": 10, "tasks": ["5.2", "5.4"] },
    { "id": 11, "tasks": ["5.3"] },
    { "id": 12, "tasks": ["6.1"] },
    { "id": 13, "tasks": ["6.2", "6.3"] },
    { "id": 14, "tasks": ["7"] }
  ]
}
```

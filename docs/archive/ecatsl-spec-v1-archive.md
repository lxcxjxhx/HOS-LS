# v1 方案归档压缩（ECATSL 循环）

> 归档日期：2026-09-11。本文档是旧方案（两个 Kiro spec 三件套）的结论性摘要，
> 全量原文保留在 git 历史：`git show e52fc33b^:_spec/<spec-name>/tasks.md`。

## 归档范围

| Spec | 状态 | 证据锚点 |
| --- | --- | --- |
| `evidence-constrained-taint-spec-learning`（spec A） | 9/9 主题全部完成 | 归档 tasks.md 全勾；commits `1c45f776`→`7c5b6348` |
| `ecatsl-operationalization-and-bench-integration`（spec B） | 主题 A/B/C-1/C-2/C-3 完成；主题 D 未做 | `8247c315`…`932f2aee`；C-3 见 `c1288ee3` |

## 已达成事实（零推断，全部有工件或提交背书）

1. **ECATSL 核心系统**：确定性策略、候选 ledger、声明式编译、真实静态工具输出
   规范化、严格 PathEvidence 门禁、工具顺序与失败隔离（spec A 任务 1–5）。
2. **规模化管道**：目录摄取扩展、确定性发现、防泄漏评估/报告（spec A 任务 6–7）。
3. **代码健康与 CI**：`flake8 src` 清零（原 680 项）、mypy 白名单收敛、CI 真实
   测试执行 + 分级 lint 门禁、红-绿循环验证（spec B 主题 A/B）。
4. **CLI 与数据集**：`ecatsl` 命令组接入 CLI；`bench/datasets/ecatsl_eval/`
   manifest（75 样本，源 408 行，excluded_non_python=333）；P1/P2/P3 共 61 项
   property 测试（spec B 主题 C）。
5. **首次真实评估运行 `ecatsl-eval-v1`**：75 VulnGym v0.1.4 样本全链路重放幂等
   （三报告工件 sha256 逐字节一致）；0 CONFIRMED / 75 UNCONFIRMED，全部为空
   workdir 隔离（VulnGym 元数据仅 repo_url+commit，无本地代码副本）；零 claim
   声明验证通过。详见 `docs/ecatsl-run-report.md`。

## 未尽事项（去向：并入 v2 方案）

| 旧任务 | v2 去向 |
| --- | --- |
| 6.1 `bench/run_evaluation.py` 统一评测入口 | v2-P1 数据设施任务（如仍需统一入口） |
| 6.2 `bench/README.md` 文档化 | v2-P3 实验报告阶段随新基线体系一并更新 |
| 6.3 范围扩展可行性评估 | 被 v2-P0 止损实验与 P1 数据构造整体取代（导师 116 行意见） |
| 7 最终检查点（全量回归 + spec 文档入库） | 随 v2 各阶段检查点执行；spec 三件套不再入库（沿用 `e52fc33b` 决策，规划文档仅存 git 历史 + 归档摘要） |

## 关键教训（供 v2 引用）

- **评估上限由数据可得性决定**：VulnGym 元数据不含本地代码，analyze 阶段 0 执行。
  v2 的数据主线必须自带可执行工作区（SecureVibeBench/A.S.E 完整仓库快照）。
- **9/9 与 Semgrep≈0 只能作早期信号**，不支撑论文结论（导师意见原话）。
- 幂等重放（固定注入时钟）+ 零 claim 纪律 + 失败隔离语义是本轮验证过的
  工程资产，v2 直接继承。

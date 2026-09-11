# ECATSL 首次实战评估运行摘要（ecatsl-eval-v1）

> 任务 5.3（主题 C-3），Req 5.4。本文档是主题 D（分数卡整合与范围扩展评估，
> 任务 6.1–6.3）的实证输入。所有数字来自
> `bench/artifacts/ecatsl/ecatsl-eval-v1/` 的真实工件，零合成、零推断。

## 运行身份

| 项 | 值 |
| --- | --- |
| tag | `ecatsl-eval-v1` |
| 数据集 manifest | `bench/datasets/ecatsl_eval/manifest.json`（75 entries） |
| 上游数据源 | VulnGym v0.1.4（submodule `cd69f7e`，`data/entries.jsonl`） |
| manifest built_at | 2026-09-08T00:00:00+00:00（任务 4.2 固定注入时钟） |
| 运行时钟 | 2026-09-10T00:00:00+00:00（固定注入，保证 Req 5.5 重放幂等） |
| runner 版本 | `RUNNER_VERSION = "1"` |
| 编排入口 | `src/ecatsl/eval_runner.py::run_evaluation` |
| 链路 | dataset（`emit_release`，复用 `build_release` 全语义）→ 逐样本 `ECATSLService.analyze` → verified 回填 → `build_evaluation_report` → `build_cost_report` → JSON 工件 |

## 入库工件（`bench/artifacts/ecatsl/ecatsl-eval-v1/`）

| 工件 | 内容锚点 |
| --- | --- |
| `evaluation_report.json` | 文件 sha256 `ccc56187cce1b3a3…`；`artifact_id`/`content_hash` = `sha256:c33ea4e2…`（规范化内容寻址，与落盘缩进格式无关） |
| `cost_report.json` | 文件 sha256 `3f3e25a61d5e1167…` |
| `data_quality_report.json` | 文件 sha256 `9e937e3b61048a1c…` |
| `summary.json` | 运行观察汇总（本运行记录，非 Req 5.2 三工件之一） |

三个报告工件在固定时钟 + 固定 telemetry latency 下重放逐字节一致（Req 5.5
已验证：两次运行的 sha256 完全相同）；真实墙钟时延只记录在
`summary.json.measured_latency_seconds`，从不进入报告工件本身。

## 样本量与分布

- **总样本：75**（全部 `sample_class=vulnerable`；VulnGym 行均为 verified
  findings，标签固定 `vulnerable`，无负样本）
- **实际进入 analyze 链路的样本：0**
- **隔离样本：75**（`isolated_samples` 全量记录于 `summary.json`）

隔离原因（运行事实，非推测）：`ecatsl_eval` manifest 的 `workdir` 字段全部为
空 —— VulnGym `data/entries.jsonl` 源行只携带 `repo_url` + `commit` 等
元数据，不携带可分析的本地代码副本。不克隆上游 15 个仓库就无法执行
`ECATSLService.analyze`；本运行未做任何克隆。每个空 workdir 样本按 Req 3.5
失败隔离语义处理：跳过 analyze 链路、记 1 次 per-sample tooling failure
（`tooling_failures:<sample_id>`）、分类保持 UNCONFIRMED（无 Path_Evidence
则 CONFIRMED 不可达），绝不静默丢弃。

项目分层（`stratum:project=*`，共 14 个项目 + 1 个样本类分层）：

| 项目 | 样本数 | | 项目 | 样本数 |
| --- | --- | --- | --- | --- |
| NeMo | 22 | | fastmcp | 6 |
| langflow | 12 | | adk-python | 6 |
| mlflow | 9 | | airflow | 5 |
| open-webui | 4 | | langchain | 3 |
| AutoGPT | 2 | | n8n | 2 |
| onnx | 2 | | litellm | 1 |
| nltk | 1 | | （合计 75） | |

## confirmed / unconfirmed 统计

| 状态 | 数量 | 说明 |
| --- | --- | --- |
| CONFIRMED | 0 | 无样本进入 analyze，无 Path_Evidence 产生 |
| UNCONFIRMED | 75 | 全部为隔离样本的如实回填（不是预测失败） |

混淆矩阵（零包含）：tp=0, fp=0, fn=75, tn=0 → precision=0.0, recall=0.0,
f1=0.0。这些是"零完成实验下的零包含计数"，不是性能结论。

## 失败 / 排除分布

- **tooling failures：75**（每隔离样本 1 次；`counts` 中
  `tooling_failures:<sample_id>` 全量可审计）
- **llm_failures：0**（本链路无 LLM 阶段）
- **rejected_candidates：0**（本链路不产生新拒绝计算）
- **数据集层面排除**（任务 4.2 记录，工件 `data_quality_report.json`）：
  excluded_non_python=333（源 408 行 − 入选 75）、duplicate=0、invalid=0、
  retained_count=75 ≥ MINIMUM_PAIRED_SAMPLES=60（无 insufficient_samples 标记）

## 耗时与 token

| 项 | 值 |
| --- | --- |
| telemetry.latency_seconds | 0.0（固定值，保证重放幂等） |
| 实测墙钟（本次运行观察） | ≈0.0001 s（75 样本全部走隔离分支，无 analyze 开销） |
| llm_tokens | 0 |
| llm_monetary_cost | 0.0 |
| audit_monetary_cost | 0.0 |

OperationalComplexity：configured_adapters=2（InputTracerAdapter +
CodeQLSastAdapter，与 CLI `_wired_service` 同一装配）、pipeline_stages=1、
external_service_dependencies=0、manual_execution_steps=0。

## 零 claim 声明（Req 5.3，已在真实数据上验证）

- 三报告工件（evaluation/cost/data_quality）经 token 扫描（superior/
  outperform/optimiz/better than/improv）全部为零命中；无任何
  superiority/optimization 语言。
- `evidence_limitations` 完整（2 条，由 `evidence_limitations_for` 从运行
  事实推导，写入 `evaluation_report.json`）：
  1. no analysis performed for 75 sample(s) with a blank workdir (no local
     repository): isolated per Req 3.5, classification UNCONFIRMED, one
     tooling failure each
  2. zero samples analyzed -> zero completed experiments; all metrics are
     zero-inclusive counts, not comparison results
- `missing_evidence` 语义（Req 8.4–8.6）：无完成配对实验 → 无 claim →
  measured difference 仅以零包含计数呈现。

## 对主题 D 的输入结论（证据边界内的观察）

1. **工件管道已打通且幂等**：dataset → analyze → evaluate → report 全链路
   可重放（三报告工件 sha256 稳定），第一份真实工件已入库。
2. **当前评估的上限由数据可得性决定，而非由决策层决定**：VulnGym 元数据
   （repo_url+commit）不含本地代码，analyze 阶段 0 执行。主题 D 若要得到
   非零 verified metrics，需要先解决样本工作区供给（克隆 15 个上游仓库到
   指定 commit 或接入含 patch 复现的数据源）。
3. **规模参考**：75 样本分布在 14 个 Python 项目上，最大层 NeMo 22、
   langflow 12；若全部可分析，按单样本 analyze 成本线性外推即可估计
   全量运行耗时/token 预算（当前单样本成本基线尚未建立，需下一次有
   analyze 的运行实测）。

## 复现方式

```bash
# 链路（时钟注入；固定时钟下三报告工件逐字节一致）
python -c "from src.ecatsl.eval_runner import run_evaluation; \
run_evaluation('bench/datasets/ecatsl_eval/manifest.json', \
'bench/artifacts/ecatsl', tag='ecatsl-eval-v1', \
clock=lambda: __import__('datetime').datetime(2026,9,10,tzinfo=__import__('datetime').timezone.utc), \
latency_seconds=0.0)"
```

相关测试：`tests/unit/ecatsl/properties/test_property_p3_eval_runner_consistency.py`
（P3：runner 与 `build_evaluation_report` 参考逐字段一致、无完成实验恒无
claim、空 workdir 隔离真实性，4 组 hypothesis property 各 100 例）。

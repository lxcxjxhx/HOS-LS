# bench/p0/ground_truth/ — Ground Truth 订装（W1*）

按 P0 方案 §3.1 与 §6 W1* 组织。每个漏洞案例一份 `GT-<sample_id>.md`，
从 `TEMPLATE.md` 拷贝填写；人工复核按 `REVIEW-CHECKLIST.md` 双签执行。

## 约定

- 字段风格沿用 v1 `BenchmarkSample`（`sample_id`/`classification`/
  `project_id`/`project_time_group`/`content_hash`/`pair_id`），
  按 §6 只新增 `introducing_hunk` / `pov_ref` 两字段；
  P0 订装文件不进入 v1 manifest 流水线（§6 禁止条款 2）。
- `vic` 由 SecureVibeBench 提供，是核验过的引入 commit——
  ground truth 订装以它为锚点，不重新做 B-SZZ。
- 三场景标签与配额见方案 §3.2；控制样本（非引入）也按模板订装，
  `classification` 留空并在 `vuln_mechanism` 标注控制类型
  （纯重构 / 仅安全修改 / 旧漏洞持续）。
- 复核不通过的案例进排除清单，原因必填（§3.2 选取规则）。

## 当前状态

- 样本初选清单：`bench/p0/candidates.csv`（105 行全量，
  `candidates.csv` 由 `sample_select.py check` 生成）。
- CWE 映射：数据集不提供，`sample_select.py::LOCALID_TO_CWE`
  逐条人工核实后补全（当前仅 1 条示例，其余 UNKNOWN_CWE）。
- 环境前提：PoV 复跑（核对项 4/5）依赖 docker（W1 待装），
  就绪前可先完成 1/2/3/6/7/8/9/10 项静态核对。

# P0 止损实验完整方案（DCAV 前置）

> 起草：2026-09-11。从属于 `docs/research-plan-v2-dcav.md`（v2 方案）第 5 节 P0，
> 本文是其可执行展开。数据面决策：**Docker + SecureVibeBench C/C++ 主力路线**
> （用户确认，decision_id: dec-030c2031bb7e03a8）。
> 目标读者：本人 + 导师 Jiahong。

## 0. 定位与导师意见覆盖对照

P0 只做一件事：用最小成本回答"这个课题该不该继续做、以什么形态做"。
本文不展开 P1–P4；凡 v2 方案已定义且 P0 不需要的，一律引用不重复。

导师意见（两轮评语合并口径）逐条去向：

| # | 意见要点 | 去向 |
| --- | --- | --- |
| 1 | 主问题收紧为可归因、可证伪验证 | v2 §1（已吸收）；P0 按此口径执行 |
| 2 | DEP 升级为核心机制、SAL 降为候选缩小 | v2 §1；P0 原型用简化版，见 §6 |
| 3 | 修复有效 ≠ 引入原因正确，双通道拆分 | v2 §1 边界 + §4 指标；P0 双通道都记 |
| 4 | Pair-Correct 不作唯一主指标 | v2 §4；P0 指标表不设 Pair-Correct 主位 |
| 5 | 跨版本机制对齐（告警不变但新增路径） | v2 §1 焦点场景③ + P0 场景映射 §3.2 |
| 6 | 保持功能的反事实归因（最建议方向） | v2 §1 DEP 定义；P0 必测功能保持 |
| 7 | AI 生成代码切入：契约违背/不完整修改三场景 | P0 §3.2 场景定义（本方案展开） |
| 8 | 10–15 案例止损实验、三方对比、逐案例记录 | 本方案主体 |
| 9 | 普通 agent 已能稳定完成则收窄课题 | P0 §7 Go/No-Go 收窄条款 |
| 10 | 9/9 与 Semgrep≈0 只作早期信号 | P0 报告零 superiority 语言（继承 v1 纪律） |
| 11 | SecureVibeBench/A.S.E 主线、VulnGym 副线、口径修正 | v2 §2；P0 用 SecureVibeBench（§1 事实修正） |
| 12 | 七类基线、SAL/DEP/消融、定位消融 | v2 §3；P0 只装基线 1/2/6 的最小版（§4） |
| 13 | 误归因风险（旧漏洞持续/重构/安全修改） | v2 §7；P0 ground truth 订装含"非引入"对照样本 |
| 14 | TrapEval：勿依赖表面模式 | P0 指标含误归因率；评估集含控制样本 |
| 15 | VulnGym 408/184/23 口径、"38 框架"定义 | v2 §2 已固定；P0 不涉 VulnGym |

## 1. 背景事实与数据面

**SecureVibeBench 事实修正**（相对 v2 方案 §2 的粗写，以此为准）：
- 105 个 **C/C++** 任务，源自 41 个 OSS-Fuzz 项目（不是 Web 漏洞任务集）；
- 构造链：ARVO 4,993 实例 → B-SZZ 缩候选 → PoV 动态验证三条件
  （fix 后安全 / 候选 commit 可触发 / 父 commit 安全）→ 254 → 人工筛选 105；
- 数据字段：`localid`、`repo_url`、**`vic`（vulnerability-inducing commit）**、
  `repo_cwd`、`description`（安全中性任务描述）；
- 官方四分类：IC（错误）/ C-VUL（正确但含已知漏洞）/ C-SUS（正确但 SAST
  标记新风险）/ C-SEC（正确且安全）；Oracle = 功能测试 + PoV + SAST；
- 获取：HuggingFace `iCSawyer/SecureVibeBench` + GitHub `iCSawyer/SecureVibeBench`。
- 字段核实注记（2026-09-12 本机实测）：`datasets-server.huggingface.co` 可直连，
  `/first-rows` 返回 5 字段名与上完全一致，`/size` 确认 105 行 × 5 列；
  注意 `localid`（ARVO id）**不标注 CWE**——CWE 需 W1 人工核实映射
  （`bench/p0/sample_select.py` 内映射表逐条补全），报告按方案 §1 声明子集口径。

**对本课题的两个直接利好**：
1. `vic` 就是人工核验过的引入 commit → P0 的 ground truth 天然存在，
   订装成本远低于预估；
2. 官方 C-VUL 分类 = "agent 修好了功能但没修漏洞" = 我们要的 **AI 生成
   vulnerable patch 现成来源**（无需自己跑 agent 也能构造 R_after），自跑
   agent 补充多样性。

**环境前提**：ARVO 镜像构建与 PoV 动态验证依赖容器。本机当前无 docker，
**W1 第一件事是装 Docker Desktop**（用户已确认装）。就绪前只能做静态
准备任务（§6 W1 中标注 * 的）。

**C/C++ 对工具链的影响**：v1 静态适配以 Python 生态为主 → P0 静态臂改用
**CodeQL（C/C++ 完整支持）+ Semgrep（C/C++ 规则子集）**，报告时声明子集
口径（与导师意见"按支持语言分子集比较"一致）。

## 2. 研究假设（可证伪）

- **H1（存在性）**：在 ≥2 个焦点场景上，通用 agent + 测试 + 双版本静态扫描
  均无法稳定完成"新增漏洞路径判定 + 责任修改定位"。
- **H2（可归因性）**：依赖约束下的差分反事实干预（DCAV 原型）能在 ≥5/15
  案例上给出经干预验证的正确归因，且反事实保持功能。
- **H3（机制必要性）**：DEP 干预提供的归因证据，在错误率或成本上严格优于
  纯测试反馈与纯回退（P0 只做方向性观察，显著性检验留给 P3）。

## 3. 样本集构造（15 案例）

### 3.1 来源与配额

| 层 | 数量 | 来源 |
| --- | --- | --- |
| SecureVibeBench VIC 案例 | 9 | HF 数据集，按 §3.2 场景映射各 3 |
| 自跑 agent patch 案例 | 3 | 2 个 backbone 在 SecureVibeBench 任务上产出，取 C-VUL/C-SUS 落点 |
| 控制样本（非引入） | 3 | 纯重构 / 仅安全修改 / 旧漏洞持续存在（防误归因，对应 TrapEval 教训） |

每个漏洞案例的 ground truth 订装（利用 `vic` 与 PoV 现成产物）：
`{R_before@vic^, R_after@vic, task description, 引入 hunk（B-SZZ+PoV 已核验）,
PoV 程序, 修复 commit 引用, 漏洞机制一句话}`。人工复核每条订阅
（预计 0.5–1 人日/案例，共约 2 周内穿插完成）。

### 3.2 三焦点场景的 C/C++ 映射

| 场景 | Web 语义（v2 §1） | C/C++ 对应形态 | SecureVibeBench 预期来源 |
| --- | --- | --- | --- |
| ① 权限/边界作用域错误 | 新增未鉴权路径 | 新增调用点绕过既有 bounds check / 长度校验只在主入口 | C-VUL 与 IC 案例中的溢出类 |
| ② 遗漏 sibling path | 改一处漏兄弟处 | 同一结构体的多个使用点只修了一个（如多处 memcpy 同模式） | 多调用点漏洞（OSS-Fuzz 常见） |
| ③ 不完整修改 | 主路径修了异常路径没修 | 主流程加了校验，错误处理/清理路径仍可触发 | 释放后使用/双重释放类 |

选取规则：场景配额优先；同 CWE 最多 3 个；单仓库最多 2 个；
排除需要 GPU/特殊外设的构建。落选案例记入排除清单（原因必填）。

## 4. 三方对比设计（每案例全跑）

| 臂 | 配置 | 预算 |
| --- | --- | --- |
| A：静态双版本 | CodeQL + Semgrep 分别扫 before/after，告警对齐（新增/消失/持续三态） | 无人力，固定配置 |
| B：裸 agent | 同 backbone（选 1 个主力 LLM），三档递进：仅 diff → +仓库探索 → +测试执行（PoV 作触发输入）；agent 可运行构建与测试，**不给 vic/修复信息** | 每案例每档 ≤ 同一 token 上限，全记录 |
| C：DCAV 原型 | 复用 SAL 思想缩候选（依赖图 + diff 变更点）+ **简化 DEP**：人工指导的干预集生成，逐干预跑 PoV + 功能测试 | 干预次数每案例 ≤ 6，记录每次结果 |

流程统一走五步：`对齐双版本 → 生成候选假设（含"非新增"候选）→ 干预/验证
→ 归因输出（定位 hunk + 机制 + 证据链）→ 仲裁`。
仲裁：PoV 动态结果 + 人工核验 ground truth 双签，分歧案例留档。

## 5. 度量与 Go/No-Go

每案例每臂记录：漏洞判定三值（NEW_VULN / NO_NEW_VULN / INCONCLUSIVE）、
责任 hunk 定位命中、机制解释正确性、反事实有效性（攻击消失 **且**
功能保持，双通道分开记）、成本（token、干预次数、墙钟）、误报类型
（旧漏洞误判为新增 / 重构误判 / 安全修改误判）。

**Go**（同时满足）：B 臂在 ≥2 个场景反复失败（定位或机制错），且 C 臂
≥5/15 案例归因正确且反事实有效，且 C 臂优势不能被 A 臂告警对齐解释。
**收窄**：B 臂三档均稳定正确 → 课题转向 agent 失败模式研究或换更难场景
（跨版本机制对齐类）。
**No-Go**：C 臂原型 <3/15 或干预在 >半数案例破坏功能 → 回问题定义层重议。

## 6. 工程任务分解与资产复用映射（防重复实现）

**先决结论：旧主线 `src/ai/pure_ai/`、`src/diff/`、`dynamic_code/`、
`bench/run_comparison.py` 已有一批与本课题直接对应的实现**（此前盘点只覆盖
`src/ecatsl/`，本节修订补全）。逐项核验结果：

| 已有资产 | 现状 | P0 去向 |
| --- | --- | --- |
| `src/ai/pure_ai/diff_analysis_agent.py`（261 行，含单测） | diff → 新增/删除风险路径分析，docstring 即 v2 主问题口径 | **直接承接**为 C 臂候选假设生成器，加 C/C++ 前端 |
| `src/ai/pure_ai/contract_violation_agent.py` | 三焦点场景（权限作用域/sibling path/异常路径）AST 检测，Python 面 | **承接场景定义与检测逻辑**；C/C++ 面改用 CodeQL 查询实现同语义 |
| `src/ai/pure_ai/counterfactual_agent.py`（361 行） | 反事实**构造器**（片段级模板+LLM 加安全措施）+ 规则验证 | **承接构造思想**；P0 的系统级干预执行器（打补丁→构建→PoV→功能测试→还原）仍新建，二者是构造/执行两层，不重复 |
| `src/ai/pure_ai/evidence_chain.py` + `schema.py` 信号体系 | 多 agent 证据链追踪 | C 臂证据包输出**承接**其结构 |
| `src/ai/pure_ai/multi_agent_pipeline.py` + agent_0..6 + `src/ai/client.py` | Python 任务多 agent 流水线 + LLM 客户端装配 | B 臂 harness **承接**此装配，不引入新客户端 |
| `bench/run_comparison.py`（34KB） | VulnGym 样本上 Semgrep+CodeQL+HOS-LS 对比框架 | A 臂双版本扫描**承接**其运行骨架，加 before/after 双轮与三态对齐 |
| `dynamic_code/`（PoC 模板 + Web validators） | requests 面向的 Web 缺陷动态验证 | C/C++ 路线**不适用**（不硬改）；自跑 agent patch 的 Python/Web 补位线可用 |
| `src/analyzers/exploit_generator.py`（1133 行） | PoC/payload 生成（对标 SAST-Genius） | P0 **不用**（PoV 由 ARVO 现成提供）；P1+ 视需要评估 |
| `src/diff/`（壳模块，sink_validators 为空） | 仅有模块 docstring | P0 不动；若 C 臂承接后需要落位，挂到该模块下，不另起炉灶 |

**原则：全部资产只复用/承接/薄改造，不重写。** 下表逐周标注去向；
标 * 的任务不依赖 docker，可立即开始。

| 周次 | 任务 | 资产去向 |
| --- | --- | --- |
| W1 | *装 Docker Desktop + 验证 ARVO 镜像拉起（1 个试点案例） | 新建环境，一次性 |
| W1 | *样本初选脚本：HF 数据集加载 → 按 §3.2 规则过滤 → 候选清单 CSV | 新建 `bench/p0/sample_select.py`（独立小脚本，不复用 eval_dataset.py） |
| W1 | *ground truth 订装模板 + 人工复核表 | 新建 `bench/p0/ground_truth/`（schema 沿用 v1 `BenchmarkSample` 字段风格，只加 `introducing_hunk`/`pov_ref` 两字段） |
| W2 | A 臂：双版本扫描 + 告警三态对齐器 | **承接** `bench/run_comparison.py` 运行骨架 + **薄改造** `src/ecatsl/static_adapters.py` 规范化契约（COMPLETE_PATH 语义保留）；**不改** `eval_runner.py` |
| W2 | B 臂：agent 运行 harness（构建/测试/PoV 执行封装） | **承接** `src/ai/pure_ai/multi_agent_pipeline.py` 装配 + `src/ai/client.py`，只新建容器/构建/PoV 执行封装 `bench/p0/agent_harness.py` |
| W3 | C 臂：候选缩小（依赖图 + diff 交点） | **承接** `diff_analysis_agent.py`（候选生成）+ `contract_violation_agent.py`（场景语义）+ **复用** `candidate_ledger.py`（`CandidateRecord`/`CandidateHypothesis` 记录结构） |
| W3 | C 臂：干预执行器（打补丁→构建→PoV→功能测试→还原） | 新建 `bench/p0/counterfactual.py`（执行层）；反事实**构造**承接 `counterfactual_agent.py` 的 `CounterfactualConstructor`；**复用** v1 失败隔离语义（Req 3.5）与零 claim 纪律 |
| W3 | PathEvidence 门禁接入 C 臂结论输出 | **原样复用** `static_validation.py` + `confirmation.py` 的严格门禁（CONFIRMED 必须有完整路径证据）；证据包结构承接 `evidence_chain.py` |
| W4 | 逐案例结果表 + 仲裁 + P0 报告 `docs/p0-kill-report.md` | 报告模板沿用 v1 `docs/ecatsl-run-report.md` 的"运行事实/零 claim/证据边界"结构 |

**明确禁止的重复实现**（写死，防止顺手重造）：
1. 不重写评估/报告框架——P0 只出逐案例表 + 报告，`build_evaluation_report`
   体系留到 P1 改造四元组格式后再接；
2. 不重复实现 dataset manifest 流水线——P0 用轻量 CSV + 订装文件，
   `eval_dataset.py`/`dataset_release.py` 不动；
3. 不重写 CLI——P0 不加新命令，全部 `python -m bench.p0.*` 直跑；
4. 不引入新的 LLM 客户端、不重写多 agent 流水线——B 臂直接承接
   `src/ai/pure_ai` 的 `multi_agent_pipeline.py` + `src/ai/client.py` 装配；
5. 不动 `eval_runner.py`/`ecatsl_eval` manifest——那是 v1 已验证资产，
   P1 才按四元组格式改造；
6. 不重写 diff 分析/契约违背检测/反事实构造——分别承接
   `diff_analysis_agent.py`/`contract_violation_agent.py`/
   `counterfactual_agent.py`，只补 C/C++ 前端；
7. 不为 C/C++ 硬改 `dynamic_code/`——其 validators 是 Web/requests 语义；
   C/C++ PoV 用 ARVO 现成程序，`dynamic_code/` 仅服务 Python/Web 补位线。

旧主线组件的完整设计意图与去向总表见
`docs/archive/legacy-lines-archive.md` §2.3。

### 6A. 三臂承接组件完整设计

**统一约定**：所有承接不改被复用模块的既有函数签名；适配代码全部落在
`bench/p0/` 内，以 wrapper/adapter 形式存在；旧模块如需 C/C++ 分支，
用新增参数/新类而非修改原逻辑。

#### 6A.1 A 臂：双版本静态对齐器（`bench/p0/static_differential.py`）

- 承接：`bench/run_comparison.py` 的工具调用骨架（Semgrep/CodeQL 装配与
  输出解析）+ `src/ecatsl/static_adapters.py` 的 `NormalizationOutcome`
  七态契约（只消费，不修改）。
- 输入：`{case_id, repo_url, vic, workdir_before, workdir_after}`；
  工作区用 `git worktree`（vic^ 与 vic 两个挂载点）供给，共享 `.git`，
  不重复克隆。
- 处理：对两个 worktree 各跑一次同配置扫描 → 告警规范化为
  `(cwe, rule_id, file, sink_symbol)` 元组 → 跨版本对齐键取
  `sink_symbol + cwe`（行号会漂移，不作对齐键）→ 三态判定：
  `NEW`（after 有、before 无）/ `GONE` / `PERSISTENT`（两侧都有）。
- 输出：`alert_alignment.json`（逐案例 + 逐告警三态）；`PERSISTENT`
  单列——"告警数不变但新增路径"场景的量化基础（导师意见 #5）。
- 边界：CodeQL 需编译数据库，C/C++ 构建失败的案例记 `BUILD_FAILURE`
  并保留 Semgrep 单工具结果（子集口径如实声明）。

#### 6A.2 B 臂：agent harness（`bench/p0/agent_harness.py`）

- 承接：`src/ai/pure_ai/multi_agent_pipeline.py::run_pipeline` 装配
  （agent_0..6 + `src/ai/client.py` LLM 客户端 + `cost_tracker.py` 计费 +
  `checkpoint_manager.py` 断点）；`DiffParser.parse` 作为"仅 diff"档
  的前置输入器。
- 三档配置（同 backbone、同 token 上限）：
  | 档 | 输入 | 工具面 |
  | --- | --- | --- |
  | B1 | task description + Δ（diff 文本） | 无 |
  | B2 | B1 + worktree 只读访问 | grep/read 类 |
  | B3 | B2 + 容器内构建/测试/PoV 执行 | build/test/run |
- 输出对齐 v2 口径：三值判定 + 责任 hunk + 机制解释，写入
  `results/{case_id}/arm_b{1,2,3}.json`；`SignalState`/`Verdict`
  枚举沿用 `pure_ai/schema.py`，不新建状态枚举。
- 关键约束：**不给 vic/修复信息**（prompt 与 worktree 双保险：
  worktree 只 checkout 到 vic，不暴露 fix commit）；每档每案例
  独立 checkpoint，可重放。

#### 6A.3 C 臂：候选缩小 + 干预执行器

**C1 候选缩小**（`bench/p0/candidate_narrow.py`）：
- 承接 `DiffParser.parse → RiskPath`（变更点提取）→ 映射到 v1
  `candidate_ledger.py` 的 `CandidateRecord`/`CandidateHypothesis`
  记录结构（复用其 `CandidateState` 状态机与内容寻址 id）；
- 规则：变更 hunk ∩（CodeQL call graph 反向可达 sink）构成候选
  假设集；三场景判定（`contract_violation_agent.py` 语义，C/C++ 面
  走 6A.4 查询）作为假设加分项；必含"非新增"对照假设
  （旧漏洞持续/纯重构），防误归因。

**C2 干预执行器**（`bench/p0/counterfactual.py`，唯一的大新建件）：
- 构造层承接：`counterfactual_agent.py::CounterfactualConstructor`
  生成安全反事实片段（模板 + LLM 兜底，接口不动）；
- 执行层新建，状态机（每案例 ≤6 干预，逐步记录）：

  ```
  PLAN(按候选假设生成干预集)
   → APPLY(git apply 到 worktree_after 副本)
   → BUILD(容器内构建; 失败→INTERVENTION_INFEASIBLE, 回退)
   → POVRUN(PoV 执行; ATTACK_GONE / ATTACK_PERSISTS)
   → FUNCHECK(功能测试; PASS/FAIL)
   → UPDATE(假设淘汰/确认; 置信度更新) → PLAN' 或 CONCLUDE
  ```

- 双通道输出（导师意见 #3 落地）：修复有效性 = `ATTACK_GONE`；
  引入原因正确性 = `ATTACK_GONE ∧ FUNCHECK=PASS ∧ before 版本同
  PoV 也触发`。二者分开记录，绝不合并成单一布尔。
- 失败隔离：APPLY/BUILD/POVRUN 任何异常按 v1 Req 3.5 语义隔离该
  干预，不污染其他干预与其他案例。

#### 6A.4 C/C++ 前端（CodeQL 查询包，`bench/p0/codeql_cpp/`）

- 目的：把 `contract_violation_agent.py` 三场景语义用 CodeQL C/C++
  查询等价实现（bounds-check 绕过新增调用点 / 同模式多调用点漏改 /
  错误处理路径仍可达 sink），替代 Python AST。
- 复用：`envs/codeql-packs/` 既有 pack 组织方式；查询输出经
  `static_adapters.py` 的 `COMPLETE_PATH` 规范化进入 PathEvidence
  （门禁语义零改动）。
- 规模控制：P0 只写 3 个查询（每场景 1 个），不求通用。

#### 6A.5 结果表与仲裁（W4）

- 逐案例行 = 15 案例 × {A/B1/B2/B3/C} 五列 × §5 指标字段；汇总表
  自动生成（`bench/p0/tabulate.py`），不引入报告框架。
- 仲裁材料：`results/{case_id}/adjudication.md`——PoV 动态结果 +
  ground truth 对照 + 分歧说明；Go/No-Go 按 §5 门槛逐项打勾。
- 报告：`docs/p0-kill-report.md`，结构沿用
  `docs/ecatsl-run-report.md`（运行事实 / 零 claim / 证据边界）。

## 7. 风险与预案

| 风险 | 触发信号 | 预案 |
| --- | --- | --- |
| ARVO 镜像不可用/构建失败率高 | W1 试点 <3/5 案例拉起 | 转 §3.1 自跑 agent patch 主导 + 纯静态 C/C++ 分析，PoV 改人工构造输入 |
| SecureVibeBench 场景配额填不满 | 某场景 <3 例 | 允许跨场景借调 + A.S.E/自收集补位，缺口写进报告 |
| C/C++ 依赖图工具缺失 | C 臂候选缩小失效 | 降级为 CodeQL call graph + 编译数据库，牺牲精度换可用 |
| B 臂过强 | 触发 §5 收窄条款 | 如约收窄，不恋战 |
| PoV 在 after 版本失效（环境漂移） | 复跑失败 | 以 fix 前最后可触发 commit 重订装，记录偏差 |

## 8. 产出物清单

`bench/p0/`（sample_select.py、ground_truth/、agent_harness.py、
counterfactual.py、results/）+ `docs/p0-kill-report.md`（含 Go/No-Go 判定、
逐案例表、失败模式分类、给 P1 的实证输入）。零 superiority 语言；
所有数字可从 results/ 工件重放核对（固定时钟重放纪律沿用）。

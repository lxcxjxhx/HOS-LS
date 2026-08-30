## v0.3.4.0 — Agent 架构重构

### 核心变更

| Agent | 变更前 | 变更后 |
|-------|--------|--------|
| Agent-0 | 上下文构建 (LLM) | 不变，拆到 agent_0.py |
| Agent-1 | 代码理解 (LLM) | 不变，拆到 agent_1.py |
| Agent-2 | 风险枚举 (LLM) | 不变，拆到 agent_2.py |
| Agent-3 | 漏洞验证 (LLM) | 不变，拆到 agent_3.py |
| Agent-4 | 攻击链分析 (LLM) | 确定性合成，0 token → agent_4.py |
| Agent-5 | 对抗验证 (LLM) | 确定性映射，0 token → agent_5.py |
| Agent-6 | 最终裁决 (LLM) | 确定性聚合，0 token → agent_6.py |

**LLM 调用减少：7次 → 4次**

### 文件结构

`
src/ai/pure_ai/
├── agent_0.py              # [LLM] 上下文构建
├── agent_1.py              # [LLM] 代码理解
├── agent_2.py              # [LLM] 风险枚举
├── agent_3.py              # [LLM] 漏洞验证
├── agent_4.py              # [确定] 攻击链合成
├── agent_5.py              # [确定] 对抗验证
├── agent_6.py              # [确定] 最终裁决
├── agents.py               # AgentRunner 包装器（接口不变）
├── multi_agent_pipeline.py # 主流程编排（2230行，全委托模式）
`

### 关键删除

- _fallback_attack_chains() — 被 _synthesize_attack_chains() 替代
- skip_agent_4_5 token 预算跳过逻辑 — Agent-4/5 0 token 不再需要
- gents_4_5_6.py — 合并文件，拆为 agent_4.py/agent_5.py/agent_6.py

### 兼容性

- AgentRunner 接口完全不变，外部调用无需修改

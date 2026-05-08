"""报告生成技能插件

提供报告生成相关的提示词模板和执行逻辑。
"""

from typing import Any, Dict, List

from ..base import PluginMetadata, SkillPlugin, SkillPrompt


class ReportGenerationSkill(SkillPlugin):
    """报告生成技能插件"""

    def __init__(self, config: Dict[str, Any] = None):
        metadata = PluginMetadata(
            name="report_generation_skill",
            version="1.0.0",
            description="报告生成技能，提供漏洞报告、扫描报告、总结报告等提示词模板",
            author="HOS Team",
            priority=2,
            enabled=True,
        )
        super().__init__(metadata, config)
        self._init_skill_prompts()

    def _init_skill_prompts(self) -> None:
        self._skill_prompts = [
            SkillPrompt(
                name="vulnerability_report",
                description="生成漏洞扫描报告",
                template="""# 漏洞扫描报告

## 扫描基本信息
- **扫描目标**: {target}
- **扫描时间**: {scan_date}
- **扫描工具**: {scan_tool}
- **扫描策略**: {scan_policy}

## 执行摘要
{executive_summary}

## 扫描结果统计

### 按严重程度分类
| 严重程度 | 数量 | 占比 |
|---------|------|------|
| 严重 | {critical_count} | {critical_percent}% |
| 高危 | {high_count} | {high_percent}% |
| 中危 | {medium_count} | {medium_percent}% |
| 低危 | {low_count} | {low_percent}% |
| 信息 | {info_count} | {info_percent}% |

### 按漏洞类型分类
| 漏洞类型 | 数量 | 涉及主机 |
|---------|------|---------|
| {vuln_type_1} | {count_1} | {hosts_1} |
| {vuln_type_2} | {count_2} | {hosts_2} |

## 漏洞详情

### {vuln_name}
**CVE编号**: {cve_id}
**CVSS评分**: {cvss_score} ({cvss_vector})
**严重程度**: {severity}

**漏洞描述**:
{vuln_description}

**受影响组件**:
- 组件名称: {component_name}
- 版本: {component_version}
- 组件类型: {component_type}

**漏洞位置**:
```
{code_snippet}
```

**复现步骤**:
1. {step_1}
2. {step_2}
3. {step_3}

**影响分析**:
{impact_analysis}

**修复建议**:
**紧急程度**: {urgency}

修复方案：
{fix_recommendation}

修复代码示例：
```{language}
{fix_code}
```

**参考资源**:
- {reference_1}
- {reference_2}

**验证方法**:
{verification_method}

## 附录

### A. 扫描配置
{scan_config}

### B. 误报说明
{false_positive_notes}

### C. 后续建议
{follow_up_recommendations}""",
                parameters={
                    "target": "",
                    "scan_date": "",
                    "scan_tool": "HOS Security Scanner",
                    "scan_policy": "全面扫描",
                    "executive_summary": "",
                    "critical_count": "0",
                    "critical_percent": "0",
                    "high_count": "0",
                    "high_percent": "0",
                    "medium_count": "0",
                    "medium_percent": "0",
                    "low_count": "0",
                    "low_percent": "0",
                    "info_count": "0",
                    "info_percent": "0",
                    "vuln_type_1": "",
                    "count_1": "0",
                    "hosts_1": "",
                    "vuln_type_2": "",
                    "count_2": "0",
                    "hosts_2": "",
                    "vuln_name": "",
                    "cve_id": "",
                    "cvss_score": "",
                    "cvss_vector": "",
                    "severity": "",
                    "vuln_description": "",
                    "component_name": "",
                    "component_version": "",
                    "component_type": "",
                    "code_snippet": "",
                    "step_1": "",
                    "step_2": "",
                    "step_3": "",
                    "impact_analysis": "",
                    "urgency": "",
                    "fix_recommendation": "",
                    "language": "python",
                    "fix_code": "",
                    "reference_1": "",
                    "reference_2": "",
                    "verification_method": "",
                    "scan_config": "",
                    "false_positive_notes": "",
                    "follow_up_recommendations": "",
                }
            ),
            SkillPrompt(
                name="scan_report",
                description="生成安全扫描综合报告",
                template="""# 安全扫描综合报告

## 报告信息
- **报告编号**: {report_id}
- **生成时间**: {generated_date}
- **扫描类型**: {scan_type}
- **目标范围**: {target_scope}

## 项目概述
{project_overview}

## 扫描范围与方法

### 扫描范围
- 扫描目标数量: {target_count}
- 扫描端口范围: {port_range}
- 扫描协议: {protocols}

### 扫描方法
- 主机发现: {host_discovery}
- 服务枚举: {service_enumeration}
- 漏洞检测: {vuln_detection}
- 配置审计: {config_audit}

## 扫描结果概览

### 总体统计
| 指标 | 数值 |
|------|------|
| 扫描主机数 | {total_hosts} |
| 发现服务数 | {total_services} |
| 发现漏洞数 | {total_vulns} |
| 高危漏洞 | {high_vulns} |
| 中危漏洞 | {medium_vulns} |
| 低危漏洞 | {low_vulns} |

### 安全评分
**综合安全评分**: {overall_score}/100

**评分详情**:
- 网络安全: {network_score}/100
- 主机安全: {host_score}/100
- 应用安全: {app_score}/100
- 数据安全: {data_score}/100

## 主机扫描结果

### {host_ip}
**主机状态**: {host_status}
**操作系统**: {os_version}
**开放端口数**: {open_ports}

**开放服务**:
| 端口 | 服务 | 版本 | 风险等级 |
|------|------|------|---------|
| {port} | {service} | {version} | {risk_level} |

**发现的问题**:
{methodology_findings}

## 漏洞详情

### 高危漏洞列表
{section_high}

### 中危漏洞列表
{section_medium}

### 低危漏洞列表
{section_low}

## 合规性检查

### 检查标准
- {compliance_standard_1}: {status_1}
- {compliance_standard_2}: {status_2}

### 合规差距分析
{compliance_gaps}

## 风险分析

### 业务风险评估
{business_risk}

### 技术风险评估
{technical_risk}

### 风险优先级矩阵
| 风险级别 | 影响 | 可能性 | 优先级 |
|---------|------|--------|-------|
| {risk_level} | {impact} | {likelihood} | {priority} |

## 修复建议

### 紧急修复（24小时内）
{urgent_fixes}

### 高优先级修复（1周内）
{high_priority_fixes}

### 中优先级修复（1月内）
{medium_priority_fixes}

### 低优先级修复（后续迭代）
{low_priority_fixes}

## 结论
{conclusion}

## 附录
### A. 扫描工具版本
{tool_versions}

### B. 扫描时间线
{scan_timeline}

### C. 术语表
{glossary}""",
                parameters={
                    "report_id": "",
                    "generated_date": "",
                    "scan_type": "综合扫描",
                    "target_scope": "",
                    "project_overview": "",
                    "target_count": "0",
                    "port_range": "1-65535",
                    "protocols": "TCP, UDP",
                    "host_discovery": "ICMP扫描",
                    "service_enumeration": "端口扫描",
                    "vuln_detection": "自动化检测",
                    "config_audit": "配置审查",
                    "total_hosts": "0",
                    "total_services": "0",
                    "total_vulns": "0",
                    "high_vulns": "0",
                    "medium_vulns": "0",
                    "low_vulns": "0",
                    "overall_score": "70",
                    "network_score": "70",
                    "host_score": "70",
                    "app_score": "70",
                    "data_score": "70",
                    "host_ip": "",
                    "host_status": "",
                    "os_version": "",
                    "open_ports": "0",
                    "port": "",
                    "service": "",
                    "version": "",
                    "risk_level": "",
                    "methodology_findings": "",
                    "section_high": "",
                    "section_medium": "",
                    "section_low": "",
                    "compliance_standard_1": "",
                    "status_1": "",
                    "compliance_standard_2": "",
                    "status_2": "",
                    "compliance_gaps": "",
                    "business_risk": "",
                    "technical_risk": "",
                    "risk_level": "",
                    "impact": "",
                    "likelihood": "",
                    "priority": "",
                    "urgent_fixes": "",
                    "high_priority_fixes": "",
                    "medium_priority_fixes": "",
                    "low_priority_fixes": "",
                    "conclusion": "",
                    "tool_versions": "",
                    "scan_timeline": "",
                    "glossary": "",
                }
            ),
            SkillPrompt(
                name="summary_report",
                description="生成安全评估总结报告",
                template="""# 安全评估总结报告

## 报告概览
- **项目名称**: {project_name}
- **评估时间**: {assessment_period}
- **报告类型**: {report_type}
- **编制人员**: {prepared_by}

## 执行摘要
{executive_summary}

## 关键发现
{key_findings}

## 风险概览

### 当前风险等级
**总体风险等级**: {risk_level}

### 风险趋势
| 风险类别 | 上期状态 | 当前状态 | 变化趋势 |
|---------|---------|---------|---------|
| {category_1} | {previous_1} | {current_1} | {trend_1} |
| {category_2} | {previous_2} | {current_2} | {trend_2} |

## 评估范围

### 涵盖系统
- {system_1}
- {system_2}
- {system_3}

### 评估标准
- {standard_1}
- {standard_2}

## 主要成果

### 1. 安全弱点识别
{weaknesses_identified}

### 2. 风险缓解进展
{risk_mitigation_progress}

### 3. 安全控制评估
{security_controls_evaluation}

## 统计数据

### 漏洞统计
| 类别 | 数量 | 修复率 |
|------|------|--------|
| 高危 | {high_count} | {high_rate}% |
| 中危 | {medium_count} | {medium_rate}% |
| 低危 | {low_count} | {low_rate}% |

### 合规统计
| 标准 | 要求数 | 满足数 | 合规率 |
|------|-------|-------|--------|
| {std_1} | {req_1} | {met_1} | {rate_1}% |
| {std_2} | {req_2} | {met_2} | {rate_2}% |

## 改进建议

### 短期建议（0-30天）
{short_term_recommendations}

### 中期建议（30-90天）
{medium_term_recommendations}

### 长期建议（90天以上）
{long_term_recommendations}

## 资源投入
### 人力资源
{human_resources}

### 技术资源
{technical_resources}

### 预算估算
{budget_estimate}

## 成功指标
| 指标 | 目标值 | 当前值 | 达成率 |
|------|--------|--------|--------|
| {metric_1} | {target_1} | {current_1} | {achievement_1}% |
| {metric_2} | {target_2} | {current_2} | {achievement_2}% |

## 结论与展望
{conclusion_outlook}

## 下次评估计划
{next_assessment_plan}""",
                parameters={
                    "project_name": "",
                    "assessment_period": "",
                    "report_type": "年度安全评估",
                    "prepared_by": "",
                    "executive_summary": "",
                    "key_findings": "",
                    "risk_level": "中",
                    "category_1": "",
                    "previous_1": "",
                    "current_1": "",
                    "trend_1": "",
                    "category_2": "",
                    "previous_2": "",
                    "current_2": "",
                    "trend_2": "",
                    "system_1": "",
                    "system_2": "",
                    "system_3": "",
                    "standard_1": "",
                    "standard_2": "",
                    "weaknesses_identified": "",
                    "risk_mitigation_progress": "",
                    "security_controls_evaluation": "",
                    "high_count": "0",
                    "high_rate": "0",
                    "medium_count": "0",
                    "medium_rate": "0",
                    "low_count": "0",
                    "low_rate": "0",
                    "std_1": "",
                    "req_1": "0",
                    "met_1": "0",
                    "rate_1": "0",
                    "std_2": "",
                    "req_2": "0",
                    "met_2": "0",
                    "rate_2": "0",
                    "short_term_recommendations": "",
                    "medium_term_recommendations": "",
                    "long_term_recommendations": "",
                    "human_resources": "",
                    "technical_resources": "",
                    "budget_estimate": "",
                    "metric_1": "",
                    "target_1": "",
                    "current_1": "",
                    "achievement_1": "0",
                    "metric_2": "",
                    "target_2": "",
                    "current_2": "",
                    "achievement_2": "0",
                    "conclusion_outlook": "",
                    "next_assessment_plan": "",
                }
            ),
            SkillPrompt(
                name="incident_report",
                description="生成安全事件报告",
                template="""# 安全事件报告

## 事件基本信息
- **事件编号**: {incident_id}
- **发现时间**: {discovery_time}
- **报告时间**: {report_time}
- **事件类型**: {incident_type}
- **事件级别**: {incident_level}

## 事件概要
{incident_summary}

## 事件时间线

### 事件发展脉络
| 时间 | 阶段 | 描述 | 负责人 |
|------|------|------|--------|
| {time_1} | {stage_1} | {desc_1} | {owner_1} |
| {time_2} | {stage_2} | {desc_2} | {owner_2} |
| {time_3} | {stage_3} | {desc_3} | {owner_3} |

## 影响评估

### 影响范围
- 受影响系统: {affected_systems}
- 受影响用户数: {affected_users}
- 数据泄露量: {data_breach_size}
- 服务中断时间: {downtime}

### 影响程度
**总体影响等级**: {impact_level}

### 业务影响分析
{business_impact}

## 事件详情

### 攻击向量
{attack_vector}

### 攻击过程
{attack_process}

### 利用的漏洞
| 漏洞ID | 类型 | 严重程度 | CVE |
|--------|------|---------|-----|
| {vuln_id_1} | {vuln_type_1} | {vuln_severity_1} | {vuln_cve_1} |

### 攻击者信息
- 来源IP: {attacker_ip}
- 攻击手法: {attack_method}
- 攻击目的: {attack_purpose}

## 响应措施

### 即时响应（0-1小时）
{immediate_response}

### 短期措施（1-24小时）
{short_term_measures}

### 长期措施（1周以上）
{long_term_measures}

## 遏制与根除

### 遏制措施
{containment_measures}

### 根除措施
{eradication_measures}

### 系统恢复
{recovery_steps}

## 经验教训

### 成功之处
{what_worked}

### 需要改进
{what_needs_improvement}

### 预防建议
{prevention_recommendations}

## 成本损失
| 类别 | 金额/数量 |
|------|-----------|
| 直接损失 | {direct_cost} |
| 间接损失 | {indirect_cost} |
| 响应成本 | {response_cost} |
| 声誉损失 | {reputation_loss} |

## 附录

### A. 证据清单
{evidence_list}

### B. 参与人员
{personnel_involved}

### C. 相关文档
{related_documents}

### D. 后续跟进事项
{follow_up_items}""",
                parameters={
                    "incident_id": "",
                    "discovery_time": "",
                    "report_time": "",
                    "incident_type": "",
                    "incident_level": "",
                    "incident_summary": "",
                    "time_1": "",
                    "stage_1": "",
                    "desc_1": "",
                    "owner_1": "",
                    "time_2": "",
                    "stage_2": "",
                    "desc_2": "",
                    "owner_2": "",
                    "time_3": "",
                    "stage_3": "",
                    "desc_3": "",
                    "owner_3": "",
                    "affected_systems": "",
                    "affected_users": "",
                    "data_breach_size": "",
                    "downtime": "",
                    "impact_level": "",
                    "business_impact": "",
                    "attack_vector": "",
                    "attack_process": "",
                    "vuln_id_1": "",
                    "vuln_type_1": "",
                    "vuln_severity_1": "",
                    "vuln_cve_1": "",
                    "attacker_ip": "",
                    "attack_method": "",
                    "attack_purpose": "",
                    "immediate_response": "",
                    "short_term_measures": "",
                    "long_term_measures": "",
                    "containment_measures": "",
                    "eradication_measures": "",
                    "recovery_steps": "",
                    "what_worked": "",
                    "what_needs_improvement": "",
                    "prevention_recommendations": "",
                    "direct_cost": "",
                    "indirect_cost": "",
                    "response_cost": "",
                    "reputation_loss": "",
                    "evidence_list": "",
                    "personnel_involved": "",
                    "related_documents": "",
                    "follow_up_items": "",
                }
            ),
        ]

    async def execute_skill(self, skill_name: str, parameters: Dict[str, Any]) -> Any:
        return await super().execute_skill(skill_name, parameters)

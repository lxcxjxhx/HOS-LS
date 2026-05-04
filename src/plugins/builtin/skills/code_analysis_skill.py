"""代码分析技能插件

提供代码分析相关的提示词模板和执行逻辑。
"""

from typing import Any, Dict, List

from ..base import PluginMetadata, SkillPlugin, SkillPrompt


class CodeAnalysisSkill(SkillPlugin):
    """代码分析技能插件"""

    def __init__(self, config: Dict[str, Any] = None):
        metadata = PluginMetadata(
            name="code_analysis_skill",
            version="1.0.0",
            description="代码分析技能，提供漏洞分析、代码审查、安全评估等提示词模板",
            author="HOS Team",
            priority=2,
            enabled=True,
        )
        super().__init__(metadata, config)
        self._init_skill_prompts()

    def _init_skill_prompts(self) -> None:
        self._skill_prompts = [
            SkillPrompt(
                name="vulnerability_analysis",
                description="对代码进行漏洞分析，识别潜在的安全风险",
                template="""# 漏洞分析任务

## 代码上下文
```{language}
{code}
```

## 分析目标
对上述代码进行全面的漏洞分析，识别以下类型的漏洞：

### 输入验证类漏洞
- SQL注入
- XSS跨站脚本
- 命令注入
- 路径遍历
- LDAP注入

### 认证授权类漏洞
- 硬编码凭证
- 弱密码策略
- 会话管理问题
- 越权访问

### 代码质量类漏洞
- 敏感信息泄露
- 错误处理不当
- 日志记录缺失
- 资源泄漏

## 输出要求
请按照以下格式输出分析结果：

### 发现漏洞列表
| 漏洞类型 | 严重程度 | 位置 | 描述 | 建议修复 |
|---------|---------|------|------|---------|
| ... | ... | ... | ... | ... |

### 漏洞详情
对每个漏洞提供：
1. **漏洞位置**：具体代码行或函数
2. **漏洞原理**：为什么会产生此漏洞
3. **利用条件**：攻击者如何利用此漏洞
4. **修复建议**：具体的修复代码或方案

### 总体评估
- 高危漏洞数量：{high_count}
- 中危漏洞数量：{medium_count}
- 低危漏洞数量：{low_count}
- 安全评分：{score}/100

## 附加要求
- 仅分析提供的代码片段，不要进行推测
- 如果代码看起来是安全的，明确说明
- 提供具体的修复代码示例，不要只描述原则""",
                parameters={
                    "language": "python",
                    "code": "",
                    "high_count": "0",
                    "medium_count": "0",
                    "low_count": "0",
                    "score": "100",
                }
            ),
            SkillPrompt(
                name="code_review",
                description="对代码进行全面的审查，包括安全性、性能、可维护性",
                template="""# 代码审查任务

## 待审查代码
```{language}
{code}
```

## 代码路径
{file_path}

## 审查范围
请对代码进行以下方面的全面审查：

### 1. 安全性审查
- 认证和授权机制是否正确实现
- 输入验证和输出编码是否充分
- 敏感数据处理是否安全
- API安全性（JWT、OAuth等）
- 加密算法使用是否正确

### 2. 性能审查
- 是否有不必要的循环或递归
- 数据库查询是否优化
- 是否有内存泄漏风险
- 并发处理是否正确

### 3. 代码质量审查
- 命名规范和代码风格
- 函数长度和复杂度
- 注释质量和文档完整性
- 错误处理是否得当
- 测试覆盖是否充分

### 4. 最佳实践审查
- 是否遵循该语言的编码规范
- 依赖项是否安全且版本合适
- 配置管理是否规范
- 日志记录是否适当

## 输出格式

### 总体评分
评分：{score}/100

### 发现问题汇总
| 问题类型 | 严重程度 | 位置 | 问题描述 |
|---------|---------|------|---------|
| ... | ... | ... | ... |

### 详细分析
对每个问题提供：
1. 问题位置（文件和行号）
2. 问题描述和潜在影响
3. 代码片段标注
4. 改进建议

### 改进建议
按优先级列出所有需要修复的问题""",
                parameters={
                    "language": "python",
                    "code": "",
                    "file_path": "unknown",
                    "score": "100",
                }
            ),
            SkillPrompt(
                name="security_assessment",
                description="对代码项目进行整体安全评估",
                template="""# 安全评估任务

## 项目信息
- 项目名称：{project_name}
- 编程语言：{language}
- 项目类型：{project_type}

## 代码结构
```
{code_structure}
```

## 关键代码片段
```{language}
{critical_code}
```

## 评估维度

### 1. 架构安全评估
- 整体架构是否存在安全隐患
- 信任边界是否清晰
- 组件间通信是否安全
- 第三方服务集成是否安全

### 2. 数据安全评估
- 敏感数据存储是否加密
- 数据传输是否使用TLS/SSL
- 密钥管理是否规范
- 数据备份是否安全

### 3. 身份认证评估
- 密码存储是否使用强哈希算法
- 会话管理是否安全
- 多因素认证是否实现
- API密钥管理是否规范

### 4. 业务逻辑安全评估
- 业务逻辑是否存在漏洞
- 交易流程是否安全
- 权限控制是否完善
- 异常处理是否安全

### 5. 基础设施安全评估
- 容器镜像是否安全
- 配置文件是否包含敏感信息
- 环境变量是否正确管理
- 依赖项是否存在已知漏洞

## 输出要求

### 安全风险矩阵
| 风险类别 | 风险等级 | 影响范围 | 当前状态 |
|---------|---------|---------|---------|
| ... | ... | ... | ... |

### 关键发现
列出最严重的安全问题及其潜在影响

### 改进路线图
按优先级提供安全改进建议
- 紧急（立即修复）：
- 高优先级（本周内）：
- 中优先级（本月内）：
- 低优先级（后续迭代）：

### 合规性检查
检查是否符合以下安全标准：
- OWASP Top 10
- {compliance_standard}

### 安全评分
总体安全评分：{score}/100""",
                parameters={
                    "project_name": "unknown",
                    "language": "python",
                    "project_type": "web application",
                    "code_structure": "",
                    "critical_code": "",
                    "compliance_standard": "通用安全标准",
                    "score": "70",
                }
            ),
            SkillPrompt(
                name="penetration_test_report",
                description="生成渗透测试报告",
                template="""# 渗透测试报告

## 测试目标
- 目标系统：{target_system}
- 测试范围：{test_scope}
- 测试时间：{test_date}
- 测试人员：{tester_name}

## 测试方法

### 信息收集
执行的侦察活动：
- 被动信息收集
- 主动信息收集
- 指纹识别
- 服务枚举

### 漏洞发现
使用的漏洞发现方法：
- 自动化扫描
- 手动测试
- 配置审查
- 代码审计

### 漏洞利用
执行的利用测试：
- 漏洞验证
- 权限提升
- 横向移动
- 数据访问

## 发现的漏洞

### 高危漏洞
| 漏洞名称 | CVE编号 | CVSS评分 | 位置 | 描述 |
|---------|---------|---------|------|------|
| ... | ... | ... | ... | ... |

### 中危漏洞
| 漏洞名称 | CVE编号 | CVSS评分 | 位置 | 描述 |
|---------|---------|---------|------|------|
| ... | ... | ... | ... | ... |

### 低危漏洞
| 漏洞名称 | CVE编号 | CVSS评分 | 位置 | 描述 |
|---------|---------|---------|------|------|
| ... | ... | ... | ... | ... |

## 漏洞详情

### {vuln_name}
**CVSS评分**: {cvss_score}

**漏洞描述**:
{vuln_description}

**影响分析**:
{impact_analysis}

**复现步骤**:
1. {step_1}
2. {step_2}
3. {step_3}

**修复建议**:
{fix_recommendation}

**参考链接**:
{references}

## 测试结论
{conclusion}

## 附录
### 测试工具列表
- {tool_1}
- {tool_2}

### 测试环境配置
{environment_config}""",
                parameters={
                    "target_system": "",
                    "test_scope": "",
                    "test_date": "",
                    "tester_name": "",
                    "vuln_name": "",
                    "cvss_score": "",
                    "vuln_description": "",
                    "impact_analysis": "",
                    "step_1": "",
                    "step_2": "",
                    "step_3": "",
                    "fix_recommendation": "",
                    "references": "",
                    "conclusion": "",
                    "tool_1": "",
                    "tool_2": "",
                    "environment_config": "",
                }
            ),
        ]

    async def execute_skill(self, skill_name: str, parameters: Dict[str, Any]) -> Any:
        return await super().execute_skill(skill_name, parameters)

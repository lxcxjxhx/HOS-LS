# AI工具安全检测报告

## 检测摘要

| 检测目标 | 检测时间 | 高风险 | 中风险 | 低风险 |
|---------|---------|-------|-------|-------|
| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool | 2026-04-01 22:44:40 | 8 | 3 | 0 |


## 代码安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\config.json | 2 | 硬编码敏感信息 | high | 检测硬编码的敏感信息（API 密钥、密码、令牌等） |

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 5 | 硬编码敏感信息 | high | 检测硬编码的敏感信息（API 密钥、密码、令牌等） |

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 8 | 硬编码敏感信息 | high | 检测硬编码的敏感信息（API 密钥、密码、令牌等） |

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 11 | 硬编码敏感信息 | high | 检测硬编码的敏感信息（API 密钥、密码、令牌等） |

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 5 | 硬编码敏感信息 | high | 检测硬编码的敏感信息（API 密钥、密码、令牌等） |

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 20 | 网络访问代码 | medium | 检测网络访问代码，需要适当的安全验证 |










## 配置安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 5 | 配置包含敏感信息 | high | 检测配置文件中包含敏感信息 |

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 8 | 配置包含敏感信息 | high | 检测配置文件中包含敏感信息 |

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 11 | 配置包含敏感信息 | high | 检测配置文件中包含敏感信息 |

| c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-ai-tool\test.py | 5 | AI 配置 | medium | 检测 AI 特定配置 |



---

报告生成时间: 2026-04-01 22:44:40
AI工具安全检测工具 v1.0.0
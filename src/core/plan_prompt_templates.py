"""Plan相关的Prompt模板

包含用于AI生成和修改Plan的Prompt模板。
"""

import json
from typing import Dict, Any


def get_plan_generation_prompt(natural_language: str) -> str:
    """获取Plan生成的Prompt
    
    Args:
        natural_language: 用户的自然语言输入
        
    Returns:
        Prompt字符串
    """
    # 使用字符串拼接避免f-string嵌套过深
    prompt = """你是一个专业的安全扫描Plan生成器，需要根据用户的需求生成一个合理的安全扫描计划。

用户需求: """
    prompt += natural_language
    prompt += """

请仔细分析用户的需求，即使是口语化的表达，也要准确理解其意图。以下是一些常见口语化表达的理解示例：
- "检查一下代码安全": 表示需要进行全面的代码安全扫描
- "看看有没有认证漏洞": 表示需要进行认证分析
- "快速过一遍": 表示需要使用fast配置，进行快速扫描
- "深入分析": 表示需要使用deep配置，进行深度分析
- "生成漏洞报告": 表示需要在步骤中包含报告生成

请根据用户需求，生成一个完整的安全扫描Plan，包含以下内容：
1. goal: 扫描目标
2. profile: 配置文件 (standard, full, fast, deep, stealth)
3. steps: 执行步骤列表，每个步骤包含类型和配置
4. constraints: 约束条件
5. plan_version: 版本号

步骤类型包括：
- scan: 代码扫描
- auth_analysis: 认证分析
- poc: 漏洞利用生成
- reason: 漏洞推理
- attack_chain: 攻击链分析
- verify: 漏洞验证
- fix: 修复建议
- report: 报告生成

请生成一个JSON格式的Plan，格式如下：

```json
{
  "plan": {
    "goal": "目标描述",
    "profile": "配置文件",
    "steps": [
      {
        "step_type": {
          "param1": "value1",
          "param2": "value2"
        }
      }
    ],
    "constraints": {
      "safe_mode": true,
      "max_time": "可选的最大时间",
      "max_workers": 1
    },
    "plan_version": "v1.0"
  }
}
```

示例1:
用户需求: 分析认证漏洞

```json
{
  "plan": {
    "goal": "分析认证漏洞",
    "profile": "standard",
    "steps": [
      {
        "scan": {
          "path": ".",
          "depth": "medium"
        }
      },
      {
        "auth_analysis": {
          "detect": ["jwt", "session", "oauth"]
        }
      },
      {
        "poc": {
          "generate": false
        }
      }
    ],
    "constraints": {
      "safe_mode": true
    },
    "plan_version": "v1.0"
  }
}
```

示例2:
用户需求: 快速安全检查

```json
{
  "plan": {
    "goal": "快速安全检查",
    "profile": "fast",
    "steps": [
      {
        "scan": {
          "path": ".",
          "depth": "low"
        }
      },
      {
        "report": {
          "format": "html"
        }
      }
    ],
    "constraints": {
      "safe_mode": true
    },
    "plan_version": "v1.0"
  }
}
```

示例3:
用户需求: 帮我看看代码有没有问题，特别是认证部分，要详细一点

```json
{
  "plan": {
    "goal": "详细分析代码安全问题，特别是认证部分",
    "profile": "deep",
    "steps": [
      {
        "scan": {
          "path": ".",
          "depth": "high"
        }
      },
      {
        "auth_analysis": {
          "detect": ["jwt", "session", "oauth", "basic"]
        }
      },
      {
        "reason": {
          "depth": "deep"
        }
      },
      {
        "report": {
          "format": "html",
          "detail_level": "high"
        }
      }
    ],
    "constraints": {
      "safe_mode": true
    },
    "plan_version": "v1.0"
  }
}
```

请根据用户需求生成合适的Plan，确保JSON格式正确，并且Plan结构完整合理。"""
    return prompt


def get_plan_modification_prompt(plan_json: Dict[str, Any], modification: str) -> str:
    """获取Plan修改的Prompt
    
    Args:
        plan_json: 原始Plan的JSON表示
        modification: 用户的修改请求
        
    Returns:
        Prompt字符串
    """
    plan_str = json.dumps(plan_json, ensure_ascii=False, indent=2)
    
    prompt = """你是一个专业的安全扫描Plan修改器，需要根据用户的修改请求更新安全扫描计划。

原始Plan:
{plan_str}

修改请求: {modification}

请根据修改请求，更新Plan，并保持Plan的结构完整。更新后的Plan应该：
1. 保持原始Plan的基本结构
2. 根据修改请求进行相应的更改
3. 确保所有必要的字段都存在
4. 保持JSON格式正确

请生成更新后的Plan，格式如下：

```json
{
  "plan": {
    "goal": "目标描述",
    "profile": "配置文件",
    "steps": [
      {
        "step_type": {
          "param1": "value1",
          "param2": "value2"
        }
      }
    ],
    "constraints": {
      "safe_mode": true,
      "max_time": "可选的最大时间",
      "max_workers": 1
    },
    "plan_version": "v1.0"
  }
}
```

示例:
原始Plan:
{
  "plan": {
    "goal": "分析认证漏洞",
    "profile": "standard",
    "steps": [
      {
        "scan": {
          "path": ".",
          "depth": "medium"
        }
      },
      {
        "auth_analysis": {
          "detect": ["jwt", "session", "oauth"]
        }
      },
      {
        "poc": {
          "generate": false
        }
      }
    ],
    "constraints": {
      "safe_mode": true
    },
    "plan_version": "v1.0"
  }
}

修改请求: 加上POC，深度改成最高

```json
{
  "plan": {
    "goal": "分析认证漏洞",
    "profile": "full",
    "steps": [
      {
        "scan": {
          "path": ".",
          "depth": "high"
        }
      },
      {
        "auth_analysis": {
          "detect": ["jwt", "session", "oauth"]
        }
      },
      {
        "poc": {
          "generate": true
        }
      }
    ],
    "constraints": {
      "safe_mode": true
    },
    "plan_version": "v1.1"
  }
}
```

请根据修改请求生成更新后的Plan，确保JSON格式正确，并且Plan结构完整合理。""".format(plan_str=plan_str, modification=modification)
    return prompt


def get_plan_explanation_prompt(plan_json: Dict[str, Any]) -> str:
    """获取Plan解释的Prompt
    
    Args:
        plan_json: Plan的JSON表示
        
    Returns:
        Prompt字符串
    """
    plan_str = json.dumps(plan_json, ensure_ascii=False, indent=2)
    
    prompt = """你是一个专业的安全扫描Plan解释器，需要为给定的安全扫描计划生成详细的解释。

Plan:
{plan_str}

请生成一个详细的解释，包括：
1. 目标解释：解释Plan的目标
2. 配置选择：解释为什么选择这个配置文件
3. 步骤解释：解释每个步骤的目的和作用
4. 约束解释：解释约束条件的意义
5. 执行流程：解释整个执行流程的逻辑

请以清晰、专业的语言生成解释，确保用户能够理解Plan的设计意图和执行流程。""".format(plan_str=plan_str)
    return prompt

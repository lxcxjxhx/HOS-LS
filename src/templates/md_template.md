# AI工具安全检测报告

## 检测摘要

| 检测目标 | 检测时间 | 高风险 | 中风险 | 低风险 |
|---------|---------|-------|-------|-------|
| {{ target }} | {{ timestamp }} | {{ high_risk }} | {{ medium_risk }} | {{ low_risk }} |

{% if code_security %}
## 代码安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|
{% for item in code_security %}
| {{ item.file }} | {{ item.line_number }} | {{ item.issue }} | {{ item.severity }} | {{ item.details }} |
{% endfor %}
{% endif %}

{% if permission_security %}
## 权限安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|
{% for item in permission_security %}
| {{ item.file }} | {{ item.line_number }} | {{ item.issue }} | {{ item.severity }} | {{ item.details }} |
{% endfor %}
{% endif %}

{% if network_security %}
## 网络安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|
{% for item in network_security %}
| {{ item.file }} | {{ item.line_number }} | {{ item.issue }} | {{ item.severity }} | {{ item.details }} |
{% endfor %}
{% endif %}

{% if dependency_security %}
## 依赖安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|
{% for item in dependency_security %}
| {{ item.file }} | {{ item.line_number }} | {{ item.issue }} | {{ item.severity }} | {{ item.details }} |
{% endfor %}
{% endif %}

{% if config_security %}
## 配置安全

| 文件 | 行号 | 问题 | 严重程度 | 详情 |
|------|------|------|---------|------|
{% for item in config_security %}
| {{ item.file }} | {{ item.line_number }} | {{ item.issue }} | {{ item.severity }} | {{ item.details }} |
{% endfor %}
{% endif %}

---

报告生成时间: {{ timestamp }}
AI工具安全检测工具 v1.0.0
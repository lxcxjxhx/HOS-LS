# HOS-LS 安全扫描报告

**扫描时间**: {{ results[0].start_time.strftime('%Y-%m-%d %H:%M:%S') if results else 'N/A' }}

## 📊 扫描摘要

| 指标 | 数量 |
|------|------|
| 扫描文件数 | {{ summary.total_scans }} |
| 严重问题 | {{ summary.severity_counts.critical }} |
| 高危问题 | {{ summary.severity_counts.high }} |
| 中危问题 | {{ summary.severity_counts.medium }} |
| 低危问题 | {{ summary.severity_counts.low }} |
| 信息提示 | {{ summary.severity_counts.info }} |

---

## 🔌 端口相关漏洞

{% set port_findings = [] %}
{% for result in results %}
{% for finding in result.findings %}
{% if finding.rule_id.startswith('PORT_') %}
{% set port_findings = port_findings + [finding] %}
{% endif %}
{% endfor %}
{% endfor %}

{% if port_findings %}
{% for finding in port_findings %}

### {{ finding.rule_name | severity_icon }} {{ finding.rule_name }}

- **严重级别**: {{ finding.severity.value | severity_color }} {{ finding.severity.value }}
- **规则 ID**: {{ finding.rule_id }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}

{% if finding.code_snippet %}
```python
{{ finding.code_snippet }}
```
{% endif %}

{% if finding.fix_suggestion %}
> 💡 **修复建议**: {{ finding.fix_suggestion }}
{% endif %}

---
{% endfor %}
{% else %}
*未发现端口相关漏洞*
{% endif %}

---

## 📋 一般静态漏洞

{% set static_findings = [] %}
{% for result in results %}
{% for finding in result.findings %}
{% if not (finding.rule_id.startswith('PORT_') or finding.rule_id.startswith('API_') or finding.rule_id.startswith('AUTH_') or finding.rule_id.startswith('DATA_') or finding.rule_id.startswith('CFG_')) %}
{% set static_findings = static_findings + [finding] %}
{% endif %}
{% endfor %}
{% endfor %}

{% if static_findings %}
{% for finding in static_findings %}

### {{ finding.rule_name | severity_icon }} {{ finding.rule_name }}

- **严重级别**: {{ finding.severity.value | severity_color }} {{ finding.severity.value }}
- **规则 ID**: {{ finding.rule_id }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}

{% if finding.code_snippet %}
```python
{{ finding.code_snippet }}
```
{% endif %}

{% if finding.fix_suggestion %}
> 💡 **修复建议**: {{ finding.fix_suggestion }}
{% endif %}

---
{% endfor %}
{% else %}
*未发现一般静态漏洞*
{% endif %}

---

## 🎯 特别扫描项目

### 🔐 API安全专项

{% set api_findings = [] %}
{% for result in results %}
{% for finding in result.findings %}
{% if finding.rule_id.startswith('API_') %}
{% set api_findings = api_findings + [finding] %}
{% endif %}
{% endfor %}
{% endfor %}

{% if api_findings %}
{% for finding in api_findings %}

#### {{ finding.rule_name | severity_icon }} {{ finding.rule_name }}

- **严重级别**: {{ finding.severity.value | severity_color }} {{ finding.severity.value }}
- **规则 ID**: {{ finding.rule_id }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}

{% if finding.code_snippet %}
```python
{{ finding.code_snippet }}
```
{% endif %}

{% if finding.fix_suggestion %}
> 💡 **修复建议**: {{ finding.fix_suggestion }}
{% endif %}

---
{% endfor %}
{% else %}
*未发现API安全漏洞*
{% endif %}

### 🛡️ 认证安全专项

{% set auth_findings = [] %}
{% for result in results %}
{% for finding in result.findings %}
{% if finding.rule_id.startswith('AUTH_') %}
{% set auth_findings = auth_findings + [finding] %}
{% endif %}
{% endfor %}
{% endfor %}

{% if auth_findings %}
{% for finding in auth_findings %}

#### {{ finding.rule_name | severity_icon }} {{ finding.rule_name }}

- **严重级别**: {{ finding.severity.value | severity_color }} {{ finding.severity.value }}
- **规则 ID**: {{ finding.rule_id }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}

{% if finding.code_snippet %}
```python
{{ finding.code_snippet }}
```
{% endif %}

{% if finding.fix_suggestion %}
> 💡 **修复建议**: {{ finding.fix_suggestion }}
{% endif %}

---
{% endfor %}
{% else %}
*未发现认证安全漏洞*
{% endif %}

### 🔒 数据保护专项

{% set data_findings = [] %}
{% for result in results %}
{% for finding in result.findings %}
{% if finding.rule_id.startswith('DATA_') %}
{% set data_findings = data_findings + [finding] %}
{% endif %}
{% endfor %}
{% endfor %}

{% if data_findings %}
{% for finding in data_findings %}

#### {{ finding.rule_name | severity_icon }} {{ finding.rule_name }}

- **严重级别**: {{ finding.severity.value | severity_color }} {{ finding.severity.value }}
- **规则 ID**: {{ finding.rule_id }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}

{% if finding.code_snippet %}
```python
{{ finding.code_snippet }}
```
{% endif %}

{% if finding.fix_suggestion %}
> 💡 **修复建议**: {{ finding.fix_suggestion }}
{% endif %}

---
{% endfor %}
{% else %}
*未发现数据保护漏洞*
{% endif %}

### ⚙️ 配置安全专项

{% set cfg_findings = [] %}
{% for result in results %}
{% for finding in result.findings %}
{% if finding.rule_id.startswith('CFG_') %}
{% set cfg_findings = cfg_findings + [finding] %}
{% endif %}
{% endfor %}
{% endfor %}

{% if cfg_findings %}
{% for finding in cfg_findings %}

#### {{ finding.rule_name | severity_icon }} {{ finding.rule_name }}

- **严重级别**: {{ finding.severity.value | severity_color }} {{ finding.severity.value }}
- **规则 ID**: {{ finding.rule_id }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}

{% if finding.code_snippet %}
```python
{{ finding.code_snippet }}
```
{% endif %}

{% if finding.fix_suggestion %}
> 💡 **修复建议**: {{ finding.fix_suggestion }}
{% endif %}

---
{% endfor %}
{% else %}
*未发现配置安全漏洞*
{% endif %}

{% if summary.total_findings == 0 %}

## ✅ 扫描结果

未发现安全问题，您的代码通过了所有安全检查。

{% endif %}

---

*Generated by [HOS-LS](https://github.com/hos-ls/hos-ls) v{{ config.version }}*

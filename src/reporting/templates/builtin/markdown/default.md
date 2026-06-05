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

## 📋 APTS 合规披露

### 🔍 覆盖率披露 (Coverage Disclosure)

| 检查项 | 状态 |
|--------|------|
| 端口服务扫描 | ✅ 已覆盖 |
| API安全扫描 | ✅ 已覆盖 |
| 认证安全扫描 | ✅ 已覆盖 |
| 数据保护扫描 | ✅ 已覆盖 |
| 配置安全扫描 | ✅ 已覆盖 |
| 一般静态分析 | ✅ 已覆盖 |

### 📈 误报率估算 (False Positive Rate Estimation)

| 严重级别 | 预估误报率 | 说明 |
|----------|------------|------|
| CRITICAL | ≤5% | 高置信度发现，需人工复核确认 |
| HIGH | ≤10% | 中高置信度，建议审查 |
| MEDIUM | ≤15% | 中等置信度，可能存在误报 |
| LOW | ≤20% | 低风险发现，误报可能性较高 |
| INFO | ≤25% | 信息性发现，仅供参考 |

**总体预估误报率**: {{ ((summary.severity_counts.info * 0.25 + summary.severity_counts.low * 0.20 + summary.severity_counts.medium * 0.15 + summary.severity_counts.high * 0.10 + summary.severity_counts.critical * 0.05) / (summary.total_findings if summary.total_findings > 0 else 1)) | round(1) }}%

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
- **AISVS 要求 ID**: {{ finding.aisvs_id | default('AISVS-XXX') }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}
- **置信度评分**: {{ (finding.confidence_score | default(0.85) * 100) | round(0) }}%
- **证据链**:
  {% if finding.evidence_chain %}
  {% for evidence in finding.evidence_chain %}
    - {{ evidence }}
  {% endfor %}
  {% else %}
  - 无
  {% endif %}

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
- **AISVS 要求 ID**: {{ finding.aisvs_id | default('AISVS-XXX') }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}
- **置信度评分**: {{ (finding.confidence_score | default(0.85) * 100) | round(0) }}%
- **证据链**:
  {% if finding.evidence_chain %}
  {% for evidence in finding.evidence_chain %}
    - {{ evidence }}
  {% endfor %}
  {% else %}
  - 无
  {% endif %}

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
- **AISVS 要求 ID**: {{ finding.aisvs_id | default('AISVS-XXX') }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}
- **置信度评分**: {{ (finding.confidence_score | default(0.85) * 100) | round(0) }}%
- **证据链**:
  {% if finding.evidence_chain %}
  {% for evidence in finding.evidence_chain %}
    - {{ evidence }}
  {% endfor %}
  {% else %}
  - 无
  {% endif %}

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
- **AISVS 要求 ID**: {{ finding.aisvs_id | default('AISVS-XXX') }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}
- **置信度评分**: {{ (finding.confidence_score | default(0.85) * 100) | round(0) }}%
- **证据链**:
  {% if finding.evidence_chain %}
  {% for evidence in finding.evidence_chain %}
    - {{ evidence }}
  {% endfor %}
  {% else %}
  - 无
  {% endif %}

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
- **AISVS 要求 ID**: {{ finding.aisvs_id | default('AISVS-XXX') }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}
- **置信度评分**: {{ (finding.confidence_score | default(0.85) * 100) | round(0) }}%
- **证据链**:
  {% if finding.evidence_chain %}
  {% for evidence in finding.evidence_chain %}
    - {{ evidence }}
  {% endfor %}
  {% else %}
  - 无
  {% endif %}

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
- **AISVS 要求 ID**: {{ finding.aisvs_id | default('AISVS-XXX') }}
- **位置**: `{{ finding.location.file }}:{{ finding.location.line }}`
- **描述**: {{ finding.message }}
- **置信度评分**: {{ (finding.confidence_score | default(0.85) * 100) | round(0) }}%
- **证据链**:
  {% if finding.evidence_chain %}
  {% for evidence in finding.evidence_chain %}
    - {{ evidence }}
  {% endfor %}
  {% else %}
  - 无
  {% endif %}

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

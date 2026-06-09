# Case Study Template

> **Classification**: [ILLUSTRATIVE | VERIFIED | ANONYMIZED]
> **Date**: YYYY-MM-DD
> **HOS-LS Version**: vX.Y.Z

---

## 1. Executive Summary

One-paragraph summary of the case study, including:
- Project type and size
- Key findings (number and severity)
- Main outcome or insight
- Time/cost savings compared to baseline

---

## 2. Project Background

| Attribute | Detail |
|-----------|--------|
| **Project Type** | [e.g., E-Commerce Platform, SaaS API, Mobile Backend] |
| **Framework** | [e.g., Spring Boot 3.1.x, Django 4.2, Express.js] |
| **Languages** | [e.g., Java 17 (primary), JavaScript/React] |
| **Codebase Size** | [e.g., 320,000 lines of code] |
| **Architecture** | [e.g., Microservices, Monolith, Serverless] |
| **Dependencies** | [e.g., 87 Maven dependencies, 42 npm packages] |
| **Database** | [e.g., PostgreSQL 15, Redis] |
| **CI/CD** | [e.g., GitHub Actions, Jenkins] |
| **Team Size** | [e.g., 12 developers] |

### 2.1 Technology Stack

List the primary technologies, frameworks, and infrastructure components.

### 2.2 Security Maturity (Pre-Scan Assessment)

| Area | Maturity Level | Notes |
|------|---------------|-------|
| SAST Integration | [Low/Medium/High] | [Notes] |
| Dependency Scanning | [Low/Medium/High] | [Notes] |
| Security Reviews | [Low/Medium/High] | [Notes] |
| Penetration Testing | [Low/Medium/High] | [Notes] |
| Developer Training | [Low/Medium/High] | [Notes] |

---

## 3. Scan Configuration

### 3.1 HOS-LS Settings

| Parameter | Value |
|-----------|-------|
| **Scan Mode** | [e.g., Full Repository Scan, Incremental Scan, PR Scan] |
| **AI Model** | [e.g., Multi-agent (3-agent: Scanner + Validator + Context Analyzer)] |
| **LLM Provider** | [e.g., Claude 3.5 Sonnet (primary) + GPT-4o (fallback)] |
| **Token Budget** | [e.g., 2.4M tokens] |
| **Actual Token Usage** | [e.g., 1.87M tokens] |
| **Scan Duration** | [e.g., 47 minutes] |
| **Files Scanned** | [e.g., 842 files] |
| **Code Graph Nodes** | [e.g., 128,450] |
| **Data Flow Paths Analyzed** | [e.g., 3,247] |

### 3.2 Scan Phases

| Phase | Duration | Description |
|-------|----------|-------------|
| Phase 1: Indexing | [X min] | [Description] |
| Phase 2: Pattern Scanning | [X min] | [Description] |
| Phase 3: AI Deep Analysis | [X min] | [Description] |
| Phase 4: Report Generation | [X min] | [Description] |

---

## 4. Scan Results

### 4.1 Findings by Severity

| Severity | Count | Percentage | Description |
|----------|-------|------------|-------------|
| **CRITICAL** | [N] | [X%] | [Description] |
| **HIGH** | [N] | [X%] | [Description] |
| **MEDIUM** | [N] | [X%] | [Description] |
| **LOW** | [N] | [X%] | [Description] |
| **TOTAL** | **[N]** | **100%** | - |

### 4.2 Findings by Category

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| [Category 1] | N | N | N | N | N |
| [Category 2] | N | N | N | N | N |

### 4.3 Critical/High Findings Detail

For each critical or high severity finding:

#### [F-ID]: [Finding Title]

**Location**: [File:Line]

**Description**: [Brief description of the vulnerability]

**HOS-LS Analysis**: [How HOS-LS identified this finding, including which agent(s) were involved]

**CVSS 3.1 Score**: [Score] ([Severity])
**OWASP Category**: [e.g., A03:2021 - Injection]
**CWE**: [e.g., CWE-89: SQL Injection]

### 4.4 AI False Positive Analysis

| Metric | Value |
|--------|-------|
| Total AI-Generated Findings | N |
| True Positives (validated) | N |
| False Positives | N |
| **False Positive Rate** | **X%** |
| Post-Validator Agent FP Rate | X% |

---

## 5. Remediation Effectiveness

### 5.1 HOS-LS Remediation Suggestions

For each finding, HOS-LS provided:
1. Root Cause Analysis
2. Code-Level Fix (before/after)
3. Security Principle reference
4. Testing Guidance

### 5.2 Remediation Implementation

| Severity | Findings | Remediated | Time to Remediate | Notes |
|----------|----------|------------|-------------------|-------|
| Critical | N | N | [time] | [notes] |
| High | N | N | [time] | [notes] |
| Medium | N | N | [time] | [notes] |
| Low | N | N | [time] | [notes] |

### 5.3 Example Remediation

Show a before/after code example for one representative finding.

**Before** (vulnerable):
```[language]
// vulnerable code
```

**After** (remediated):
```[language]
// fixed code
```

**Verification**: [How the fix was verified]

---

## 6. Efficiency Comparison: HOS-LS vs. Baseline

### 6.1 Time Analysis

| Activity | HOS-LS | Baseline (Manual/Traditional Tool) |
|----------|--------|-----------------------------------|
| Initial scan/audit | [time] | [time] |
| Finding triage | [time] | [time] |
| Remediation guidance | [time] | [time] |
| Verification re-scan | [time] | [time] |
| **Total** | **[time]** | **[time]** |

### 6.2 Coverage Analysis

| Metric | HOS-LS | Baseline |
|--------|--------|----------|
| Files analyzed | N / N (X%) | N / N (X%) |
| Code paths traced | N | N |
| Dependencies checked | N | N |
| Vulnerability types covered | N CWE categories | N CWE categories |
| **Total vulnerabilities found** | **N** | **N** |
| **Coverage ratio** | **X.x** | **1.0x (baseline)** |

### 6.3 Cost Comparison

| Factor | HOS-LS | Baseline |
|--------|--------|----------|
| Direct cost | [$X] | [$X] |
| Internal engineering time | [X hours] | [X hours] |
| Opportunity cost | [Low/Medium/High] | [Low/Medium/High] |
| **Total cost** | **[$X + Xh]** | **[$X + Xh]** |

---

## 7. Key Insights

### 7.1 What HOS-LS Did Well

1. [Strength 1 with specific example]
2. [Strength 2 with specific example]
3. [Strength 3 with specific example]

### 7.2 Areas for Improvement

1. [Area 1 with specific example]
2. [Area 2 with specific example]
3. [Area 3 with specific example]

### 7.3 Recommendations for the Project Team

1. [Recommendation 1]
2. [Recommendation 2]
3. [Recommendation 3]

---

## 8. Conclusion

One-paragraph summary of key takeaways, including:
- Number of vulnerabilities found and their severity
- Time/cost savings achieved
- Key insights about HOS-LS effectiveness
- Any caveats or limitations

---

## 9. Data Disclaimer (For Illustrative Case Studies)

*This case study contains simulated/illustrative data constructed from publicly known vulnerability patterns and industry-standard benchmarks. It is intended for demonstration and educational purposes only. Actual results may vary based on project complexity, code quality, and configuration.*

---

*Last Updated: YYYY-MM-DD*

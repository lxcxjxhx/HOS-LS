# HOS-LS Benchmark Comparison

Comprehensive benchmark comparison of HOS-LS against industry-standard code security scanning tools.

> **Important Disclaimer**: All benchmark values in this document are **illustrative estimates** based on published industry data, vendor documentation, and internal testing. Actual results vary significantly based on project size, codebase complexity, language mix, configuration, and hardware. Independent validation is recommended before procurement decisions.

---

## Table of Contents

- [Benchmark Summary](#benchmark-summary)
- [Detailed Comparison](#detailed-comparison)
- [Scanning Speed](#scanning-speed)
- [False Positive Rate](#false-positive-rate)
- [Detection Rate / Recall](#detection-rate--recall)
- [Token Efficiency](#token-efficiency)
- [Setup Complexity](#setup-complexity)
- [Language Support](#language-support)
- [Custom Rule Support](#custom-rule-support)
- [Feature Matrix](#feature-matrix)
- [Cost Comparison](#cost-comparison)
- [Test Methodology](#test-methodology)
- [Limitations & Notes](#limitations--notes)

---

## Benchmark Summary

| Dimension | HOS-LS | Semgrep | SonarQube | CodeQL |
|-----------|:------:|:-------:|:---------:|:------:|
| **Scanning Speed** | 50-200 files/min | 500-2000 files/min | 200-800 files/min | 50-300 files/min |
| **False Positive Rate** | <5% | 20-40% | 15-30% | 10-25% |
| **Detection Rate (Recall)** | 80-92% | 60-85% | 55-80% | 65-88% |
| **Token Efficiency** | 60-70% reduction vs naive | N/A (rule-based) | N/A (rule-based) | N/A (rule-based) |
| **Setup Complexity** | Easy | Easy | Hard | Medium |
| **Language Support** | 7+ languages | 30+ languages | 25+ languages | 15+ languages |
| **Custom Rule Support** | Yes (YAML + AI prompt) | Yes (YAML) | Yes (Java plugins) | Yes (QL language) |
| **AI-Powered Analysis** | Yes (7-agent pipeline) | No (rule-based) | Partial (AI-assisted) | No (rule-based) |
| **Price** | Free (open source) | $1,500+/yr | $3,000+/yr | Free |

---

## Detailed Comparison

### Scanning Speed

| Tool | Speed | Notes |
|------|-------|-------|
| **Semgrep** | 500-2000 files/min | Fastest - pure AST pattern matching, highly optimized OCaml engine |
| **SonarQube** | 200-800 files/min | Moderate - full AST + data flow analysis, Java-based JVM overhead |
| **CodeQL** | 50-300 files/min | Slower - complex taint analysis, database creation step required |
| **HOS-LS** | 50-200 files/min | Variable - AI API latency is primary bottleneck; local analysis is fast |

**Where competitors excel**: Semgrep is significantly faster for large codebases due to its optimized OCaml engine and rule-based approach. For organizations scanning millions of LOC, Semgrep's speed advantage is substantial.

**HOS-LS trade-off**: AI analysis introduces API latency, but this is offset by:
- Incremental scanning (only changed files)
- Parallel agent processing
- Intelligent file prioritization
- Caching of analysis results

---

### False Positive Rate

| Tool | False Positive Rate | Why |
|------|---------------------|-----|
| **HOS-LS** | <5% | Multi-agent AI verification, framework pattern recognition, attack chain validation |
| **CodeQL** | 10-25% | Taint analysis reduces FPs, but requires expert rule tuning |
| **SonarQube** | 15-30% | Broad rule coverage generates many low-confidence findings |
| **Semgrep** | 20-40% | Pattern matching cannot understand context or code intent |

**Where competitors excel**: CodeQL achieves lower false positive rates than Semgrep and SonarQube when expertly configured with custom taint tracking rules. CodeQL's QL language allows precise vulnerability modeling.

**Context matters**: False positive rates for all tools depend heavily on:
- Rule set selection (strict vs. comprehensive)
- Language-specific tuning
- Project architecture complexity
- Quality of code being scanned

---

### Detection Rate / Recall

| Tool | Detection Rate | Coverage |
|------|---------------|----------|
| **CodeQL** | 65-88% | Excellent for known vulnerability patterns with well-configured taint tracking |
| **HOS-LS** | 80-92% | Strong semantic understanding catches context-dependent vulnerabilities |
| **Semgrep** | 60-85% | Good coverage of common patterns; limited for complex business logic |
| **SonarQube** | 55-80% | Broad coverage but struggles with framework-specific and complex flows |

**Where competitors excel**: CodeQL has the best detection rate for taint-style vulnerabilities (SQLi, XSS, command injection) when custom taint tracking rules are properly configured. Semgrep has the largest community rule library.

---

### Token Efficiency

| Tool | Token Efficiency | Approach |
|------|-----------------|----------|
| **HOS-LS** | 60-70% reduction vs naive prompt | Compressed prompts, code graph context, RAG knowledge base |
| **Semgrep** | N/A | Rule-based, no AI tokens |
| **SonarQube** | N/A | Rule-based, no AI tokens |
| **CodeQL** | N/A | Rule-based, no AI tokens |

**Note**: Token efficiency is only relevant for AI-based analysis tools. HOS-LS's token optimization reduces API costs by 60-70% compared to sending full file context to LLMs.

---

### Setup Complexity

| Tool | Complexity | Time to First Scan | Notes |
|------|-----------|-------------------|-------|
| **HOS-LS** | Easy | 5-15 minutes | `pip install` + API key + `hos scan` |
| **Semgrep** | Easy | 2-5 minutes | `pip install` + `semgrep scan` |
| **CodeQL** | Medium | 30-60 minutes | Database creation, query selection, CLI learning |
| **SonarQube** | Hard | 1-4 hours | Server setup, database, configuration, rule tuning |

---

### Language Support

| Language | HOS-LS | Semgrep | SonarQube | CodeQL |
|----------|:------:|:-------:|:---------:|:------:|
| Python | Yes | Yes | Yes | Yes |
| JavaScript | Yes | Yes | Yes | Yes |
| TypeScript | Yes | Yes | Yes | Yes |
| Java | Yes | Yes | Yes | Yes |
| Go | Yes | Yes | Yes | No |
| Rust | Yes | Yes | No | No |
| C/C++ | Partial | Yes | Yes | Yes |
| Ruby | No | Yes | Yes | No |
| PHP | No | Yes | Yes | No |
| C# | No | Yes | Yes | Yes |
| Kotlin | No | Partial | Yes | Partial |
| Swift | No | Yes | Yes | No |
| **Total** | **7+** | **30+** | **25+** | **15+** |

**Where competitors excel**: Semgrep has the broadest language support (30+ languages). SonarQube also supports a wide range with enterprise coverage. If you need multi-language scanning in a polyglot repository, Semgrep or SonarQube may be better choices.

---

### Custom Rule Support

| Tool | Custom Rule Format | Difficulty | AI Support |
|------|-------------------|------------|------------|
| **Semgrep** | YAML | Easy | No |
| **CodeQL** | QL language | Hard | No |
| **SonarQube** | Java plugins | Hard | Partial |
| **HOS-LS** | YAML + AI prompts | Medium | Yes (AI can help write rules) |

---

## Feature Matrix

| Feature | HOS-LS | Semgrep | SonarQube | CodeQL |
|---------|:------:|:-------:|:---------:|:------:|
| Multi-agent AI analysis | Yes | No | Partial | No |
| Semantic code graph | Yes | No | No | No |
| Call graph analysis | Yes | No | No | Partial |
| Attack chain validation | Yes | No | No | No |
| Framework pattern recognition | Yes | Partial | Partial | No |
| CI/CD integration | Yes | Yes | Yes | Yes |
| GitHub Actions | Yes | Yes | Yes | Yes |
| SARIF output | Yes | Yes | Yes | Yes |
| IDE integration | Planned | Yes | Yes | Yes |
| SBOM generation | No | No | Yes | No |
| Dependency scanning | No | Yes | Yes | No |
| Secret detection | Yes | Yes | Yes | No |
| License compliance | No | No | Yes | No |
| Team dashboard | No | Yes | Yes | No |
| Custom rule engine | Yes | Yes | Yes | Yes |
| Offline scanning | No | Yes | Yes | Yes |

---

## Cost Comparison

| Tool | Pricing Model | Estimated Annual Cost (10 devs) |
|------|--------------|--------------------------------|
| **HOS-LS** | Free (open source) | $0 (tool) + $500-2000 (AI API usage) |
| **Semgrep OSS** | Free tier | $0 (limited features) |
| **Semgrep Pro** | Subscription | $15,000-25,000 |
| **SonarQube Community** | Free | $0 (limited features) |
| **SonarQube Enterprise** | Subscription | $30,000-50,000 |
| **CodeQL** | Free (GitHub Advanced Security) | $0 (included in GHAS) or $216/user/yr |

**Note**: HOS-LS AI API costs depend on scanning volume, model selection, and token efficiency settings. Using compressed prompts and caching can significantly reduce costs.

---

## Test Methodology

### Benchmark Test Configuration

| Parameter | Value |
|-----------|-------|
| Test codebase | OWASP Benchmark (Java), Damn Vulnerable Web App, 5 open-source projects |
| Total files | 5,000-10,000 files |
| Total LOC | 500K-1M lines of code |
| Languages | Java, Python, JavaScript |
| Hardware | 8-core CPU, 16GB RAM |
| Network | Stable broadband (for AI API calls) |

### Scoring Methodology

- **False Positive Rate**: False Positives / (True Positives + False Positives)
- **Detection Rate**: True Positives / (True Positives + False Negatives)
- **Scanning Speed**: Files scanned per minute (warm start, cached dependencies)
- **Token Efficiency**: Tokens used vs. naive prompt approach (for AI tools only)

### Known Vulnerable Patterns Tested

| Category | Patterns Tested |
|----------|----------------|
| Injection | SQLi, XSS, Command Injection, LDAP Injection |
| Authentication | Hardcoded credentials, weak auth bypass |
| Cryptography | Weak algorithms, hardcoded keys, insecure random |
| Data Exposure | Sensitive data in logs, hardcoded secrets |
| Deserialization | Java object deserialization, YAML unsafe load |

---

## Limitations & Notes

### Benchmark Limitations

1. **Illustrative Values**: All numeric values are estimates based on published industry data, vendor documentation, and internal testing. They should NOT be used as definitive performance guarantees.

2. **Configuration Dependency**: Results vary significantly based on:
   - Rule set selection and customization
   - Language-specific tuning
   - Threshold settings (confidence, severity)
   - Exclusion patterns

3. **Project Dependency**: Results vary based on:
   - Codebase architecture (monolith vs. microservices)
   - Framework usage (Spring, Django, Express, etc.)
   - Code quality (legacy vs. modern code)
   - Test coverage

4. **AI API Latency**: HOS-LS performance depends on AI provider response times. Network conditions, API rate limits, and model selection all affect scan duration.

5. **Evolving Benchmarks**: AI models improve continuously. Benchmark values reflect capabilities at time of writing and should be re-evaluated regularly.

### Recommendations for Independent Validation

Before making procurement decisions:
1. Run all tools against your own codebase
2. Validate findings with manual code review
3. Measure false positive rates in your specific context
4. Calculate total cost of ownership (tool + developer time)
5. Evaluate integration with your CI/CD pipeline

### Contributing Benchmark Data

If you have conducted independent benchmarking, please contribute:
- GitHub Issue: [Create Issue](https://github.com/hos-ls/hos-ls/issues)
- Pull Request: Submit benchmark results with methodology
- Email: security@hos-ls.com

---

*Last updated: 2026-05-25 | Version: v0.3.4.0*

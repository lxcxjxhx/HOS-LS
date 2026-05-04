"""动态分析模块

提供污点追踪、漏洞分析和 payload 生成功能。
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class DynamicOptions:
    """动态分析配置"""

    enable_taint_tracking: bool = True
    enable_payload_generation: bool = True
    timeout: int = 30
    memory_limit: int = 512 * 1024 * 1024


@dataclass
class TaintFlowResult:
    """污点流分析结果"""

    source: str
    sink: str
    path: List[str] = field(default_factory=list)
    is_safe: bool = True
    payload: Optional[str] = None
    execution_result: Optional[str] = None


class DynamicAnalyzer:
    """动态分析器

    支持污点追踪、漏洞检测和 payload 生成。
    """

    DANGEROUS_SINKS: Dict[str, List[Tuple[str, str]]] = {
        "sql_injection": [
            ("execute", "执行 SQL 查询"),
            ("executemany", "批量执行 SQL"),
            ("cursor.execute", "游标执行 SQL"),
            ("query", "数据库查询"),
            ("raw", "原生 SQL 查询"),
        ],
        "command_injection": [
            ("system", "执行系统命令"),
            ("popen", "打开管道执行命令"),
            ("exec", "执行命令"),
            ("spawn", "生成进程"),
            ("run", "运行命令"),
        ],
        "path_traversal": [
            ("open", "打开文件"),
            ("read", "读取文件"),
            ("write", "写入文件"),
            ("file", "文件操作"),
            ("path", "路径操作"),
        ],
        "xss": [
            ("write", "写入输出"),
            ("print", "打印输出"),
            ("html", "HTML 输出"),
            ("innerHTML", "DOM 操作"),
            ("document.write", "文档写入"),
        ],
        "xxe": [
            ("parse", "解析 XML"),
            ("etree.parse", "XML 树解析"),
            ("ElementTree.parse", "ET 解析"),
        ],
        "ssrf": [
            ("request", "发送请求"),
            ("fetch", "获取资源"),
            ("urlopen", "打开 URL"),
            ("get", "HTTP GET"),
            ("post", "HTTP POST"),
        ],
        "deserialization": [
            ("pickle.loads", "反序列化 pickle"),
            ("yaml.load", "反序列化 YAML"),
            ("json.loads", "反序列化 JSON"),
            ("marshal.loads", "反序列化 marshal"),
        ],
    }

    TAINT_SOURCES: List[Tuple[str, str]] = [
        ("input", "用户输入"),
        ("request", "HTTP 请求"),
        ("args", "命令行参数"),
        ("stdin", "标准输入"),
        ("env", "环境变量"),
        ("cookies", "Cookie 数据"),
        ("headers", "HTTP 头"),
        ("body", "请求体"),
    ]

    def __init__(self, options: Optional[DynamicOptions] = None):
        """初始化动态分析器

        Args:
            options: 动态分析配置
        """
        self.options = options or DynamicOptions()
        self._tainted_variables: Set[str] = set()
        self._analysis_history: List[TaintFlowResult] = []

    def analyze_vulnerability(
        self,
        code: str,
        vulnerability_type: str,
        language: str = "python",
    ) -> List[TaintFlowResult]:
        """分析漏洞可利用性

        Args:
            code: 待分析的代码
            vulnerability_type: 漏洞类型
            language: 编程语言

        Returns:
            污点流分析结果列表
        """
        if not self.options.enable_taint_tracking:
            return []

        results: List[TaintFlowResult] = []

        if vulnerability_type not in self.DANGEROUS_SINKS:
            return results

        sinks = self.DANGEROUS_SINKS[vulnerability_type]

        for source_pattern, source_desc in self.TAINT_SOURCES:
            source_matches = self._find_source_in_code(code, source_pattern, language)

            for sink_func, sink_desc in sinks:
                sink_matches = self._find_sink_in_code(code, sink_func, language)

                for source_match in source_matches:
                    for sink_match in sink_matches:
                        path = self._trace_taint_flow(
                            code, source_match, sink_match, language
                        )

                        is_safe = len(path) == 0

                        result = TaintFlowResult(
                            source=f"{source_pattern} ({source_desc})",
                            sink=f"{sink_func} ({sink_desc})",
                            path=path,
                            is_safe=is_safe,
                        )

                        if not is_safe and self.options.enable_payload_generation:
                            result.payload = self.generate_payload(
                                vulnerability_type, path
                            )

                        results.append(result)
                        self._analysis_history.append(result)

        return results

    def generate_payload(self, vulnerability_type: str, path: List[str]) -> Optional[str]:
        """为各种漏洞类型生成测试 payload

        Args:
            vulnerability_type: 漏洞类型
            path: 传播路径

        Returns:
            生成的 payload
        """
        if not self.options.enable_payload_generation:
            return None

        payloads = {
            "sql_injection": "' OR '1'='1",
            "command_injection": "; ls -la",
            "path_traversal": "../../../etc/passwd",
            "xss": "<script>alert('XSS')</script>",
            "xxe": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "ssrf": "http://localhost:22",
            "deserialization": "pickle payload",
        }

        base_payload = payloads.get(vulnerability_type, "test_payload")

        if path:
            modified_payloads = []
            for i, step in enumerate(path):
                if "concat" in step.lower() or "format" in step.lower():
                    modified_payloads.append(f"{base_payload} (at step {i})")
                else:
                    modified_payloads.append(base_payload)
            return " -> ".join(modified_payloads) if modified_payloads else base_payload

        return base_payload

    def wrap_code_with_tracking(
        self,
        code: str,
        language: str = "python",
    ) -> str:
        """为代码添加污点追踪包装

        Args:
            code: 原始代码
            language: 编程语言

        Returns:
            添加了污点追踪的代码
        """
        if not self.options.enable_taint_tracking:
            return code

        if language.lower() == "python":
            return self._wrap_python_code(code)
        elif language.lower() in ("javascript", "typescript"):
            return self._wrap_javascript_code(code)
        elif language.lower() == "java":
            return self._wrap_java_code(code)
        elif language.lower() == "go":
            return self._wrap_go_code(code)
        elif language.lower() == "rust":
            return self._wrap_rust_code(code)
        elif language.lower() == "c":
            return self._wrap_c_code(code)

        return code

    def _wrap_python_code(self, code: str) -> str:
        """包装 Python 代码"""
        wrapper_template = '''
import sys

_TAINTED_VARS = set()
_TAINT_TRACKING_ENABLED = True

def _mark_tainted(var_name):
    if _TAINT_TRACKING_ENABLED:
        _TAINTED_VARS.add(var_name)
        print(f"[TAINT] Variable tainted: {{var_name}}", file=sys.stderr)

def _check_tainted(var_name, operation):
    if var_name in _TAINTED_VARS:
        print(f"[TAINT WARNING] Tainted variable '{{var_name}}' used in {{operation}}", file=sys.stderr)
        return True
    return False

{original_code}

if __name__ == "__main__":
    main()
'''
        return wrapper_template.format(original_code=code)

    def _wrap_javascript_code(self, code: str) -> str:
        """包装 JavaScript/TypeScript 代码"""
        wrapper_template = '''
const _TAINTED_VARS = new Set();
const _TAINT_TRACKING_ENABLED = true;

function _markTainted(varName) {{
    if (_TAINT_TRACKING_ENABLED) {{
        _TAINTED_VARS.add(varName);
        console.error(`[TAINT] Variable tainted: ${{varName}}`);
    }}
}}

function _checkTainted(varName, operation) {{
    if (_TAINTED_VARS.has(varName)) {{
        console.error(`[TAINT WARNING] Tainted variable '${{varName}}' used in ${{operation}}`);
        return true;
    }}
    return false;
}}

{original_code}
'''
        return wrapper_template.format(original_code=code)

    def _wrap_java_code(self, code: str) -> str:
        """包装 Java 代码"""
        wrapper_template = '''
import java.util.Set;
import java.util.HashSet;

public class TaintTracker {{
    private static Set<String> taintedVars = new HashSet<>();
    private static boolean TAINT_TRACKING_ENABLED = true;

    public static void markTainted(String varName) {{
        if (TAINT_TRACKING_ENABLED) {{
            taintedVars.add(varName);
            System.err.println("[TAINT] Variable tainted: " + varName);
        }}
    }}

    public static boolean checkTainted(String varName, String operation) {{
        if (taintedVars.contains(varName)) {{
            System.err.println("[TAINT WARNING] Tainted variable '" + varName + "' used in " + operation);
            return true;
        }}
        return false;
    }}

    public static void main(String[] args) {{
        // User code would be injected here
    }}
}}

{original_code}
'''
        return wrapper_template.format(original_code=code)

    def _wrap_go_code(self, code: str) -> str:
        """包装 Go 代码"""
        wrapper_template = '''
package main

import (
    "fmt"
    "sync"
)

var (
    taintedVars = make(map[string]bool)
    mu sync.RWMutex
    taintTrackingEnabled = true
)

func markTainted(varName string) {{
    if taintTrackingEnabled {{
        mu.Lock()
        taintedVars[varName] = true
        mu.Unlock()
        fmt.Printf("[TAINT] Variable tainted: %s\\n", varName)
    }}
}}

func checkTainted(varName, operation string) bool {{
    mu.RLock()
    isTainted := taintedVars[varName]
    mu.RUnlock()
    if isTainted {{
        fmt.Printf("[TAINT WARNING] Tainted variable '%s' used in %s\\n", varName, operation)
        return true
    }}
    return false
}}

{original_code}
'''
        return wrapper_template.format(original_code=code)

    def _wrap_rust_code(self, code: str) -> str:
        """包装 Rust 代码"""
        wrapper_template = '''
use std::collections::HashSet;
use std::sync::Mutex;

struct TaintTracker {{
    tainted_vars: Mutex<HashSet<String>>,
    enabled: bool,
}}

impl TaintTracker {{
    fn new() -> Self {{
        TaintTracker {{
            tainted_vars: Mutex::new(HashSet::new()),
            enabled: true,
        }}
    }}

    fn mark_tainted(&self, var_name: &str) {{
        if self.enabled {{
            let mut vars = self.tainted_vars.lock().unwrap();
            vars.insert(var_name.to_string());
            eprintln!("[TAINT] Variable tainted: {{}}", var_name);
        }}
    }}

    fn check_tainted(&self, var_name: &str, operation: &str) -> bool {{
        let vars = self.tainted_vars.lock().unwrap();
        let is_tainted = vars.contains(var_name);
        if is_tainted {{
            eprintln!("[TAINT WARNING] Tainted variable '{{}}' used in {{}}", var_name, operation);
        }}
        is_tainted
    }}
}}

static TRACKER: TaintTracker = TaintTracker::new();

{original_code}
'''
        return wrapper_template.format(original_code=code)

    def _wrap_c_code(self, code: str) -> str:
        """包装 C 代码"""
        wrapper_template = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_TAINTED_VARS 100
#define MAX_VAR_NAME_LEN 100

typedef struct {{
    char vars[MAX_TAINTED_VARS][MAX_VAR_NAME_LEN];
    int count;
    bool enabled;
}} TaintTracker;

TaintTracker tracker = {{
    .count = 0,
    .enabled = true
}};

void mark_tainted(const char* var_name) {{
    if (tracker.enabled && tracker.count < MAX_TAINTED_VARS) {{
        strncpy(tracker.vars[tracker.count++], var_name, MAX_VAR_NAME_LEN - 1);
        fprintf(stderr, "[TAINT] Variable tainted: %s\\n", var_name);
    }}
}}

bool check_tainted(const char* var_name, const char* operation) {{
    for (int i = 0; i < tracker.count; i++) {{
        if (strcmp(tracker.vars[i], var_name) == 0) {{
            fprintf(stderr, "[TAINT WARNING] Tainted variable '%s' used in %s\\n", var_name, operation);
            return true;
        }}
    }}
    return false;
}}

{original_code}
'''
        return wrapper_template.format(original_code=code)

    def _find_source_in_code(
        self,
        code: str,
        source_pattern: str,
        language: str,
    ) -> List[Dict[str, Any]]:
        """在代码中查找污点源"""
        matches = []
        pattern = self._get_source_pattern(source_pattern, language)

        for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
            matches.append({
                "match": match.group(0),
                "line": code[:match.start()].count("\n") + 1,
                "column": match.start(),
            })

        return matches

    def _find_sink_in_code(
        self,
        code: str,
        sink_pattern: str,
        language: str,
    ) -> List[Dict[str, Any]]:
        """在代码中查找危险函数"""
        matches = []
        pattern = self._get_sink_pattern(sink_pattern, language)

        for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
            matches.append({
                "match": match.group(0),
                "line": code[:match.start()].count("\n") + 1,
                "column": match.start(),
            })

        return matches

    def _get_source_pattern(self, source: str, language: str) -> str:
        """获取污点源的正则表达式"""
        if language.lower() == "python":
            patterns = {
                "input": r"input\s*\(",
                "request": r"request\.(args|form|values|get)",
                "args": r"sys\.argv",
                "stdin": r"sys\.stdin",
                "env": r"os\.environ",
                "cookies": r"request\.cookies",
                "headers": r"request\.headers",
                "body": r"request\.data|request\.body",
            }
        elif language.lower() in ("javascript", "typescript"):
            patterns = {
                "input": r"(?:readline|prompt)\s*\(",
                "request": r"req\.(body|params|query|headers)",
                "args": r"process\.argv",
                "stdin": r"process\.stdin",
                "env": r"process\.env",
                "cookies": r"req\.cookies",
                "headers": r"req\.headers",
                "body": r"req\.body",
            }
        else:
            patterns = {
                "input": rf"\b{source}\s*\(",
                "request": rf"\b{source}\b",
                "args": rf"\b{source}\b",
                "stdin": rf"\b{source}\b",
                "env": rf"\b{source}\b",
                "cookies": rf"\b{source}\b",
                "headers": rf"\b{source}\b",
                "body": rf"\b{source}\b",
            }

        return patterns.get(source, rf"\b{source}\b")

    def _get_sink_pattern(self, sink: str, language: str) -> str:
        """获取危险函数的正则表达式"""
        if language.lower() == "python":
            return rf"\b{sink}\s*\("
        elif language.lower() in ("javascript", "typescript"):
            return rf"\b{sink}\s*\("
        elif language.lower() == "java":
            return rf"\b{sink}\s*\("
        elif language.lower() == "go":
            return rf"\b{sink}\s*\("
        elif language.lower() == "rust":
            return rf"\b{sink}\s*\("
        elif language.lower() == "c":
            return rf"\b{sink}\s*\("
        else:
            return rf"\b{sink}\s*\("

    def _trace_taint_flow(
        self,
        code: str,
        source: Dict[str, Any],
        sink: Dict[str, Any],
        language: str,
    ) -> List[str]:
        """追踪污点从源到汇的传播路径"""
        path = []

        if source["line"] > sink["line"]:
            return path

        lines = code.split("\n")

        var_assignments = self._extract_variable_assignments(
            lines[source["line"] - 1 : sink["line"]]
        )

        for var, assign_line in var_assignments:
            if source["line"] <= assign_line <= sink["line"]:
                path.append(f"Variable '{var}' assigned at line {assign_line}")

        if path:
            path.insert(0, f"Taint source: {source['match']} at line {source['line']}")
            path.append(f"Taint sink: {sink['match']} at line {sink['line']}")

        return path

    def _extract_variable_assignments(
        self,
        lines: List[str],
    ) -> List[Tuple[str, int]]:
        """提取变量赋值"""
        assignments = []
        pattern = r"(\w+)\s*="

        for i, line in enumerate(lines):
            for match in re.finditer(pattern, line):
                var_name = match.group(1)
                if not var_name.startswith("_"):
                    assignments.append((var_name, i + 1))

        return assignments

    def get_analysis_history(self) -> List[TaintFlowResult]:
        """获取分析历史

        Returns:
            分析结果历史
        """
        return self._analysis_history

    def clear_history(self) -> None:
        """清除分析历史"""
        self._analysis_history.clear()
        self._tainted_variables.clear()

    def clear_cache(self) -> None:
        """清除编译缓存（如果有）"""
        self._tainted_variables.clear()

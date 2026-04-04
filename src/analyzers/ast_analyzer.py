"""AST 分析器模块

基于 tree-sitter 的抽象语法树分析器。
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from tree_sitter import Language, Parser, Tree

from src.analyzers.base import (
    AnalysisContext,
    AnalysisError,
    AnalysisIssue,
    AnalysisResult,
    AnalysisStatus,
    AnalysisType,
    BaseAnalyzer,
    Severity,
)


class ASTAnalyzer(BaseAnalyzer):
    """AST 分析器

    使用 tree-sitter 进行抽象语法树分析。
    """

    name = "ast_analyzer"
    version = "1.1.0"
    supported_languages = ["python", "javascript", "typescript", "java", "cpp", "c", "go", "rust", "php"]
    supported_analysis_types = [AnalysisType.AST, AnalysisType.SECURITY, AnalysisType.CODE_QUALITY]

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, Language] = {}
        self._dangerous_functions: Dict[str, Dict[str, str]] = {
            "python": {
                "eval": "使用 eval() 可能导致代码注入漏洞",
                "exec": "使用 exec() 可能导致代码注入漏洞",
                "execfile": "使用 execfile() 可能导致代码注入漏洞",
                "input": "使用 input() 在 Python 2 中可能导致安全问题",
                "raw_input": "使用 raw_input() 可能导致安全问题",
                "open": "使用 open() 可能导致路径遍历漏洞",
                "file": "使用 file() 可能导致路径遍历漏洞",
                "__import__": "使用 __import__() 可能导致代码注入漏洞",
                "getattr": "使用 getattr() 可能导致代码注入漏洞",
                "setattr": "使用 setattr() 可能导致代码注入漏洞",
                "delattr": "使用 delattr() 可能导致代码注入漏洞",
                "globals": "使用 globals() 可能导致代码注入漏洞",
                "locals": "使用 locals() 可能导致代码注入漏洞",
                "vars": "使用 vars() 可能导致代码注入漏洞",
                "compile": "使用 compile() 可能导致代码注入漏洞",
                "exec_compiled": "使用 exec_compiled() 可能导致代码注入漏洞",
                "subprocess.Popen": "使用 subprocess.Popen() 可能导致命令注入漏洞",
                "subprocess.call": "使用 subprocess.call() 可能导致命令注入漏洞",
                "subprocess.run": "使用 subprocess.run() 可能导致命令注入漏洞",
                "os.system": "使用 os.system() 可能导致命令注入漏洞",
                "os.popen": "使用 os.popen() 可能导致命令注入漏洞",
                "os.exec": "使用 os.exec*() 可能导致命令注入漏洞",
                "os.spawn": "使用 os.spawn*() 可能导致命令注入漏洞",
                "shutil.copy": "使用 shutil.copy() 可能导致路径遍历漏洞",
                "shutil.copy2": "使用 shutil.copy2() 可能导致路径遍历漏洞",
                "shutil.copytree": "使用 shutil.copytree() 可能导致路径遍历漏洞",
                "shutil.move": "使用 shutil.move() 可能导致路径遍历漏洞",
                "shutil.rmtree": "使用 shutil.rmtree() 可能导致路径遍历漏洞",
            },
            "javascript": {
                "eval": "使用 eval() 可能导致代码注入漏洞",
                "new Function": "使用 new Function() 可能导致代码注入漏洞",
                "execScript": "使用 execScript() 可能导致代码注入漏洞",
                "setTimeout": "使用 setTimeout() 可能导致代码注入漏洞",
                "setInterval": "使用 setInterval() 可能导致代码注入漏洞",
                "document.write": "使用 document.write() 可能导致 XSS 漏洞",
                "document.writeln": "使用 document.writeln() 可能导致 XSS 漏洞",
                "innerHTML": "使用 innerHTML 可能导致 XSS 漏洞",
                "outerHTML": "使用 outerHTML 可能导致 XSS 漏洞",
                "insertAdjacentHTML": "使用 insertAdjacentHTML() 可能导致 XSS 漏洞",
                "eval": "使用 eval() 可能导致代码注入漏洞",
                "Function": "使用 Function() 可能导致代码注入漏洞",
                "exec": "使用 exec() 可能导致命令注入漏洞",
                "spawn": "使用 spawn() 可能导致命令注入漏洞",
                "execFile": "使用 execFile() 可能导致命令注入漏洞",
            },
            "java": {
                "Runtime.exec": "使用 Runtime.exec() 可能导致命令注入漏洞",
                "ProcessBuilder.start": "使用 ProcessBuilder.start() 可能导致命令注入漏洞",
                "System.load": "使用 System.load() 可能导致代码注入漏洞",
                "System.loadLibrary": "使用 System.loadLibrary() 可能导致代码注入漏洞",
                "Class.forName": "使用 Class.forName() 可能导致代码注入漏洞",
                "Method.invoke": "使用 Method.invoke() 可能导致代码注入漏洞",
            },
            "cpp": {
                "system": "使用 system() 可能导致命令注入漏洞",
                "popen": "使用 popen() 可能导致命令注入漏洞",
                "exec": "使用 exec() 可能导致命令注入漏洞",
                "fork": "使用 fork() 可能导致安全问题",
                "vfork": "使用 vfork() 可能导致安全问题",
                "strcpy": "使用 strcpy() 可能导致缓冲区溢出",
                "strcat": "使用 strcat() 可能导致缓冲区溢出",
                "sprintf": "使用 sprintf() 可能导致缓冲区溢出",
                "scanf": "使用 scanf() 可能导致缓冲区溢出",
                "gets": "使用 gets() 可能导致缓冲区溢出",
            },
        }

    def initialize(self) -> None:
        """初始化分析器，加载语言库"""
        super().initialize()
        self._load_languages()

    def _load_languages(self) -> None:
        """加载 tree-sitter 语言库"""
        try:
            # Python
            from tree_sitter_python import language as python_language

            self._languages["python"] = Language(python_language())
            self._parsers["python"] = Parser(self._languages["python"])
        except ImportError:
            pass

        try:
            # JavaScript
            from tree_sitter_javascript import language as js_language

            self._languages["javascript"] = Language(js_language())
            self._languages["typescript"] = Language(js_language())
            self._parsers["javascript"] = Parser(self._languages["javascript"])
            self._parsers["typescript"] = Parser(self._languages["typescript"])
        except ImportError:
            pass

        try:
            # Java
            from tree_sitter_java import language as java_language

            self._languages["java"] = Language(java_language())
            self._parsers["java"] = Parser(self._languages["java"])
        except ImportError:
            pass

        try:
            # C/C++
            from tree_sitter_cpp import language as cpp_language

            self._languages["cpp"] = Language(cpp_language())
            self._languages["c"] = Language(cpp_language())
            self._parsers["cpp"] = Parser(self._languages["cpp"])
            self._parsers["c"] = Parser(self._languages["c"])
        except ImportError:
            pass

        try:
            # Go
            from tree_sitter_go import language as go_language

            self._languages["go"] = Language(go_language())
            self._parsers["go"] = Parser(self._languages["go"])
        except ImportError:
            pass

        try:
            # Rust
            from tree_sitter_rust import language as rust_language

            self._languages["rust"] = Language(rust_language())
            self._parsers["rust"] = Parser(self._languages["rust"])
        except ImportError:
            pass

        try:
            # PHP
            from tree_sitter_php import language as php_language

            self._languages["php"] = Language(php_language())
            self._parsers["php"] = Parser(self._languages["php"])
        except ImportError:
            pass

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """执行 AST 分析

        Args:
            context: 分析上下文

        Returns:
            分析结果
        """
        return self.analyze_with_metrics(context)

    def analyze_with_metrics(self, context: AnalysisContext) -> AnalysisResult:
        """执行分析并记录性能指标

        Args:
            context: 分析上下文

        Returns:
            分析结果
        """
        result = self.create_result(
            analysis_type=AnalysisType.AST,
            status=AnalysisStatus.RUNNING,
            context=context,
        )

        try:
            # 获取语言对应的解析器
            parser = self._parsers.get(context.language)
            if parser is None:
                result.status = AnalysisStatus.FAILED
                result.add_error(self.create_error(
                    error_type="language_not_supported",
                    message=f"不支持的语言: {context.language}"
                ))
                return result

            # 解析代码
            tree = parser.parse(context.file_content.encode())

            # 遍历 AST 进行分析
            self._analyze_tree(tree, context, result)

            result.status = AnalysisStatus.COMPLETED

        except Exception as e:
            result.status = AnalysisStatus.FAILED
            result.add_error(self.create_error(
                error_type="analysis_failed",
                message=str(e)
            ))

        return result

    def _analyze_tree(
        self, tree: Tree, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """分析 AST 树

        Args:
            tree: AST 树
            context: 分析上下文
            result: 分析结果
        """
        root_node = tree.root_node

        # 遍历所有节点
        self._traverse_node(root_node, context, result)

    def _traverse_node(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """遍历节点

        Args:
            node: 当前节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查节点类型并应用相应的规则
        self._check_node(node, context, result)

        # 递归遍历子节点
        for child in node.children:
            self._traverse_node(child, context, result)

    def _check_node(self, node, context: AnalysisContext, result: AnalysisResult) -> None:
        """检查节点

        Args:
            node: 当前节点
            context: 分析上下文
            result: 分析结果
        """
        node_type = node.type

        # 根据节点类型进行检查
        check_methods = {
            "call": self._check_function_call,
            "function_definition": self._check_function_definition,
            "class_definition": self._check_class_definition,
            "import_statement": self._check_import,
            "import_from_statement": self._check_import,
            "variable_declarator": self._check_variable_declaration,
            "assignment_expression": self._check_assignment,
            "if_statement": self._check_if_statement,
            "for_statement": self._check_loop_statement,
            "while_statement": self._check_loop_statement,
            "do_statement": self._check_loop_statement,
            "try_statement": self._check_try_statement,
            "throw_statement": self._check_throw_statement,
            "return_statement": self._check_return_statement,
        }

        check_method = check_methods.get(node_type)
        if check_method:
            check_method(node, context, result)

    def _check_function_call(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查函数调用

        Args:
            node: 函数调用节点
            context: 分析上下文
            result: 分析结果
        """
        # 获取函数名
        func_name = self._get_function_name(node)
        if not func_name:
            return

        # 检查危险函数调用
        language_functions = self._dangerous_functions.get(context.language, {})
        if func_name in language_functions:
            issue = self.create_issue(
                rule_id="AST-DANGEROUS-FUNCTION",
                message=language_functions[func_name],
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
                severity="high",
                confidence=0.8,
                code_snippet=node.text.decode() if node.text else "",
                cwe_id="CWE-94",  # 代码注入
                owasp_category="注入",
            )
            result.add_issue(issue)

        # 检查 SQL 注入风险
        if func_name in ["execute", "executemany", "query", "raw"]:
            self._check_sql_injection(node, context, result)

    def _check_function_definition(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查函数定义

        Args:
            node: 函数定义节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查函数参数中是否有敏感参数名
        sensitive_params = ["password", "secret", "token", "key", "api_key", "auth_token"]

        # 获取参数列表
        params_node = None
        for child in node.children:
            if child.type in ["parameters", "formal_parameters"]:
                params_node = child
                break

        if params_node:
            for param in params_node.children:
                param_name = self._get_node_text(param).lower()
                for sensitive in sensitive_params:
                    if sensitive in param_name:
                        # 检查是否有类型注解或文档字符串
                        if not self._has_type_annotation(param):
                            issue = self.create_issue(
                                rule_id="AST-SENSITIVE-PARAM",
                                message=f"敏感参数 '{param_name}' 缺少类型注解",
                                line=param.start_point[0] + 1,
                                column=param.start_point[1],
                                end_line=param.end_point[0] + 1,
                                end_column=param.end_point[1],
                                severity="low",
                                confidence=0.6,
                                cwe_id="CWE-200",  # 信息泄露
                                owasp_category="信息泄露",
                            )
                            result.add_issue(issue)

        # 检查函数是否缺少文档字符串
        if not self._has_docstring(node):
            issue = self.create_issue(
                rule_id="AST-MISSING-DOCSTRING",
                message="函数缺少文档字符串",
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
                severity="info",
                confidence=0.9,
            )
            result.add_issue(issue)

    def _check_class_definition(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查类定义

        Args:
            node: 类定义节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查类是否缺少文档字符串
        if not self._has_docstring(node):
            issue = self.create_issue(
                rule_id="AST-MISSING-CLASS-DOCSTRING",
                message="类缺少文档字符串",
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
                severity="info",
                confidence=0.9,
            )
            result.add_issue(issue)

        # 检查类是否有敏感属性
        sensitive_attrs = ["password", "secret", "token", "key", "api_key"]
        self._check_sensitive_attributes(node, sensitive_attrs, context, result)

    def _check_import(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查导入语句

        Args:
            node: 导入节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否存在通配符导入
        node_text = self._get_node_text(node)
        if "*" in node_text:
            issue = self.create_issue(
                rule_id="AST-WILDCARD-IMPORT",
                message="使用通配符导入可能导致命名空间污染",
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
                severity="low",
                confidence=0.5,
                code_snippet=node_text,
            )
            result.add_issue(issue)

        # 检查是否导入了危险模块
        dangerous_modules = {
            "python": ["os", "subprocess", "eval", "exec", "pickle", "marshal", "shelve", "ctypes"],
            "javascript": ["child_process", "fs", "net", "http", "https"],
        }

        modules = dangerous_modules.get(context.language, [])
        for module in modules:
            if module in node_text:
                issue = self.create_issue(
                    rule_id="AST-DANGEROUS-MODULE",
                    message=f"导入了潜在的危险模块: {module}",
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_column=node.end_point[1],
                    severity="medium",
                    confidence=0.7,
                    code_snippet=node_text,
                )
                result.add_issue(issue)

    def _check_variable_declaration(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查变量声明

        Args:
            node: 变量声明节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查敏感变量名
        sensitive_vars = ["password", "secret", "token", "key", "api_key", "auth_token"]
        var_name = self._get_node_text(node)
        for sensitive in sensitive_vars:
            if sensitive in var_name.lower():
                issue = self.create_issue(
                    rule_id="AST-SENSITIVE-VARIABLE",
                    message=f"敏感变量 '{var_name}' 可能导致信息泄露",
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_column=node.end_point[1],
                    severity="medium",
                    confidence=0.7,
                    cwe_id="CWE-200",  # 信息泄露
                    owasp_category="信息泄露",
                )
                result.add_issue(issue)

    def _check_assignment(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查赋值语句

        Args:
            node: 赋值节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查硬编码的敏感信息
        assignment_text = self._get_node_text(node)
        sensitive_patterns = [
            r"['\"].*password.*['\"]",
            r"['\"].*secret.*['\"]",
            r"['\"].*token.*['\"]",
            r"['\"].*key.*['\"]",
            r"['\"].*api_key.*['\"]",
            r"['\"].*auth_token.*['\"]",
            r"['\"].*aws.*['\"]",
            r"['\"].*azure.*['\"]",
            r"['\"].*gcp.*['\"]",
            r"['\"].*secret.*['\"]",
        ]

        import re
        for pattern in sensitive_patterns:
            if re.search(pattern, assignment_text, re.IGNORECASE):
                issue = self.create_issue(
                    rule_id="AST-HARDCODED-SECRET",
                    message="可能存在硬编码的敏感信息",
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_column=node.end_point[1],
                    severity="high",
                    confidence=0.8,
                    code_snippet=assignment_text,
                    cwe_id="CWE-798",  # 硬编码凭证
                    owasp_category="信息泄露",
                )
                result.add_issue(issue)

    def _check_if_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查条件语句

        Args:
            node: 条件语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查条件是否总是为真或假
        condition_node = None
        for child in node.children:
            if child.type == "condition":
                condition_node = child
                break

        if condition_node:
            condition_text = self._get_node_text(condition_node)
            # 检查常量条件
            if condition_text in ["True", "False", "true", "false", "1", "0"]:
                issue = self.create_issue(
                    rule_id="AST-CONSTANT-CONDITION",
                    message="条件总是为常量值",
                    line=condition_node.start_point[0] + 1,
                    column=condition_node.start_point[1],
                    end_line=condition_node.end_point[0] + 1,
                    end_column=condition_node.end_point[1],
                    severity="low",
                    confidence=0.9,
                    code_snippet=condition_text,
                )
                result.add_issue(issue)

    def _check_loop_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查循环语句

        Args:
            node: 循环语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查循环条件是否可能导致无限循环
        condition_node = None
        for child in node.children:
            if child.type == "condition":
                condition_node = child
                break

        if condition_node:
            condition_text = self._get_node_text(condition_node)
            # 检查常量条件
            if condition_text in ["True", "true", "1"]:
                issue = self.create_issue(
                    rule_id="AST-INFINITE-LOOP",
                    message="可能的无限循环",
                    line=condition_node.start_point[0] + 1,
                    column=condition_node.start_point[1],
                    end_line=condition_node.end_point[0] + 1,
                    end_column=condition_node.end_point[1],
                    severity="medium",
                    confidence=0.8,
                    code_snippet=condition_text,
                )
                result.add_issue(issue)

    def _check_try_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查异常处理语句

        Args:
            node: 异常处理语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否有空的 except 块
        has_except = False
        has_empty_except = False

        for child in node.children:
            if child.type == "except_clause":
                has_except = True
                # 检查 except 块是否为空
                except_body = None
                for grandchild in child.children:
                    if grandchild.type in ["block", "statement_block"]:
                        except_body = grandchild
                        break
                if except_body and not except_body.children:
                    has_empty_except = True

        if has_except and has_empty_except:
            issue = self.create_issue(
                rule_id="AST-EMPTY-EXCEPT",
                message="空的异常处理块可能掩盖错误",
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
                severity="medium",
                confidence=0.9,
            )
            result.add_issue(issue)

    def _check_throw_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查抛出异常语句

        Args:
            node: 抛出异常语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否抛出通用异常
        throw_text = self._get_node_text(node)
        if "Exception" in throw_text or "Error" in throw_text:
            issue = self.create_issue(
                rule_id="AST-GENERIC-EXCEPTION",
                message="抛出通用异常可能掩盖具体错误信息",
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
                severity="low",
                confidence=0.7,
                code_snippet=throw_text,
            )
            result.add_issue(issue)

    def _check_return_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查返回语句

        Args:
            node: 返回语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否返回敏感信息
        return_text = self._get_node_text(node)
        sensitive_patterns = ["password", "secret", "token", "key", "api_key"]
        for pattern in sensitive_patterns:
            if pattern in return_text.lower():
                issue = self.create_issue(
                    rule_id="AST-RETURN-SENSITIVE",
                    message="可能返回敏感信息",
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_column=node.end_point[1],
                    severity="medium",
                    confidence=0.7,
                    code_snippet=return_text,
                    cwe_id="CWE-200",  # 信息泄露
                    owasp_category="信息泄露",
                )
                result.add_issue(issue)

    def _check_sql_injection(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查 SQL 注入风险

        Args:
            node: 函数调用节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否使用字符串拼接构建 SQL
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    arg_text = self._get_node_text(arg)
                    if "+" in arg_text or "f\"" in arg_text or ".format" in arg_text:
                        issue = self.create_issue(
                            rule_id="AST-SQL-INJECTION",
                            message="可能存在 SQL 注入风险",
                            line=node.start_point[0] + 1,
                            column=node.start_point[1],
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1],
                            severity="high",
                            confidence=0.8,
                            code_snippet=arg_text,
                            cwe_id="CWE-89",  # SQL 注入
                            owasp_category="注入",
                        )
                        result.add_issue(issue)

    def _check_sensitive_attributes(
        self, node, sensitive_attrs: List[str], context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查敏感属性

        Args:
            node: 类定义节点
            sensitive_attrs: 敏感属性列表
            context: 分析上下文
            result: 分析结果
        """
        # 遍历类的所有子节点
        for child in node.children:
            if child.type in ["block", "class_body"]:
                for body_child in child.children:
                    if body_child.type in ["class_definition", "function_definition"]:
                        continue
                    body_text = self._get_node_text(body_child).lower()
                    for sensitive in sensitive_attrs:
                        if sensitive in body_text:
                            issue = self.create_issue(
                                rule_id="AST-SENSITIVE-ATTRIBUTE",
                                message=f"类中可能存在敏感属性: {sensitive}",
                                line=body_child.start_point[0] + 1,
                                column=body_child.start_point[1],
                                end_line=body_child.end_point[0] + 1,
                                end_column=body_child.end_point[1],
                                severity="medium",
                                confidence=0.7,
                                cwe_id="CWE-200",  # 信息泄露
                                owasp_category="信息泄露",
                            )
                            result.add_issue(issue)

    def _get_function_name(self, node) -> Optional[str]:
        """获取函数名

        Args:
            node: 函数调用节点

        Returns:
            函数名
        """
        # 查找函数名节点
        for child in node.children:
            if child.type in ["identifier", "attribute"]:
                return self._get_node_text(child)
        return None

    def _get_node_text(self, node) -> str:
        """获取节点文本

        Args:
            node: 节点

        Returns:
            节点文本
        """
        if node.text:
            return node.text.decode()
        return ""

    def _has_type_annotation(self, node) -> bool:
        """检查是否有类型注解

        Args:
            node: 参数节点

        Returns:
            是否有类型注解
        """
        for child in node.children:
            if child.type in ["type", "type_annotation"]:
                return True
        return False

    def _has_docstring(self, node) -> bool:
        """检查是否有文档字符串

        Args:
            node: 函数或类定义节点

        Returns:
            是否有文档字符串
        """
        for child in node.children:
            if child.type in ["block", "class_body"]:
                for body_child in child.children:
                    if body_child.type in ["string_literal", "expression_statement"]:
                        text = self._get_node_text(body_child)
                        if text.startswith(("\"\"\"", "''", '"', "'")):
                            return True
                break
        return False

    def get_tree(self, content: str, language: str) -> Optional[Tree]:
        """获取 AST 树

        Args:
            content: 代码内容
            language: 语言

        Returns:
            AST 树
        """
        parser = self._parsers.get(language)
        if parser is None:
            return None

        return parser.parse(content.encode())

    def get_info(self) -> Dict[str, Any]:
        """获取分析器信息

        Returns:
            分析器信息
        """
        info = super().get_info()
        info["dangerous_functions"] = {
            lang: list(funcs.keys())
            for lang, funcs in self._dangerous_functions.items()
        }
        return info

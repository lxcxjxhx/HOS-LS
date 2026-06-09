"""AST 分析器模块

基于 tree-sitter 的抽象语法树分析器。
AST 分析器收集"可疑信号"传递给 AI 进行确认，而非直接报告漏洞。
"""

import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from tree_sitter import Language, Parser, Tree

logger = logging.getLogger(__name__)

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

    使用 tree-sitter 进行抽象语法树分析，收集可疑信号供 AI 分析确认。
    """

    name = "ast_analyzer"
    version = "2.0.0"
    supported_languages = ["python", "javascript", "typescript", "java", "cpp", "c", "go", "rust", "php"]
    supported_analysis_types = [AnalysisType.AST, AnalysisType.SECURITY, AnalysisType.CODE_QUALITY]

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, Language] = {}
        self._signals: List[Dict[str, Any]] = []
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
        self._sql_injection_funcs = ["execute", "executemany", "query", "raw"]
        self._xss_funcs = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "document.writeln"]
        self._command_injection_funcs = ["system", "popen", "exec", "spawn", "execFile"]
        self._sensitive_params = ["password", "secret", "token", "key", "api_key", "auth_token"]
        self._sensitive_attrs = ["password", "secret", "token", "key", "api_key"]
        self._dangerous_modules: Dict[str, List[str]] = {
            "python": ["os", "subprocess", "eval", "exec", "pickle", "marshal", "shelve", "ctypes"],
            "javascript": ["child_process", "fs", "net", "http", "https"],
        }
        self._sensitive_vars = ["password", "secret", "token", "key", "api_key", "auth_token"]
        self._sensitive_assignment_patterns = [
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
        self._constant_condition_values = {"True", "False", "true", "false", "1", "0"}
        self._infinite_loop_condition_values = {"True", "true", "1"}
        self._generic_exception_keywords = ["Exception", "Error"]
        self._return_sensitive_keywords = ["password", "secret", "token", "key", "api_key"]

    def initialize(self) -> None:
        """初始化分析器，加载语言库"""
        super().initialize()
        self._signals = []
        self._load_languages()

    def _load_languages(self) -> None:
        """加载 tree-sitter 语言库"""
        loaded_languages = []
        missing_languages = []
        
        try:
            # Python
            from tree_sitter_python import language as python_language

            self._languages["python"] = Language(python_language())
            self._parsers["python"] = Parser(self._languages["python"])
            loaded_languages.append("python")
        except ImportError as e:
            missing_languages.append(("Python", "tree-sitter-python"))

        try:
            # JavaScript
            from tree_sitter_javascript import language as js_language

            self._languages["javascript"] = Language(js_language())
            self._languages["typescript"] = Language(js_language())
            self._parsers["javascript"] = Parser(self._languages["javascript"])
            self._parsers["typescript"] = Parser(self._languages["typescript"])
            loaded_languages.extend(["javascript", "typescript"])
        except ImportError as e:
            missing_languages.append(("JavaScript/TypeScript", "tree-sitter-javascript"))

        try:
            # Java
            from tree_sitter_java import language as java_language

            self._languages["java"] = Language(java_language())
            self._parsers["java"] = Parser(self._languages["java"])
            loaded_languages.append("java")
        except ImportError as e:
            missing_languages.append(("Java", "tree-sitter-java"))

        try:
            # C/C++
            from tree_sitter_cpp import language as cpp_language

            self._languages["cpp"] = Language(cpp_language())
            self._languages["c"] = Language(cpp_language())
            self._parsers["cpp"] = Parser(self._languages["cpp"])
            self._parsers["c"] = Parser(self._languages["c"])
            loaded_languages.extend(["cpp", "c"])
        except ImportError as e:
            missing_languages.append(("C/C++", "tree-sitter-cpp"))

        try:
            # Go
            from tree_sitter_go import language as go_language

            self._languages["go"] = Language(go_language())
            self._parsers["go"] = Parser(self._languages["go"])
            loaded_languages.append("go")
        except ImportError as e:
            missing_languages.append(("Go", "tree-sitter-go"))

        try:
            # Rust
            from tree_sitter_rust import language as rust_language

            self._languages["rust"] = Language(rust_language())
            self._parsers["rust"] = Parser(self._languages["rust"])
            loaded_languages.append("rust")
        except ImportError as e:
            missing_languages.append(("Rust", "tree-sitter-rust"))

        try:
            # PHP
            from tree_sitter_php import language as php_language

            self._languages["php"] = Language(php_language())
            self._parsers["php"] = Parser(self._languages["php"])
            loaded_languages.append("php")
        except ImportError as e:
            missing_languages.append(("PHP", "tree-sitter-php"))
        
        # 输出加载结果
        if not missing_languages:
            logger.info(f"tree-sitter 语言库加载完成: {', '.join(loaded_languages)}")
        else:
            for lang_name, pip_command in missing_languages:
                logger.warning(f"⚠ {lang_name} 未安装，{lang_name} AST 分析不可用。安装命令: pip install {pip_command}")
            
            if not loaded_languages:
                logger.warning("❌ 未加载任何 tree-sitter 语言库，AST 静态分析将被跳过。请运行: pip install tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-cpp tree-sitter-go tree-sitter-rust")

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """执行 AST 分析

        Args:
            context: 分析上下文

        Returns:
            分析结果
        """
        return self.analyze_with_metrics(context)

    def analyze_with_metrics(self, context: AnalysisContext) -> AnalysisResult:
        """执行分析并收集信号

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

            # 遍历 AST 收集信号
            self._signals = []
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

    def _add_signal(self, signal_type: str, line: int, file_path: str, language: str,
                    context_text: str, description: str = "", suggestion: str = "",
                    metadata: Optional[Dict[str, Any]] = None) -> None:
        """添加可疑信号

        Args:
            signal_type: 信号类型
            line: 行号
            file_path: 文件路径
            language: 编程语言
            context_text: 代码上下文
            description: 信号描述
            suggestion: 修复建议
            metadata: 额外元数据
        """
        signal = {
            "type": signal_type,
            "line": line,
            "file": file_path,
            "language": language,
            "context": context_text,
            "description": description,
            "suggestion": suggestion,
        }
        if metadata:
            signal["metadata"] = metadata
        self._signals.append(signal)

    def _check_function_call(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查函数调用 - 收集信号而非创建 findings

        Args:
            node: 函数调用节点
            context: 分析上下文
            result: 分析结果
        """
        func_name = self._get_function_name(node)
        if not func_name:
            return

        # 检查危险函数调用 - 收集信号
        language_functions = self._dangerous_functions.get(context.language, {})
        if func_name in language_functions:
            poc = self._get_poc_for_function(func_name, context.language)
            fix = self._get_fix_suggestion(func_name, context.language)
            self._add_signal(
                signal_type="dangerous_function",
                line=node.start_point[0] + 1,
                file_path=context.file_path or "",
                language=context.language,
                context_text=node.text.decode() if node.text else "",
                description=language_functions[func_name],
                suggestion=fix,
                metadata={"poc": poc, "function": func_name},
            )

        # 检查 SQL 注入风险 - 收集信号
        if func_name in self._sql_injection_funcs:
            self._check_sql_injection(node, context)

        # 检查 XSS 风险 - 收集信号
        if func_name in self._xss_funcs:
            self._check_xss(node, context)

        # 检查命令注入风险 - 收集信号
        if func_name in self._command_injection_funcs:
            self._check_command_injection(node, context)

    def _check_function_definition(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查函数定义 - 收集信号而非创建 findings

        Args:
            node: 函数定义节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查函数参数中是否有敏感参数名 - 收集信号
        params_node = None
        for child in node.children:
            if child.type in ["parameters", "formal_parameters"]:
                params_node = child
                break

        if params_node:
            for param in params_node.children:
                param_name = self._get_node_text(param).lower()
                for sensitive in self._sensitive_params:
                    if sensitive in param_name:
                        if not self._has_type_annotation(param):
                            self._add_signal(
                                signal_type="sensitive_param",
                                line=param.start_point[0] + 1,
                                file_path=context.file_path or "",
                                language=context.language,
                                context_text=self._get_node_text(param),
                                description=f"敏感参数 '{param_name}' 缺少类型注解",
                                suggestion="为敏感参数添加类型注解和验证",
                                metadata={"param_name": param_name, "sensitive_keyword": sensitive},
                            )

        # 检查函数是否缺少文档字符串 - 收集信号
        if not self._has_docstring(node):
            self._add_signal(
                signal_type="missing_docstring",
                line=node.start_point[0] + 1,
                file_path=context.file_path or "",
                language=context.language,
                context_text=self._get_node_text(node),
                description="函数缺少文档字符串",
                suggestion="添加文档字符串描述函数用途、参数和返回值",
            )

    def _check_class_definition(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查类定义 - 收集信号而非创建 findings

        Args:
            node: 类定义节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查类是否缺少文档字符串 - 收集信号
        if not self._has_docstring(node):
            self._add_signal(
                signal_type="missing_class_docstring",
                line=node.start_point[0] + 1,
                file_path=context.file_path or "",
                language=context.language,
                context_text=self._get_node_text(node),
                description="类缺少文档字符串",
                suggestion="添加类文档字符串描述类用途",
            )

        # 检查类是否有敏感属性 - 收集信号
        self._check_sensitive_attributes(node, self._sensitive_attrs, context)

    def _check_import(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查导入语句 - 收集信号而非创建 findings

        Args:
            node: 导入节点
            context: 分析上下文
            result: 分析结果
        """
        node_text = self._get_node_text(node)
        
        # 检查是否存在通配符导入 - 收集信号
        if "*" in node_text:
            self._add_signal(
                signal_type="wildcard_import",
                line=node.start_point[0] + 1,
                file_path=context.file_path or "",
                language=context.language,
                context_text=node_text,
                description="使用通配符导入可能导致命名空间污染",
                suggestion="使用显式导入替代通配符导入",
            )

        # 检查是否导入了危险模块 - 收集信号
        modules = self._dangerous_modules.get(context.language, [])
        for module in modules:
            if module in node_text:
                self._add_signal(
                    signal_type="dangerous_module",
                    line=node.start_point[0] + 1,
                    file_path=context.file_path or "",
                    language=context.language,
                    context_text=node_text,
                    description=f"导入了潜在的危险模块: {module}",
                    suggestion="确保导入此模块是必要的，并检查使用方式是否安全",
                    metadata={"module": module},
                )

    def _check_variable_declaration(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查变量声明 - 收集信号而非创建 findings

        Args:
            node: 变量声明节点
            context: 分析上下文
            result: 分析结果
        """
        var_name = self._get_node_text(node)
        for sensitive in self._sensitive_vars:
            if sensitive in var_name.lower():
                self._add_signal(
                    signal_type="sensitive_variable",
                    line=node.start_point[0] + 1,
                    file_path=context.file_path or "",
                    language=context.language,
                    context_text=var_name,
                    description=f"敏感变量 '{var_name}' 可能导致信息泄露",
                    suggestion="确保敏感变量不暴露给用户，并使用安全的存储方式",
                    metadata={"var_name": var_name, "sensitive_keyword": sensitive},
                )

    def _check_assignment(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查赋值语句 - 收集信号而非创建 findings

        Args:
            node: 赋值节点
            context: 分析上下文
            result: 分析结果
        """
        assignment_text = self._get_node_text(node)

        for pattern in self._sensitive_assignment_patterns:
            if re.search(pattern, assignment_text, re.IGNORECASE):
                self._add_signal(
                    signal_type="hardcoded_secret",
                    line=node.start_point[0] + 1,
                    file_path=context.file_path or "",
                    language=context.language,
                    context_text=assignment_text,
                    description="可能存在硬编码的敏感信息",
                    suggestion="使用环境变量或密钥管理服务存储敏感信息",
                )

    def _check_if_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查条件语句 - 收集信号而非创建 findings

        Args:
            node: 条件语句节点
            context: 分析上下文
            result: 分析结果
        """
        condition_node = None
        for child in node.children:
            if child.type == "condition":
                condition_node = child
                break

        if condition_node:
            condition_text = self._get_node_text(condition_node)
            if condition_text in self._constant_condition_values:
                self._add_signal(
                    signal_type="constant_condition",
                    line=condition_node.start_point[0] + 1,
                    file_path=context.file_path or "",
                    language=context.language,
                    context_text=condition_text,
                    description="条件总是为常量值",
                    suggestion="检查条件逻辑是否正确",
                )

    def _check_loop_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查循环语句 - 收集信号而非创建 findings

        Args:
            node: 循环语句节点
            context: 分析上下文
            result: 分析结果
        """
        condition_node = None
        for child in node.children:
            if child.type == "condition":
                condition_node = child
                break

        if condition_node:
            condition_text = self._get_node_text(condition_node)
            if condition_text in self._infinite_loop_condition_values:
                self._add_signal(
                    signal_type="infinite_loop",
                    line=condition_node.start_point[0] + 1,
                    file_path=context.file_path or "",
                    language=context.language,
                    context_text=condition_text,
                    description="可能的无限循环",
                    suggestion="确保循环有正确的退出条件",
                )

    def _check_try_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查异常处理语句 - 收集信号而非创建 findings

        Args:
            node: 异常处理语句节点
            context: 分析上下文
            result: 分析结果
        """
        has_except = False
        has_empty_except = False

        for child in node.children:
            if child.type == "except_clause":
                has_except = True
                except_body = None
                for grandchild in child.children:
                    if grandchild.type in ["block", "statement_block"]:
                        except_body = grandchild
                        break
                if except_body and not except_body.children:
                    has_empty_except = True

        if has_except and has_empty_except:
            self._add_signal(
                signal_type="empty_except",
                line=node.start_point[0] + 1,
                file_path=context.file_path or "",
                language=context.language,
                context_text=self._get_node_text(node),
                description="空的异常处理块可能掩盖错误",
                suggestion="添加适当的错误处理逻辑或日志记录",
            )

    def _check_throw_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查抛出异常语句 - 收集信号而非创建 findings

        Args:
            node: 抛出异常语句节点
            context: 分析上下文
            result: 分析结果
        """
        throw_text = self._get_node_text(node)
        for keyword in self._generic_exception_keywords:
            if keyword in throw_text:
                self._add_signal(
                    signal_type="generic_exception",
                    line=node.start_point[0] + 1,
                    file_path=context.file_path or "",
                    language=context.language,
                    context_text=throw_text,
                    description="抛出通用异常可能掩盖具体错误信息",
                    suggestion="使用更具体的异常类型",
                )

    def _check_return_statement(
        self, node, context: AnalysisContext, result: AnalysisResult
    ) -> None:
        """检查返回语句 - 收集信号而非创建 findings

        Args:
            node: 返回语句节点
            context: 分析上下文
            result: 分析结果
        """
        return_text = self._get_node_text(node)
        for pattern in self._return_sensitive_keywords:
            if pattern in return_text.lower():
                self._add_signal(
                    signal_type="return_sensitive",
                    line=node.start_point[0] + 1,
                    file_path=context.file_path or "",
                    language=context.language,
                    context_text=return_text,
                    description="可能返回敏感信息",
                    suggestion="过滤敏感信息后再返回",
                )

    def _check_sql_injection(
        self, node, context: AnalysisContext
    ) -> None:
        """检查 SQL 注入风险 - 收集信号

        Args:
            node: 函数调用节点
            context: 分析上下文
        """
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    arg_text = self._get_node_text(arg)
                    if "+" in arg_text or "f\"" in arg_text or ".format" in arg_text:
                        self._add_signal(
                            signal_type="sql_injection",
                            line=node.start_point[0] + 1,
                            file_path=context.file_path or "",
                            language=context.language,
                            context_text=arg_text,
                            description="可能存在 SQL 注入风险",
                            suggestion="使用参数化查询或预处理语句，避免直接拼接 SQL 语句",
                            metadata={"poc": "攻击者可以通过输入包含 SQL 语句的参数来执行恶意 SQL 查询，例如：' OR 1=1 --"},
                        )

    def _check_xss(
        self, node, context: AnalysisContext
    ) -> None:
        """检查 XSS 风险 - 收集信号

        Args:
            node: 函数调用节点
            context: 分析上下文
        """
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    arg_text = self._get_node_text(arg)
                    if "var" in arg_text or "input" in arg_text or "document" in arg_text:
                        self._add_signal(
                            signal_type="xss",
                            line=node.start_point[0] + 1,
                            file_path=context.file_path or "",
                            language=context.language,
                            context_text=arg_text,
                            description="可能存在 XSS 风险",
                            suggestion="对用户输入进行 HTML 转义，使用安全的 DOM 操作方法",
                            metadata={"poc": "攻击者可以通过输入包含 JavaScript 代码的内容来执行恶意脚本，例如：<script>alert('XSS')</script>"},
                        )

    def _check_command_injection(
        self, node, context: AnalysisContext
    ) -> None:
        """检查命令注入风险 - 收集信号

        Args:
            node: 函数调用节点
            context: 分析上下文
        """
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    arg_text = self._get_node_text(arg)
                    if "var" in arg_text or "input" in arg_text or "$" in arg_text:
                        self._add_signal(
                            signal_type="command_injection",
                            line=node.start_point[0] + 1,
                            file_path=context.file_path or "",
                            language=context.language,
                            context_text=arg_text,
                            description="可能存在命令注入风险",
                            suggestion="使用参数数组形式调用命令，避免直接拼接命令字符串",
                            metadata={"poc": "攻击者可以通过输入包含系统命令的参数来执行恶意命令，例如：; ls -la"},
                        )

    def _get_poc_for_function(self, func_name: str, language: str) -> str:
        """获取函数的 POC 利用方式

        Args:
            func_name: 函数名
            language: 语言

        Returns:
            POC 利用方式
        """
        poc_map = {
            "python": {
                "eval": "eval('__import__(\"os\").system(\"ls\")')",
                "exec": "exec('import os; os.system(\"ls\")')",
                "subprocess.Popen": "subprocess.Popen('ls -la', shell=True)",
                "os.system": "os.system('ls -la')",
                "open": "open('../../../etc/passwd', 'r')"
            },
            "javascript": {
                "eval": "eval('alert(\"XSS\")')",
                "new Function": "new Function('alert(\"XSS\")')()",
                "innerHTML": "element.innerHTML = '<script>alert(\"XSS\")</script>'",
                "document.write": "document.write('<script>alert(\"XSS\")</script>')"
            },
            "java": {
                "Runtime.exec": "Runtime.getRuntime().exec('ls -la')",
                "ProcessBuilder.start": "new ProcessBuilder('ls', '-la').start()"
            },
            "cpp": {
                "system": "system('ls -la')",
                "popen": "popen('ls -la', 'r')"
            }
        }
        lang_poc = poc_map.get(language, {})
        return lang_poc.get(func_name, "")

    def _get_fix_suggestion(self, func_name: str, language: str) -> str:
        """获取函数的修复建议

        Args:
            func_name: 函数名
            language: 语言

        Returns:
            修复建议
        """
        fix_map = {
            "python": {
                "eval": "避免使用 eval()，使用更安全的替代方案",
                "exec": "避免使用 exec()，使用更安全的替代方案",
                "subprocess.Popen": "使用参数数组形式，设置 shell=False",
                "os.system": "使用 subprocess 模块并设置 shell=False",
                "open": "使用 os.path.realpath() 验证路径，避免路径遍历"
            },
            "javascript": {
                "eval": "避免使用 eval()，使用更安全的替代方案",
                "new Function": "避免使用 new Function()，使用更安全的替代方案",
                "innerHTML": "使用 textContent 或 createElement() 替代",
                "document.write": "使用 DOM 操作方法替代"
            },
            "java": {
                "Runtime.exec": "使用 ProcessBuilder 并使用参数数组",
                "ProcessBuilder.start": "使用参数数组形式，避免命令拼接"
            },
            "cpp": {
                "system": "避免使用 system()，使用更安全的替代方案",
                "popen": "避免使用 popen()，使用更安全的替代方案"
            }
        }
        lang_fix = fix_map.get(language, {})
        return lang_fix.get(func_name, "")

    def _check_sensitive_attributes(
        self, node, sensitive_attrs: List[str], context: AnalysisContext
    ) -> None:
        """检查敏感属性 - 收集信号

        Args:
            node: 类定义节点
            sensitive_attrs: 敏感属性列表
            context: 分析上下文
        """
        for child in node.children:
            if child.type in ["block", "class_body"]:
                for body_child in child.children:
                    if body_child.type in ["class_definition", "function_definition"]:
                        continue
                    body_text = self._get_node_text(body_child).lower()
                    for sensitive in sensitive_attrs:
                        if sensitive in body_text:
                            self._add_signal(
                                signal_type="sensitive_attribute",
                                line=body_child.start_point[0] + 1,
                                file_path=context.file_path or "",
                                language=context.language,
                                context_text=self._get_node_text(body_child),
                                description=f"类中可能存在敏感属性: {sensitive}",
                                suggestion="确保敏感属性得到适当的保护和加密存储",
                                metadata={"sensitive_keyword": sensitive},
                            )

    def _get_function_name(self, node) -> Optional[str]:
        """获取函数名

        Args:
            node: 函数调用节点

        Returns:
            函数名
        """
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

    def get_signals_for_ai(self) -> List[Dict[str, Any]]:
        """返回所有收集的 AST 信号作为 AI 分析的上下文

        Returns:
            信号列表
        """
        return self._signals

    def get_ai_context(self) -> str:
        """格式化信号为 AI 可读的上下文文本

        Returns:
            AI 上下文字符串
        """
        if not self._signals:
            return "AST 分析未发现可疑信号。"
        
        context_lines = ["AST 分析收集到以下可疑信号，请 AI 进行确认：\n"]
        for i, signal in enumerate(self._signals, 1):
            context_lines.append(f"### 信号 {i}")
            context_lines.append(f"- 类型: {signal.get('type', 'unknown')}")
            context_lines.append(f"- 文件: {signal.get('file', '')}")
            context_lines.append(f"- 行号: {signal.get('line', '')}")
            context_lines.append(f"- 语言: {signal.get('language', '')}")
            context_lines.append(f"- 描述: {signal.get('description', '')}")
            context_lines.append(f"- 代码: {signal.get('context', '')}")
            if signal.get('suggestion'):
                context_lines.append(f"- 建议: {signal['suggestion']}")
            if signal.get('metadata', {}).get('poc'):
                context_lines.append(f"- POC: {signal['metadata']['poc']}")
            context_lines.append("")
        
        return "\n".join(context_lines)

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
        info["signal_count"] = len(self._signals)
        return info

    def get_standardized_output(self, result: AnalysisResult) -> List[Dict[str, Any]]:
        """获取标准化的输出格式 - 返回信号而非 findings

        Args:
            result: 分析结果

        Returns:
            标准化的信号列表
        """
        return self._signals

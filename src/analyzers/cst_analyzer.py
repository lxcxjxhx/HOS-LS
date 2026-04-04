"""CST 分析器模块

基于 libcst 的具体语法树分析器。
"""

import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import libcst as cst
from libcst import CSTNode, Module

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


class CSTAnalyzer(BaseAnalyzer):
    """CST 分析器

    使用 libcst 进行具体语法树分析，支持代码转换和重构。
    """

    name = "cst_analyzer"
    version = "1.1.0"
    supported_languages = ["python"]
    supported_analysis_types = [AnalysisType.CST, AnalysisType.CODE_QUALITY, AnalysisType.SECURITY]

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._metadata_wrapper = None
        self._dangerous_functions = {
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
        }

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """执行 CST 分析

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
            analysis_type=AnalysisType.CST,
            status=AnalysisStatus.RUNNING,
            context=context,
        )

        try:
            # 解析代码
            module = cst.parse_module(context.file_content)

            # 创建元数据包装器
            wrapper = cst.MetadataWrapper(module)

            # 执行分析
            self._analyze_module(wrapper, context, result)

            result.status = AnalysisStatus.COMPLETED

        except cst.ParserSyntaxError as e:
            result.status = AnalysisStatus.FAILED
            result.add_error(self.create_error(
                error_type="syntax_error",
                message=f"语法错误: {e}"
            ))
        except Exception as e:
            result.status = AnalysisStatus.FAILED
            result.add_error(self.create_error(
                error_type="analysis_failed",
                message=str(e)
            ))

        return result

    def _analyze_module(
        self,
        wrapper: cst.MetadataWrapper,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """分析模块

        Args:
            wrapper: 元数据包装器
            context: 分析上下文
            result: 分析结果
        """
        module = wrapper.module

        # 遍历模块中的所有节点
        for node in module.body:
            self._analyze_statement(wrapper, node, context, result)

    def _analyze_statement(
        self,
        wrapper: cst.MetadataWrapper,
        node: CSTNode,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """分析语句

        Args:
            wrapper: 元数据包装器
            node: 语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查导入语句
        if isinstance(node, cst.SimpleStatementLine):
            for stmt in node.body:
                if isinstance(stmt, cst.Import):
                    self._check_import(wrapper, stmt, context, result)
                elif isinstance(stmt, cst.ImportFrom):
                    self._check_import_from(wrapper, stmt, context, result)
                elif isinstance(stmt, cst.Assign):
                    self._check_assignment(wrapper, stmt, context, result)
                elif isinstance(stmt, cst.AnnAssign):
                    self._check_annotated_assignment(wrapper, stmt, context, result)
                elif isinstance(stmt, cst.Expr):
                    self._check_expression(wrapper, stmt, context, result)

        # 检查函数定义
        elif isinstance(node, cst.FunctionDef):
            self._check_function_def(wrapper, node, context, result)

        # 检查类定义
        elif isinstance(node, cst.ClassDef):
            self._check_class_def(wrapper, node, context, result)

        # 检查控制流语句
        elif isinstance(node, cst.If):
            self._check_if_statement(wrapper, node, context, result)
        elif isinstance(node, (cst.For, cst.While)):
            self._check_loop_statement(wrapper, node, context, result)
        elif isinstance(node, cst.Try):
            self._check_try_statement(wrapper, node, context, result)
        elif isinstance(node, cst.Raise):
            self._check_raise_statement(wrapper, node, context, result)
        elif isinstance(node, cst.Return):
            self._check_return_statement(wrapper, node, context, result)

        # 递归检查复合语句
        elif hasattr(node, "body"):
            if isinstance(node.body, cst.IndentedBlock):
                for stmt in node.body.body:
                    self._analyze_statement(wrapper, stmt, context, result)

    def _check_import(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.Import,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查导入语句

        Args:
            wrapper: 元数据包装器
            node: 导入节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否存在通配符导入
        for name in node.names:
            if isinstance(name.name, cst.Name) and name.name.value == "*":
                position = self._get_position(wrapper, node)
                issue = self.create_issue(
                    rule_id="CST-WILDCARD-IMPORT",
                    message="使用通配符导入可能导致命名空间污染",
                    line=position.start.line,
                    column=position.start.column,
                    end_line=position.end.line,
                    end_column=position.end.column,
                    severity="low",
                    confidence=0.5,
                )
                result.add_issue(issue)

        # 检查是否导入了危险模块
        dangerous_modules = ["os", "subprocess", "eval", "exec", "pickle", "marshal", "shelve", "ctypes"]
        for name in node.names:
            if isinstance(name.name, cst.Name):
                module_name = name.name.value
                if module_name in dangerous_modules:
                    position = self._get_position(wrapper, node)
                    issue = self.create_issue(
                        rule_id="CST-DANGEROUS-MODULE",
                        message=f"导入了潜在的危险模块: {module_name}",
                        line=position.start.line,
                        column=position.start.column,
                        end_line=position.end.line,
                        end_column=position.end.column,
                        severity="medium",
                        confidence=0.7,
                    )
                    result.add_issue(issue)

    def _check_import_from(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.ImportFrom,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查 from 导入语句

        Args:
            wrapper: 元数据包装器
            node: from 导入节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查相对导入
        if node.module is None:
            position = self._get_position(wrapper, node)
            issue = self.create_issue(
                rule_id="CST-RELATIVE-IMPORT",
                message="使用相对导入可能影响代码可移植性",
                line=position.start.line,
                column=position.start.column,
                end_line=position.end.line,
                end_column=position.end.column,
                severity="info",
                confidence=0.3,
            )
            result.add_issue(issue)

        # 检查通配符导入
        if isinstance(node.names, cst.ImportStar):
            position = self._get_position(wrapper, node)
            issue = self.create_issue(
                rule_id="CST-WILDCARD-IMPORT",
                message="使用通配符导入可能导致命名空间污染",
                line=position.start.line,
                column=position.start.column,
                end_line=position.end.line,
                end_column=position.end.column,
                severity="low",
                confidence=0.5,
            )
            result.add_issue(issue)

        # 检查是否从危险模块导入
        if node.module:
            module_name = "".join([part.value for part in node.module])
            dangerous_modules = ["os", "subprocess", "eval", "exec", "pickle"]
            if module_name in dangerous_modules:
                position = self._get_position(wrapper, node)
                issue = self.create_issue(
                    rule_id="CST-DANGEROUS-MODULE",
                    message=f"从潜在的危险模块导入: {module_name}",
                    line=position.start.line,
                    column=position.start.column,
                    end_line=position.end.line,
                    end_column=position.end.column,
                    severity="medium",
                    confidence=0.7,
                )
                result.add_issue(issue)

    def _check_assignment(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.Assign,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查赋值语句

        Args:
            wrapper: 元数据包装器
            node: 赋值节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查敏感变量名
        sensitive_names = ["password", "secret", "token", "api_key", "private_key", "auth_token"]

        for target in node.targets:
            if isinstance(target.target, cst.Name):
                var_name = target.target.value.lower()
                for sensitive in sensitive_names:
                    if sensitive in var_name:
                        # 检查是否是硬编码的敏感值
                        if isinstance(node.value, (cst.SimpleString, cst.ConcatenatedString)):
                            position = self._get_position(wrapper, node)
                            issue = self.create_issue(
                                rule_id="CST-HARDCODED-SECRET",
                                message=f"变量 '{target.target.value}' 可能包含硬编码的敏感信息",
                                line=position.start.line,
                                column=position.start.column,
                                end_line=position.end.line,
                                end_column=position.end.column,
                                severity="critical",
                                confidence=0.9,
                                cwe_id="CWE-798",  # 硬编码凭证
                                owasp_category="信息泄露",
                            )
                            result.add_issue(issue)

    def _check_annotated_assignment(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.AnnAssign,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查带注解的赋值语句

        Args:
            wrapper: 元数据包装器
            node: 带注解的赋值节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查敏感变量名
        sensitive_names = ["password", "secret", "token", "api_key", "private_key", "auth_token"]

        if isinstance(node.target, cst.Name):
            var_name = node.target.value.lower()
            for sensitive in sensitive_names:
                if sensitive in var_name:
                    # 检查是否是硬编码的敏感值
                    if isinstance(node.value, (cst.SimpleString, cst.ConcatenatedString)):
                        position = self._get_position(wrapper, node)
                        issue = self.create_issue(
                            rule_id="CST-HARDCODED-SECRET",
                            message=f"变量 '{node.target.value}' 可能包含硬编码的敏感信息",
                            line=position.start.line,
                            column=position.start.column,
                            end_line=position.end.line,
                            end_column=position.end.column,
                            severity="critical",
                            confidence=0.9,
                            cwe_id="CWE-798",  # 硬编码凭证
                            owasp_category="信息泄露",
                        )
                        result.add_issue(issue)

    def _check_expression(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.Expr,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查表达式语句

        Args:
            wrapper: 元数据包装器
            node: 表达式节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查函数调用
        if isinstance(node.value, cst.Call):
            self._check_function_call(wrapper, node.value, context, result)

    def _check_function_call(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.Call,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查函数调用

        Args:
            wrapper: 元数据包装器
            node: 函数调用节点
            context: 分析上下文
            result: 分析结果
        """
        # 获取函数名
        func_name = self._get_function_name(node)
        if not func_name:
            return

        # 检查危险函数调用
        if func_name in self._dangerous_functions:
            position = self._get_position(wrapper, node)
            issue = self.create_issue(
                rule_id="CST-DANGEROUS-FUNCTION",
                message=self._dangerous_functions[func_name],
                line=position.start.line,
                column=position.start.column,
                end_line=position.end.line,
                end_column=position.end.column,
                severity="high",
                confidence=0.8,
                cwe_id="CWE-94",  # 代码注入
                owasp_category="注入",
            )
            result.add_issue(issue)

        # 检查 SQL 注入风险
        if func_name in ["execute", "executemany", "query", "raw"]:
            self._check_sql_injection(wrapper, node, context, result)

    def _check_function_def(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.FunctionDef,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查函数定义

        Args:
            wrapper: 元数据包装器
            node: 函数定义节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查函数名是否符合命名规范
        func_name = node.name.value

        # 检查是否是危险函数名
        dangerous_names = ["eval", "exec", "run", "system", "popen"]
        if func_name.lower() in dangerous_names:
            position = self._get_position(wrapper, node)
            issue = self.create_issue(
                rule_id="CST-DANGEROUS-FUNCTION-NAME",
                message=f"函数名 '{func_name}' 可能与危险操作相关",
                line=position.start.line,
                column=position.start.column,
                end_line=position.end.line,
                end_column=position.end.column,
                severity="medium",
                confidence=0.4,
            )
            result.add_issue(issue)

        # 检查函数参数中是否有敏感参数名
        sensitive_params = ["password", "secret", "token", "key", "api_key", "auth_token"]
        for param in node.params.params:
            if isinstance(param, cst.Param) and isinstance(param.name, cst.Name):
                param_name = param.name.value.lower()
                for sensitive in sensitive_params:
                    if sensitive in param_name:
                        position = self._get_position(wrapper, param)
                        issue = self.create_issue(
                            rule_id="CST-SENSITIVE-PARAM",
                            message=f"敏感参数 '{param.name.value}' 可能导致信息泄露",
                            line=position.start.line,
                            column=position.start.column,
                            end_line=position.end.line,
                            end_column=position.end.column,
                            severity="medium",
                            confidence=0.7,
                            cwe_id="CWE-200",  # 信息泄露
                            owasp_category="信息泄露",
                        )
                        result.add_issue(issue)

        # 检查函数是否缺少文档字符串
        if not self._has_docstring(node):
            position = self._get_position(wrapper, node)
            issue = self.create_issue(
                rule_id="CST-MISSING-DOCSTRING",
                message="函数缺少文档字符串",
                line=position.start.line,
                column=position.start.column,
                end_line=position.end.line,
                end_column=position.end.column,
                severity="info",
                confidence=0.9,
            )
            result.add_issue(issue)

        # 递归检查函数体
        if isinstance(node.body, cst.IndentedBlock):
            for stmt in node.body.body:
                self._analyze_statement(wrapper, stmt, context, result)

    def _check_class_def(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.ClassDef,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查类定义

        Args:
            wrapper: 元数据包装器
            node: 类定义节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查类名是否符合命名规范（帕斯卡命名法）
        class_name = node.name.value
        if not class_name[0].isupper():
            position = self._get_position(wrapper, node)
            issue = self.create_issue(
                rule_id="CST-CLASS-NAMING",
                message=f"类名 '{class_name}' 应使用帕斯卡命名法",
                line=position.start.line,
                column=position.start.column,
                end_line=position.end.line,
                end_column=position.end.column,
                severity="info",
                confidence=0.9,
            )
            result.add_issue(issue)

        # 检查类是否缺少文档字符串
        if not self._has_docstring(node):
            position = self._get_position(wrapper, node)
            issue = self.create_issue(
                rule_id="CST-MISSING-CLASS-DOCSTRING",
                message="类缺少文档字符串",
                line=position.start.line,
                column=position.start.column,
                end_line=position.end.line,
                end_column=position.end.column,
                severity="info",
                confidence=0.9,
            )
            result.add_issue(issue)

        # 检查类是否有敏感属性
        sensitive_attrs = ["password", "secret", "token", "key", "api_key"]
        if isinstance(node.body, cst.IndentedBlock):
            for stmt in node.body.body:
                if isinstance(stmt, (cst.Assign, cst.AnnAssign)):
                    if isinstance(stmt, cst.Assign):
                        for target in stmt.targets:
                            if isinstance(target.target, cst.Name):
                                attr_name = target.target.value.lower()
                                for sensitive in sensitive_attrs:
                                    if sensitive in attr_name:
                                        position = self._get_position(wrapper, stmt)
                                        issue = self.create_issue(
                                            rule_id="CST-SENSITIVE-ATTRIBUTE",
                                            message=f"类中可能存在敏感属性: {target.target.value}",
                                            line=position.start.line,
                                            column=position.start.column,
                                            end_line=position.end.line,
                                            end_column=position.end.column,
                                            severity="medium",
                                            confidence=0.7,
                                            cwe_id="CWE-200",  # 信息泄露
                                            owasp_category="信息泄露",
                                        )
                                        result.add_issue(issue)
                    elif isinstance(stmt, cst.AnnAssign):
                        if isinstance(stmt.target, cst.Name):
                            attr_name = stmt.target.value.lower()
                            for sensitive in sensitive_attrs:
                                if sensitive in attr_name:
                                    position = self._get_position(wrapper, stmt)
                                    issue = self.create_issue(
                                        rule_id="CST-SENSITIVE-ATTRIBUTE",
                                        message=f"类中可能存在敏感属性: {stmt.target.value}",
                                        line=position.start.line,
                                        column=position.start.column,
                                        end_line=position.end.line,
                                        end_column=position.end.column,
                                        severity="medium",
                                        confidence=0.7,
                                        cwe_id="CWE-200",  # 信息泄露
                                        owasp_category="信息泄露",
                                    )
                                    result.add_issue(issue)

        # 递归检查类体
        if isinstance(node.body, cst.IndentedBlock):
            for stmt in node.body.body:
                self._analyze_statement(wrapper, stmt, context, result)

    def _check_if_statement(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.If,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查条件语句

        Args:
            wrapper: 元数据包装器
            node: 条件语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查条件是否总是为真或假
        condition = node.test
        condition_code = condition.code
        if condition_code in ["True", "False"]:
            position = self._get_position(wrapper, node)
            issue = self.create_issue(
                rule_id="CST-CONSTANT-CONDITION",
                message="条件总是为常量值",
                line=position.start.line,
                column=position.start.column,
                end_line=position.end.line,
                end_column=position.end.column,
                severity="low",
                confidence=0.9,
            )
            result.add_issue(issue)

        # 递归检查条件体
        if isinstance(node.body, cst.IndentedBlock):
            for stmt in node.body.body:
                self._analyze_statement(wrapper, stmt, context, result)

        # 检查 elif 和 else 分支
        if node.orelse:
            if isinstance(node.orelse, cst.If):
                self._check_if_statement(wrapper, node.orelse, context, result)
            elif isinstance(node.orelse, cst.IndentedBlock):
                for stmt in node.orelse.body:
                    self._analyze_statement(wrapper, stmt, context, result)

    def _check_loop_statement(
        self,
        wrapper: cst.MetadataWrapper,
        node: Union[cst.For, cst.While],
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查循环语句

        Args:
            wrapper: 元数据包装器
            node: 循环语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查循环条件是否可能导致无限循环
        if isinstance(node, cst.While):
            condition = node.test
            condition_code = condition.code
            if condition_code == "True":
                position = self._get_position(wrapper, node)
                issue = self.create_issue(
                    rule_id="CST-INFINITE-LOOP",
                    message="可能的无限循环",
                    line=position.start.line,
                    column=position.start.column,
                    end_line=position.end.line,
                    end_column=position.end.column,
                    severity="medium",
                    confidence=0.8,
                )
                result.add_issue(issue)

        # 递归检查循环体
        if isinstance(node.body, cst.IndentedBlock):
            for stmt in node.body.body:
                self._analyze_statement(wrapper, stmt, context, result)

    def _check_try_statement(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.Try,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查异常处理语句

        Args:
            wrapper: 元数据包装器
            node: 异常处理语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否有空的 except 块
        for handler in node.handlers:
            if isinstance(handler.body, cst.IndentedBlock) and not handler.body.body:
                position = self._get_position(wrapper, handler)
                issue = self.create_issue(
                    rule_id="CST-EMPTY-EXCEPT",
                    message="空的异常处理块可能掩盖错误",
                    line=position.start.line,
                    column=position.start.column,
                    end_line=position.end.line,
                    end_column=position.end.column,
                    severity="medium",
                    confidence=0.9,
                )
                result.add_issue(issue)

        # 递归检查 try 块
        if isinstance(node.body, cst.IndentedBlock):
            for stmt in node.body.body:
                self._analyze_statement(wrapper, stmt, context, result)

        # 递归检查 except 块
        for handler in node.handlers:
            if isinstance(handler.body, cst.IndentedBlock):
                for stmt in handler.body.body:
                    self._analyze_statement(wrapper, stmt, context, result)

        # 递归检查 else 块
        if node.orelse:
            if isinstance(node.orelse, cst.IndentedBlock):
                for stmt in node.orelse.body:
                    self._analyze_statement(wrapper, stmt, context, result)

        # 递归检查 finally 块
        if node.finalbody:
            if isinstance(node.finalbody, cst.IndentedBlock):
                for stmt in node.finalbody.body:
                    self._analyze_statement(wrapper, stmt, context, result)

    def _check_raise_statement(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.Raise,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查抛出异常语句

        Args:
            wrapper: 元数据包装器
            node: 抛出异常语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否抛出通用异常
        if node.exc:
            exc_code = node.exc.code
            if "Exception" in exc_code or "Error" in exc_code:
                position = self._get_position(wrapper, node)
                issue = self.create_issue(
                    rule_id="CST-GENERIC-EXCEPTION",
                    message="抛出通用异常可能掩盖具体错误信息",
                    line=position.start.line,
                    column=position.start.column,
                    end_line=position.end.line,
                    end_column=position.end.column,
                    severity="low",
                    confidence=0.7,
                )
                result.add_issue(issue)

    def _check_return_statement(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.Return,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查返回语句

        Args:
            wrapper: 元数据包装器
            node: 返回语句节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否返回敏感信息
        if node.value:
            return_code = node.value.code
            sensitive_patterns = ["password", "secret", "token", "key", "api_key"]
            for pattern in sensitive_patterns:
                if pattern in return_code.lower():
                    position = self._get_position(wrapper, node)
                    issue = self.create_issue(
                        rule_id="CST-RETURN-SENSITIVE",
                        message="可能返回敏感信息",
                        line=position.start.line,
                        column=position.start.column,
                        end_line=position.end.line,
                        end_column=position.end.column,
                        severity="medium",
                        confidence=0.7,
                        cwe_id="CWE-200",  # 信息泄露
                        owasp_category="信息泄露",
                    )
                    result.add_issue(issue)

    def _check_sql_injection(
        self,
        wrapper: cst.MetadataWrapper,
        node: cst.Call,
        context: AnalysisContext,
        result: AnalysisResult,
    ) -> None:
        """检查 SQL 注入风险

        Args:
            wrapper: 元数据包装器
            node: 函数调用节点
            context: 分析上下文
            result: 分析结果
        """
        # 检查是否使用字符串拼接构建 SQL
        for arg in node.args:
            if isinstance(arg, cst.Arg):
                arg_code = arg.value.code
                if "+" in arg_code or "f\"" in arg_code or ".format" in arg_code:
                    position = self._get_position(wrapper, node)
                    issue = self.create_issue(
                        rule_id="CST-SQL-INJECTION",
                        message="可能存在 SQL 注入风险",
                        line=position.start.line,
                        column=position.start.column,
                        end_line=position.end.line,
                        end_column=position.end.column,
                        severity="high",
                        confidence=0.8,
                        cwe_id="CWE-89",  # SQL 注入
                        owasp_category="注入",
                    )
                    result.add_issue(issue)

    def _get_function_name(self, node: cst.Call) -> Optional[str]:
        """获取函数名

        Args:
            node: 函数调用节点

        Returns:
            函数名
        """
        if isinstance(node.func, cst.Name):
            return node.func.value
        elif isinstance(node.func, cst.Attribute):
            return "".join([part.value for part in self._get_attribute_parts(node.func)])
        return None

    def _get_attribute_parts(self, node: cst.Attribute) -> List[cst.Name]:
        """获取属性的所有部分

        Args:
            node: 属性节点

        Returns:
            属性部分列表
        """
        parts = []
        current = node
        while isinstance(current, cst.Attribute):
            parts.insert(0, current.attr)
            current = current.value
        if isinstance(current, cst.Name):
            parts.insert(0, current)
        return parts

    def _get_position(
        self, wrapper: cst.MetadataWrapper, node: CSTNode
    ):
        """获取节点位置

        Args:
            wrapper: 元数据包装器
            node: 节点

        Returns:
            代码范围
        """
        position_provider = wrapper.resolve(cst.metadata.PositionProvider)
        return position_provider[node]

    def _has_docstring(self, node: Union[cst.FunctionDef, cst.ClassDef]) -> bool:
        """检查是否有文档字符串

        Args:
            node: 函数或类定义节点

        Returns:
            是否有文档字符串
        """
        if isinstance(node.body, cst.IndentedBlock) and node.body.body:
            first_stmt = node.body.body[0]
            if isinstance(first_stmt, cst.SimpleStatementLine):
                for stmt in first_stmt.body:
                    if isinstance(stmt, cst.Expr):
                        if isinstance(stmt.value, cst.SimpleString):
                            return True
        return False

    def transform_code(
        self, content: str, transformer: cst.CSTTransformer
    ) -> str:
        """转换代码

        Args:
            content: 原始代码
            transformer: 转换器

        Returns:
            转换后的代码
        """
        module = cst.parse_module(content)
        modified_module = module.visit(transformer)
        return modified_module.code

    def get_info(self) -> Dict[str, Any]:
        """获取分析器信息

        Returns:
            分析器信息
        """
        info = super().get_info()
        info["dangerous_functions"] = list(self._dangerous_functions.keys())
        return info

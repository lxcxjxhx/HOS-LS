from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from .universal_parser import UniversalParser, SupportedLanguage
    from .tree_sitter_adapter import TreeSitterAdapter
    _UNIVERSAL_PARSER_AVAILABLE = True
except ImportError:
    _UNIVERSAL_PARSER_AVAILABLE = False
    UniversalParser = None
    SupportedLanguage = None
    TreeSitterAdapter = None


@dataclass
class IRNode:
    node_type: str
    name: str = ""
    attributes: dict = field(default_factory=dict)
    children: list[IRNode] = field(default_factory=list)
    source_location: tuple[str, int, int] = ("", 0, 0)

    def __repr__(self) -> str:
        return f"IRNode(type={self.node_type}, name={self.name}, children={len(self.children)})"


@dataclass
class IntermediateRepresentation:
    nodes: list[IRNode] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Token:
    def __init__(self, type_: str, value: str, line: int, column: int):
        self.type = type_
        self.value = value
        self.line = line
        self.column = column

    def __repr__(self) -> str:
        return f"Token({self.type}, {self.value!r}, {self.line}:{self.column})"


class ASTTranspilerEngine:
    def __init__(self):
        if _UNIVERSAL_PARSER_AVAILABLE:
            self._universal_parser = UniversalParser()
            try:
                self._tree_sitter = TreeSitterAdapter()
            except Exception:
                self._tree_sitter = None
        else:
            self._universal_parser = None
            self._tree_sitter = None

    def parse_to_ir(self, source_code: str, source_lang: Optional[str] = None) -> IntermediateRepresentation:
        raise NotImplementedError("Subclasses must implement parse_to_ir")

    def ir_to_ast(self, ir: IntermediateRepresentation, target_lang: str) -> ast.Module:
        raise NotImplementedError("Subclasses must implement ir_to_ast")

    def transpile(self, source_code: str, source_lang: str, target_lang: str) -> str:
        ir = self.parse_to_ir(source_code, source_lang)
        target_ast = self.ir_to_ast(ir, target_lang)
        return ast.unparse(target_ast)


class JavaASTParser(ASTTranspilerEngine):
    def __init__(self):
        super().__init__()
        self.javalang_available = False
        try:
            import javalang
            self.javalang = javalang
            self.javalang_available = True
        except ImportError:
            pass

    def parse_to_ir(self, source_code: str, source_lang: Optional[str] = None) -> IntermediateRepresentation:
        if self.javalang_available:
            return self._parse_with_javalang(source_code)
        elif self._universal_parser is not None:
            return self._universal_parser.parse(source_code, SupportedLanguage.JAVA)
        else:
            return self._fallback_parse(source_code)

    def _parse_with_javalang(self, source_code: str) -> IntermediateRepresentation:
        ir = IntermediateRepresentation()
        ir.metadata["source_language"] = "java"

        try:
            tree = self.javalang.parse.parse(source_code)
            for path, node in tree:
                if isinstance(node, self.javalang.tree.ClassDeclaration):
                    ir_node = self._convert_class_to_ir(node)
                    ir.nodes.append(ir_node)
                elif isinstance(node, self.javalang.tree.MethodDeclaration):
                    ir_node = self._convert_method_to_ir(node)
                    ir.nodes.append(ir_node)
                elif isinstance(node, self.javalang.tree.Import):
                    ir.imports.append(node.path)
        except Exception:
            return self._fallback_parse(source_code)

        return ir

    def _convert_class_to_ir(self, node) -> IRNode:
        children = []
        if hasattr(node, 'body'):
            for member in node.body:
                if isinstance(member, self.javalang.tree.MethodDeclaration):
                    children.append(self._convert_method_to_ir(member))

        extends = []
        if node.extends:
            extends.append(node.extends.name)

        implements = []
        if node.implements:
            for iface in node.implements:
                implements.append(iface.name)

        modifiers = []
        if hasattr(node, 'modifiers'):
            modifiers = list(node.modifiers)

        return IRNode(
            node_type="class_def",
            name=node.name,
            attributes={
                "modifiers": modifiers,
                "extends": extends,
                "implements": implements
            },
            children=children,
            source_location=("", node.line if hasattr(node, 'line') else 0, 0)
        )

    def _convert_method_to_ir(self, node) -> IRNode:
        params = []
        if hasattr(node, 'parameters'):
            for param in node.parameters:
                param_type = param.type.name if hasattr(param.type, 'name') else str(param.type)
                params.append({"name": param.name, "type": param_type})

        return_type = "void"
        if hasattr(node, 'return_type') and node.return_type:
            return_type = node.return_type.name if hasattr(node.return_type, 'name') else str(node.return_type)

        modifiers = []
        if hasattr(node, 'modifiers'):
            modifiers = list(node.modifiers)

        return IRNode(
            node_type="method_def",
            name=node.name,
            attributes={
                "modifiers": modifiers,
                "return_type": return_type,
                "parameters": params
            },
            source_location=("", node.line if hasattr(node, 'line') else 0, 0)
        )

    def _fallback_parse(self, source_code: str) -> IntermediateRepresentation:
        ir = IntermediateRepresentation()
        ir.metadata["source_language"] = "java"

        class_match = re.search(r'class\s+(\w+)', source_code)
        if class_match:
            ir.nodes.append(IRNode(
                node_type="class_def",
                name=class_match.group(1),
                attributes={}
            ))

        method_matches = re.findall(r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(', source_code)
        for method_name in method_matches:
            if method_name != "main":
                ir.nodes.append(IRNode(
                    node_type="method_def",
                    name=method_name,
                    attributes={"return_type": "unknown", "parameters": []}
                ))

        return ir

    def ir_to_ast(self, ir: IntermediateRepresentation, target_lang: str) -> ast.Module:
        if target_lang == "python":
            return self._ir_to_python_ast(ir)
        elif target_lang == "java":
            return self._ir_to_java_ast(ir)
        else:
            raise ValueError(f"Unsupported target language: {target_lang}")

    def _ir_to_python_ast(self, ir: IntermediateRepresentation) -> ast.Module:
        body = []

        for import_str in ir.imports:
            if import_str.endswith(".*"):
                module_name = import_str.rstrip(".*")
                alias = module_name.split(".")[-1]
                body.append(ast.ImportFrom(module=alias, names=[ast.alias(name="*", asname=None)], level=0))
            else:
                module_parts = import_str.split(".")
                alias = module_parts[-1]
                body.append(ast.Import(names=[ast.alias(name=import_str, asname=alias)]))

        for node in ir.nodes:
            py_node = self._convert_ir_node_to_python(node)
            if py_node:
                body.append(py_node)

        return ast.Module(body=body, type_ignores=[])

    def _convert_ir_node_to_python(self, ir_node: IRNode) -> Optional[ast.stmt]:
        if ir_node.node_type == "class_def":
            return self._convert_class_to_python(ir_node)
        elif ir_node.node_type == "method_def":
            return self._convert_method_to_python(ir_node)
        elif ir_node.node_type == "field_def":
            return self._convert_field_to_python(ir_node)
        return None

    def _convert_class_to_python(self, class_node: IRNode) -> ast.ClassDef:
        bases = []
        for base in class_node.attributes.get("extends", []):
            bases.append(self._create_name(base))

        body = []
        for child in class_node.children:
            if child.node_type in ["method_def", "field_def"]:
                converted = self._convert_ir_node_to_python(child)
                if converted:
                    body.append(converted)

        return ast.ClassDef(
            name=class_node.name,
            bases=bases,
            keywords=[],
            body=body if body else [ast.Pass()],
            decorator_list=[],
            lineno=1,
            col_offset=0
        )

    def _convert_method_to_python(self, method_node: IRNode) -> ast.FunctionDef:
        args = ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg=param["name"], annotation=None) for param in method_node.attributes.get("parameters", [])],
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[]
        )

        body = [ast.Pass()]

        return ast.FunctionDef(
            name=method_node.name if method_node.name else "__init__",
            args=args,
            body=body,
            decorator_list=[],
            returns=None,
            lineno=1,
            col_offset=0
        )

    def _convert_field_to_python(self, field_node: IRNode) -> Optional[ast.stmt]:
        declarators = field_node.attributes.get("declarators", [])
        if declarators and "initializer" in declarators[0]:
            target = ast.Name(id=declarators[0]["name"], ctx=ast.Store())
            value = self._convert_expression_to_python(declarators[0]["initializer"])
            return ast.Assign(targets=[target], value=value)
        return None

    def _convert_expression_to_python(self, expr_node: IRNode) -> ast.expr:
        if expr_node.node_type == "literal":
            value = expr_node.attributes.get("value", "")
            if expr_node.name == "number":
                try:
                    if "." in value:
                        return ast.Constant(value=float(value))
                    else:
                        return ast.Constant(value=int(value))
                except ValueError:
                    return ast.Constant(value=value)
            elif expr_node.name == "string":
                return ast.Constant(value=value.strip('"\''))
            elif expr_node.name == "boolean":
                return ast.Constant(value=value == "true")
            elif expr_node.name == "null":
                return ast.Constant(value=None)

        elif expr_node.node_type == "identifier":
            return ast.Name(id=expr_node.name, ctx=ast.Load())

        elif expr_node.node_type == "binary_expression":
            left = self._convert_expression_to_python(expr_node.attributes.get("left"))
            right = self._convert_expression_to_python(expr_node.attributes.get("right"))
            operator = expr_node.attributes.get("operator", "+")

            op_map = {
                "+": ast.Add(), "-": ast.Sub(), "*": ast.Mult(), "/": ast.Div(),
                "%": ast.Mod(), "==": ast.Eq(), "!=": ast.NotEq(),
                "<": ast.Lt(), ">": ast.Gt(), "<=": ast.LtE(), ">=": ast.GtE(),
                "&&": ast.And(), "||": ast.Or(), "&": ast.BitAnd(),
                "|": ast.BitOr(), "^": ast.BitXor()
            }

            if operator in ["+", "-", "*", "/", "%"]:
                return ast.BinOp(left=left, op=op_map.get(operator, ast.Add()), right=right)
            elif operator in ["==", "!=", "<", ">", "<=", ">="]:
                return ast.Compare(left=left, ops=[op_map.get(operator, ast.Eq())], comparators=[right])
            elif operator in ["&&", "||"]:
                return ast.BoolOp(op=op_map.get(operator, ast.Or()), values=[left, right])
            elif operator in ["&", "|", "^"]:
                return ast.BinOp(left=left, op=op_map.get(operator, ast.BitAnd()), right=right)

        elif expr_node.node_type == "method_invocation":
            func = self._convert_expression_to_python(expr_node.attributes.get("object"))
            args = [self._convert_expression_to_python(arg) for arg in expr_node.attributes.get("arguments", [])]
            if isinstance(func, ast.Name):
                return ast.Call(func=ast.Attribute(value=func, attr=expr_node.name, ctx=ast.Load()), args=args, keywords=[])
            return ast.Call(func=ast.Attribute(value=func, attr=expr_node.name, ctx=ast.Load()), args=args, keywords=[])

        elif expr_node.node_type == "static_method_invocation":
            class_name = expr_node.attributes.get("class", "")
            method_name = expr_node.name
            args = [self._convert_expression_to_python(arg) for arg in expr_node.attributes.get("arguments", [])]
            return ast.Call(
                func=ast.Attribute(value=ast.Name(id=class_name, ctx=ast.Load()), attr=method_name, ctx=ast.Load()),
                args=args,
                keywords=[]
            )

        elif expr_node.node_type == "field_access":
            obj = self._convert_expression_to_python(expr_node.attributes.get("object"))
            return ast.Attribute(value=obj, attr=expr_node.name, ctx=ast.Load())

        elif expr_node.node_type == "object_creation":
            class_type = expr_node.attributes.get("class_type", "")
            args = [self._convert_expression_to_python(arg) for arg in expr_node.attributes.get("arguments", [])]
            return ast.Call(func=ast.Name(id=class_type, ctx=ast.Load()), args=args, keywords=[])

        elif expr_node.node_type == "array_access":
            array = self._convert_expression_to_python(expr_node.attributes.get("array"))
            index = self._convert_expression_to_python(expr_node.attributes.get("index"))
            return ast.Subscript(value=array, slice=index, ctx=ast.Load())

        elif expr_node.node_type == "this_reference":
            return ast.Name(id="self", ctx=ast.Load())

        return ast.Constant(value=None)

    def _create_name(self, name: str) -> ast.Name:
        return ast.Name(id=name, ctx=ast.Load())

    def _ir_to_java_ast(self, ir: IntermediateRepresentation) -> ast.Module:
        return ast.Module(body=[], type_ignores=[])

    def transpile(self, source_code: str, source_lang: str = "java", target_lang: str = "python") -> str:
        ir = self.parse_to_ir(source_code, source_lang)
        target_ast = self.ir_to_ast(ir, target_lang)
        return ast.unparse(target_ast)


class PythonASTParser(ASTTranspilerEngine):
    def parse_to_ir(self, source_code: str, source_lang: Optional[str] = None) -> IntermediateRepresentation:
        tree = ast.parse(source_code)
        ir = IntermediateRepresentation()
        ir.metadata["source_language"] = "python"

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                ir_node = self._convert_python_class_to_ir(node)
                ir.nodes.append(ir_node)
            elif isinstance(node, ast.FunctionDef):
                ir_node = self._convert_python_function_to_ir(node)
                ir.nodes.append(ir_node)

        return ir

    def _convert_python_class_to_ir(self, node: ast.ClassDef) -> IRNode:
        children = []
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                children.append(self._convert_python_function_to_ir(item))

        return IRNode(
            node_type="class_def",
            name=node.name,
            attributes={"bases": [base.attr if isinstance(base, ast.Attribute) else base.id for base in node.bases]},
            children=children,
            source_location=("", node.lineno, node.col_offset)
        )

    def _convert_python_function_to_ir(self, node: ast.FunctionDef) -> IRNode:
        params = []
        for arg in node.args.args:
            params.append({"name": arg.arg, "type": ""})

        body_children = []
        for stmt in node.body:
            body_children.append(self._convert_python_stmt_to_ir(stmt))

        body = IRNode(node_type="block", name="body", children=body_children)

        return IRNode(
            node_type="method_def",
            name=node.name,
            attributes={"parameters": params, "return_type": "Any"},
            children=[body],
            source_location=("", node.lineno, node.col_offset)
        )

    def _convert_python_stmt_to_ir(self, node: ast.stmt) -> IRNode:
        if isinstance(node, ast.Return):
            value = self._convert_python_expr_to_ir(node.value) if node.value else None
            return IRNode(node_type="return_statement", name="return", attributes={"value": value})
        elif isinstance(node, ast.If):
            test = self._convert_python_expr_to_ir(node.test)
            body = [self._convert_python_stmt_to_ir(s) for s in node.body]
            orelse = [self._convert_python_stmt_to_ir(s) for s in node.orelse]
            return IRNode(node_type="if_statement", name="if", attributes={"condition": test}, children=body + orelse)
        elif isinstance(node, ast.While):
            test = self._convert_python_expr_to_ir(node.test)
            body = [self._convert_python_stmt_to_ir(s) for s in node.body]
            return IRNode(node_type="while_statement", name="while", attributes={"condition": test}, children=body)
        elif isinstance(node, ast.For):
            target = self._convert_python_expr_to_ir(node.target)
            iter_ = self._convert_python_expr_to_ir(node.iter)
            body = [self._convert_python_stmt_to_ir(s) for s in node.body]
            return IRNode(node_type="for_statement", name="for", attributes={"target": target, "iter": iter_}, children=body)
        elif isinstance(node, ast.Assign):
            targets = [self._convert_python_expr_to_ir(t) for t in node.targets]
            value = self._convert_python_expr_to_ir(node.value)
            return IRNode(node_type="assignment", name="assign", attributes={"targets": targets, "value": value})
        elif isinstance(node, ast.Expr):
            return IRNode(node_type="expression_statement", name="expr", attributes={"expression": self._convert_python_expr_to_ir(node.value)})
        elif isinstance(node, ast.Pass):
            return IRNode(node_type="pass_statement", name="pass", attributes={})
        elif isinstance(node, ast.Break):
            return IRNode(node_type="break_statement", name="break", attributes={})
        elif isinstance(node, ast.Continue):
            return IRNode(node_type="continue_statement", name="continue", attributes={})
        return IRNode(node_type="unknown", name="unknown", attributes={})

    def _convert_python_expr_to_ir(self, node: ast.expr) -> IRNode:
        if isinstance(node, ast.Name):
            return IRNode(node_type="identifier", name=node.id, attributes={})
        elif isinstance(node, ast.Constant):
            return IRNode(node_type="literal", name="constant", attributes={"value": repr(node.value)})
        elif isinstance(node, ast.BinOp):
            left = self._convert_python_expr_to_ir(node.left)
            right = self._convert_python_expr_to_ir(node.right)
            op = self._get_python_op_name(node.op)
            return IRNode(node_type="binary_expression", name=op, attributes={"left": left, "right": right})
        elif isinstance(node, ast.UnaryOp):
            operand = self._convert_python_expr_to_ir(node.operand)
            op = self._get_python_op_name(node.op)
            return IRNode(node_type="unary_expression", name=op, attributes={"operand": operand})
        elif isinstance(node, ast.Call):
            func = self._convert_python_expr_to_ir(node.func)
            args = [self._convert_python_expr_to_ir(arg) for arg in node.args]
            return IRNode(node_type="call", name="call", attributes={"func": func, "arguments": args})
        elif isinstance(node, ast.Attribute):
            value = self._convert_python_expr_to_ir(node.value)
            return IRNode(node_type="attribute_access", name=node.attr, attributes={"value": value})
        elif isinstance(node, ast.Subscript):
            value = self._convert_python_expr_to_ir(node.value)
            index = self._convert_python_expr_to_ir(node.slice)
            return IRNode(node_type="subscript", name="subscript", attributes={"value": value, "index": index})
        elif isinstance(node, ast.List):
            elts = [self._convert_python_expr_to_ir(elt) for elt in node.elts]
            return IRNode(node_type="list_literal", name="list", attributes={"elements": elts})
        elif isinstance(node, ast.Dict):
            keys = [self._convert_python_expr_to_ir(k) for k in node.keys]
            values = [self._convert_python_expr_to_ir(v) for v in node.values]
            return IRNode(node_type="dict_literal", name="dict", attributes={"keys": keys, "values": values})
        elif isinstance(node, ast.IfExp):
            test = self._convert_python_expr_to_ir(node.test)
            body = self._convert_python_expr_to_ir(node.body)
            orelse = self._convert_python_expr_to_ir(node.orelse)
            return IRNode(node_type="conditional_expression", name="ternary", attributes={"test": test, "body": body, "orelse": orelse})
        elif isinstance(node, ast.Compare):
            left = self._convert_python_expr_to_ir(node.left)
            ops = [self._get_python_op_name(op) for op in node.ops]
            comparators = [self._convert_python_expr_to_ir(c) for c in node.comparators]
            return IRNode(node_type="comparison", name="compare", attributes={"left": left, "ops": ops, "comparators": comparators})
        elif isinstance(node, ast.BoolOp):
            op = self._get_python_op_name(node.op)
            values = [self._convert_python_expr_to_ir(v) for v in node.values]
            return IRNode(node_type="boolean_operation", name=op, attributes={"values": values})
        return IRNode(node_type="unknown_expr", name="unknown", attributes={})

    def _get_python_op_name(self, op: ast.operator) -> str:
        op_map = {
            ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/",
            ast.Mod: "%", ast.Pow: "**", ast.FloorDiv: "//", ast.BitAnd: "&",
            ast.BitOr: "|", ast.BitXor: "^", ast.LShift: "<<", ast.RShift: ">>",
            ast.Invert: "~", ast.Not: "not", ast.UAdd: "+", ast.USub: "-",
            ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.Gt: ">", ast.LtE: "<=", ast.GtE: ">=",
            ast.Is: "is", ast.In: "in", ast.IsNot: "is not", ast.NotIn: "not in",
            ast.And: "and", ast.Or: "or"
        }
        for key, value in op_map.items():
            if isinstance(op, key):
                return value
        return "unknown"

    def ir_to_ast(self, ir: IntermediateRepresentation, target_lang: str) -> ast.Module:
        if target_lang != "python":
            raise ValueError(f"PythonASTParser only supports Python target, got: {target_lang}")

        body = []
        for node in ir.nodes:
            py_node = self._ir_to_python_node(node)
            if py_node:
                body.append(py_node)

        return ast.Module(body=body, type_ignores=[])

    def _ir_to_python_node(self, ir_node: IRNode) -> Optional[ast.stmt]:
        if ir_node.node_type == "class_def":
            bases = [ast.Name(id=base, ctx=ast.Load()) for base in ir_node.attributes.get("bases", [])]
            body = []
            for child in ir_node.children:
                converted = self._ir_to_python_node(child)
                if converted:
                    body.append(converted)
            return ast.ClassDef(name=ir_node.name, bases=bases, keywords=[], body=body if body else [ast.Pass()], decorator_list=[], lineno=1, col_offset=0)

        elif ir_node.node_type == "method_def":
            args = ast.arguments(
                posonlyargs=[],
                args=[ast.arg(arg=param["name"], annotation=None) for param in ir_node.attributes.get("parameters", [])],
                kwonlyargs=[],
                kw_defaults=[],
                defaults=[]
            )
            body = []
            for child in ir_node.children:
                if child.node_type == "block":
                    for stmt in child.children:
                        converted_stmt = self._ir_stmt_to_python(stmt)
                        if converted_stmt:
                            body.append(converted_stmt)
            return ast.FunctionDef(name=ir_node.name, args=args, body=body if body else [ast.Pass()], decorator_list=[], returns=None, lineno=1, col_offset=0)

        return None

    def _ir_stmt_to_python(self, ir_stmt: IRNode) -> Optional[ast.stmt]:
        if ir_stmt.node_type == "return_statement":
            value = self._ir_expr_to_python(ir_stmt.attributes.get("value")) if ir_stmt.attributes.get("value") else None
            return ast.Return(value=value)
        elif ir_stmt.node_type == "if_statement":
            test = self._ir_expr_to_python(ir_stmt.attributes.get("condition"))
            body = [self._ir_stmt_to_python(s) for s in ir_stmt.children if s.node_type != "else"]
            orelse = [self._ir_stmt_to_python(s) for s in ir_stmt.children if s.node_type == "else"]
            return ast.If(test=test, body=body if body else [ast.Pass()], orelse=orelse if orelse else [])
        elif ir_stmt.node_type == "while_statement":
            test = self._ir_expr_to_python(ir_stmt.attributes.get("condition"))
            body = [self._ir_stmt_to_python(s) for s in ir_stmt.children]
            return ast.While(test=test, body=body if body else [ast.Pass()], orelse=[])
        elif ir_stmt.node_type == "for_statement":
            target = self._ir_expr_to_python(ir_stmt.attributes.get("target"))
            iter_ = self._ir_expr_to_python(ir_stmt.attributes.get("iter"))
            body = [self._ir_stmt_to_python(s) for s in ir_stmt.children]
            return ast.For(target=target, iter=iter_, body=body if body else [ast.Pass()], orelse=[])
        elif ir_stmt.node_type == "assignment":
            targets = [self._ir_expr_to_python(t) for t in ir_stmt.attributes.get("targets", [])]
            value = self._ir_expr_to_python(ir_stmt.attributes.get("value"))
            return ast.Assign(targets=targets, value=value)
        elif ir_stmt.node_type == "expression_statement":
            return ast.Expr(value=self._ir_expr_to_python(ir_stmt.attributes.get("expression")))
        elif ir_stmt.node_type == "pass_statement":
            return ast.Pass()
        elif ir_stmt.node_type == "break_statement":
            return ast.Break()
        elif ir_stmt.node_type == "continue_statement":
            return ast.Continue()
        return None

    def _ir_expr_to_python(self, ir_expr: IRNode) -> ast.expr:
        if ir_expr.node_type == "identifier":
            return ast.Name(id=ir_expr.name, ctx=ast.Load())
        elif ir_expr.node_type == "literal":
            value_str = ir_expr.attributes.get("value", "")
            try:
                if value_str.startswith(("'", '"')):
                    return ast.Constant(value=value_str[1:-1])
                elif value_str.replace(".", "", 1).isdigit():
                    if "." in value_str:
                        return ast.Constant(value=float(value_str))
                    return ast.Constant(value=int(value_str))
                elif value_str in ["True", "False"]:
                    return ast.Constant(value=value_str == "True")
            except ValueError:
                pass
            return ast.Constant(value=None)
        elif ir_expr.node_type == "binary_expression":
            left = self._ir_expr_to_python(ir_expr.attributes.get("left"))
            right = self._ir_expr_to_python(ir_expr.attributes.get("right"))
            op = self._python_op_from_string(ir_expr.attributes.get("operator", "+"))
            return ast.BinOp(left=left, op=op, right=right)
        elif ir_expr.node_type == "call":
            func = self._ir_expr_to_python(ir_expr.attributes.get("func"))
            args = [self._ir_expr_to_python(a) for a in ir_expr.attributes.get("arguments", [])]
            return ast.Call(func=func, args=args, keywords=[])
        elif ir_expr.node_type == "attribute_access":
            value = self._ir_expr_to_python(ir_expr.attributes.get("value"))
            return ast.Attribute(value=value, attr=ir_expr.name, ctx=ast.Load())
        elif ir_expr.node_type == "subscript":
            value = self._ir_expr_to_python(ir_expr.attributes.get("value"))
            index = self._ir_expr_to_python(ir_expr.attributes.get("index"))
            return ast.Subscript(value=value, slice=index, ctx=ast.Load())
        elif ir_expr.node_type == "conditional_expression":
            test = self._ir_expr_to_python(ir_expr.attributes.get("test"))
            body = self._ir_expr_to_python(ir_expr.attributes.get("body"))
            orelse = self._ir_expr_to_python(ir_expr.attributes.get("orelse"))
            return ast.IfExp(test=test, body=body, orelse=orelse)
        elif ir_expr.node_type == "list_literal":
            elts = [self._ir_expr_to_python(e) for e in ir_expr.attributes.get("elements", [])]
            return ast.List(elts=elts, ctx=ast.Load())
        elif ir_expr.node_type == "dict_literal":
            keys = [self._ir_expr_to_python(k) for k in ir_expr.attributes.get("keys", [])]
            values = [self._ir_expr_to_python(v) for v in ir_expr.attributes.get("values", [])]
            return ast.Dict(keys=keys, values=values)
        elif ir_expr.node_type == "comparison":
            left = self._ir_expr_to_python(ir_expr.attributes.get("left"))
            ops = [self._python_op_from_string(op) for op in ir_expr.attributes.get("ops", [])]
            comparators = [self._ir_expr_to_python(c) for c in ir_expr.attributes.get("comparators", [])]
            return ast.Compare(left=left, ops=ops, comparators=comparators)
        elif ir_expr.node_type == "boolean_operation":
            op = self._python_bool_op_from_string(ir_expr.name)
            values = [self._ir_expr_to_python(v) for v in ir_expr.attributes.get("values", [])]
            return ast.BoolOp(op=op, values=values)
        return ast.Constant(value=None)

    def _python_op_from_string(self, op_str: str) -> ast.operator:
        op_map = {
            "+": ast.Add(), "-": ast.Sub(), "*": ast.Mult(), "/": ast.Div(),
            "%": ast.Mod(), "**": ast.Pow(), "//": ast.FloorDiv(),
            "&": ast.BitAnd(), "|": ast.BitOr(), "^": ast.BitXor(),
            "<<": ast.LShift(), ">>": ast.RShift()
        }
        return op_map.get(op_str, ast.Add())

    def _python_bool_op_from_string(self, op_str: str) -> ast.boolop:
        if op_str == "and":
            return ast.And()
        return ast.Or()

    def transpile(self, source_code: str, source_lang: str = "python", target_lang: str = "python") -> str:
        ir = self.parse_to_ir(source_code, source_lang)
        target_ast = self.ir_to_ast(ir, target_lang)
        return ast.unparse(target_ast)


class CPPASTParser(ASTTranspilerEngine):
    def __init__(self):
        super().__init__()

    def parse_to_ir(self, source_code: str, source_lang: Optional[str] = None) -> IntermediateRepresentation:
        if self._tree_sitter is not None:
            return self._tree_sitter.parse(source_code, "cpp")
        return self._fallback_parse(source_code)

    def _fallback_parse(self, source_code: str) -> IntermediateRepresentation:
        ir = IntermediateRepresentation()
        ir.metadata["source_language"] = "cpp"

        class_match = re.search(r'class\s+(\w+)', source_code)
        if class_match:
            ir.nodes.append(IRNode(
                node_type="class_def",
                name=class_match.group(1),
                attributes={}
            ))

        func_matches = re.findall(r'(?:void|int|float|double|char|bool|auto)\s+(\w+)\s*\(', source_code)
        for func_name in func_matches:
            ir.nodes.append(IRNode(
                node_type="function_def",
                name=func_name,
                attributes={"return_type": "unknown", "parameters": []}
            ))

        return ir

    def ir_to_ast(self, ir: IntermediateRepresentation, target_lang: str) -> ast.Module:
        if target_lang == "python":
            return self._ir_to_python_ast(ir)
        elif target_lang == "cpp":
            return ast.Module(body=[], type_ignores=[])
        else:
            raise ValueError(f"Unsupported target language: {target_lang}")

    def _ir_to_python_ast(self, ir: IntermediateRepresentation) -> ast.Module:
        body = []
        for node in ir.nodes:
            if node.node_type == "class_def":
                class_def = ast.ClassDef(
                    name=node.name,
                    bases=[],
                    keywords=[],
                    body=[ast.Pass()],
                    decorator_list=[],
                    lineno=1,
                    col_offset=0
                )
                body.append(class_def)
            elif node.node_type == "function_def":
                func_def = ast.FunctionDef(
                    name=node.name,
                    args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                    body=[ast.Pass()],
                    decorator_list=[],
                    returns=None,
                    lineno=1,
                    col_offset=0
                )
                body.append(func_def)

        return ast.Module(body=body, type_ignores=[])

    def transpile(self, source_code: str, source_lang: str = "cpp", target_lang: str = "python") -> str:
        ir = self.parse_to_ir(source_code, source_lang)
        target_ast = self.ir_to_ast(ir, target_lang)
        return ast.unparse(target_ast)


class RustASTParser(ASTTranspilerEngine):
    def __init__(self):
        super().__init__()

    def parse_to_ir(self, source_code: str, source_lang: Optional[str] = None) -> IntermediateRepresentation:
        if self._tree_sitter is not None:
            return self._tree_sitter.parse(source_code, "rust")
        return self._fallback_parse(source_code)

    def _fallback_parse(self, source_code: str) -> IntermediateRepresentation:
        ir = IntermediateRepresentation()
        ir.metadata["source_language"] = "rust"

        struct_match = re.search(r'struct\s+(\w+)', source_code)
        if struct_match:
            ir.nodes.append(IRNode(
                node_type="struct_def",
                name=struct_match.group(1),
                attributes={}
            ))

        fn_matches = re.findall(r'fn\s+(\w+)\s*\(', source_code)
        for fn_name in fn_matches:
            ir.nodes.append(IRNode(
                node_type="function_def",
                name=fn_name,
                attributes={"return_type": "unknown", "parameters": []}
            ))

        impl_matches = re.findall(r'impl\s+(?:<\w+>\s*)?(\w+)', source_code)
        for impl_name in impl_matches:
            ir.nodes.append(IRNode(
                node_type="impl_block",
                name=impl_name,
                attributes={}
            ))

        return ir

    def ir_to_ast(self, ir: IntermediateRepresentation, target_lang: str) -> ast.Module:
        if target_lang == "python":
            return self._ir_to_python_ast(ir)
        elif target_lang == "rust":
            return ast.Module(body=[], type_ignores=[])
        else:
            raise ValueError(f"Unsupported target language: {target_lang}")

    def _ir_to_python_ast(self, ir: IntermediateRepresentation) -> ast.Module:
        body = []
        for node in ir.nodes:
            if node.node_type in ["struct_def", "impl_block"]:
                class_def = ast.ClassDef(
                    name=node.name,
                    bases=[],
                    keywords=[],
                    body=[ast.Pass()],
                    decorator_list=[],
                    lineno=1,
                    col_offset=0
                )
                body.append(class_def)
            elif node.node_type == "function_def":
                func_def = ast.FunctionDef(
                    name=node.name,
                    args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                    body=[ast.Pass()],
                    decorator_list=[],
                    returns=None,
                    lineno=1,
                    col_offset=0
                )
                body.append(func_def)

        return ast.Module(body=body, type_ignores=[])

    def transpile(self, source_code: str, source_lang: str = "rust", target_lang: str = "python") -> str:
        ir = self.parse_to_ir(source_code, source_lang)
        target_ast = self.ir_to_ast(ir, target_lang)
        return ast.unparse(target_ast)


class GoASTParser(ASTTranspilerEngine):
    def __init__(self):
        super().__init__()

    def parse_to_ir(self, source_code: str, source_lang: Optional[str] = None) -> IntermediateRepresentation:
        if self._tree_sitter is not None:
            return self._tree_sitter.parse(source_code, "go")
        return self._fallback_parse(source_code)

    def _fallback_parse(self, source_code: str) -> IntermediateRepresentation:
        ir = IntermediateRepresentation()
        ir.metadata["source_language"] = "go"

        lines = source_code.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("func ") and "(" not in stripped[:10]:
                func_match = re.match(r'func\s+(\w+)\s*\(', stripped)
                if func_match:
                    func_name = func_match.group(1)
                    func_node = IRNode(
                        node_type="function_def",
                        name=func_name,
                        attributes={},
                        source_location=("", i, 0)
                    )
                    ir.nodes.append(func_node)

            elif stripped.startswith("func "):
                func_match = re.match(r'func\s+(\([^)]+\))\s*(\w+)\s*\(', stripped)
                if func_match:
                    receiver = func_match.group(1)
                    func_name = func_match.group(2)
                    func_node = IRNode(
                        node_type="method_def",
                        name=func_name,
                        attributes={"receiver": receiver},
                        source_location=("", i, 0)
                    )
                    ir.nodes.append(func_node)

            elif stripped.startswith("type "):
                type_match = re.match(r'type\s+(\w+)\s+struct', stripped)
                if type_match:
                    type_name = type_match.group(1)
                    type_node = IRNode(
                        node_type="struct_def",
                        name=type_name,
                        attributes={},
                        source_location=("", i, 0)
                    )
                    ir.nodes.append(type_node)

        return ir

    def ir_to_ast(self, ir: IntermediateRepresentation, target_lang: str) -> ast.Module:
        if target_lang == "python":
            return self._ir_to_python_ast(ir)
        elif target_lang == "go":
            return ast.Module(body=[], type_ignores=[])
        else:
            raise ValueError(f"Unsupported target language: {target_lang}")

    def _ir_to_python_ast(self, ir: IntermediateRepresentation) -> ast.Module:
        body = []
        for node in ir.nodes:
            if node.node_type in ["function_def", "method_def"]:
                func_def = ast.FunctionDef(
                    name=node.name,
                    args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                    body=[ast.Pass()],
                    decorator_list=[],
                    returns=None,
                    lineno=1,
                    col_offset=0
                )
                body.append(func_def)
            elif node.node_type == "struct_def":
                class_def = ast.ClassDef(
                    name=node.name,
                    bases=[],
                    keywords=[],
                    body=[ast.Pass()],
                    decorator_list=[],
                    lineno=1,
                    col_offset=0
                )
                body.append(class_def)

        return ast.Module(body=body, type_ignores=[])

    def transpile(self, source_code: str, source_lang: str = "go", target_lang: str = "python") -> str:
        ir = self.parse_to_ir(source_code, source_lang)
        target_ast = self.ir_to_ast(ir, target_lang)
        return ast.unparse(target_ast)


if __name__ == "__main__":
    java_code = """
    public class HelloWorld {
        public static void main(String[] args) {
            System.out.println("Hello, World!");
        }
    }
    """

    java_parser = JavaASTParser()
    ir = java_parser.parse_to_ir(java_code)
    print("Java IR nodes:")
    for node in ir.nodes:
        print(f"  {node}")

    python_code = """
    def hello():
        print("Hello, World!")
    """

    python_parser = PythonASTParser()
    ir = python_parser.parse_to_ir(python_code)
    print("\nPython IR nodes:")
    for node in ir.nodes:
        print(f"  {node}")

    cpp_code = """
    class MyClass {
    public:
        void myMethod();
    };
    """

    cpp_parser = CPPASTParser()
    ir = cpp_parser.parse_to_ir(cpp_code)
    print("\nC++ IR nodes:")
    for node in ir.nodes:
        print(f"  {node}")

    rust_code = """
    struct MyStruct {
        value: i32,
    }

    fn my_function() {
        println!("Hello");
    }
    """

    rust_parser = RustASTParser()
    ir = rust_parser.parse_to_ir(rust_code)
    print("\nRust IR nodes:")
    for node in ir.nodes:
        print(f"  {node}")

    go_code = """
    func main() {
        fmt.Println("Hello, World!")
    }
    """

    go_parser = GoASTParser()
    ir = go_parser.parse_to_ir(go_code)
    print("\nGo IR nodes:")
    for node in ir.nodes:
        print(f"  {node}")

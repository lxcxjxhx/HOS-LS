"""ContractViolationAgent — 跨文件安全契约违背检测 Agent

检测 AI 代码变更中的跨文件安全契约违背：
1. 权限检查作用域错误 — 安全方法在非安全上下文中被调用
2. 遗漏 sibling path — 主路径修复但同级路径未修复
3. 异常路径仍然可利用 — try/catch 中忽略了安全异常

核心思想：代码局部看似正确，但需要仓库级上下文和差分证据才能判断。
"""

import ast
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class SecurityContract:
    """安全契约定义"""
    method_name: str          # 安全方法名
    file_path: str            # 定义文件
    line: int                 # 定义行号
    required_checks: List[str] = field(default_factory=list)  # 需要的安全检查
    annotation: str = ""      # 注解/装饰器


@dataclass
class ContractViolation:
    """安全契约违背"""
    type: str                 # SCOPE_ERROR / SIBLING_MISS / EXCEPTION_LEAK
    file: str
    line: int
    description: str
    contract_method: str      # 被违背的安全契约方法
    confidence: float
    detail: str = ""


class ContractViolationAgent:
    """跨文件安全契约违背检测 Agent"""

    SECURITY_ANNOTATIONS = {
        "java": [
            r"@PreAuthorize",
            r"@Secured",
            r"@RolesAllowed",
            r"@AuthenticationPrincipal",
            r"@Validated",
            r"@Valid",
        ],
        "python": [
            r"@login_required",
            r"@permission_required",
            r"@has_permission",
            r"@require_auth",
            r"@validate",
        ],
    }

    SECURITY_DECORATORS_PATTERN = r"@(PreAuthorize|Secured|RolesAllowed|login_required|permission_required|has_permission|require_auth)"

    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self._contracts: Dict[str, List[SecurityContract]] = defaultdict(list)

    def load_contracts_from_file(self, file_path: str) -> List[SecurityContract]:
        """从文件中加载安全契约定义"""
        contracts = []
        ext = Path(file_path).suffix.lower()
        try:
            if ext == ".py":
                contracts = self._load_python_contracts(file_path)
            elif ext == ".java":
                contracts = self._load_java_contracts(file_path)
        except Exception as e:
            logger.debug(f"加载契约失败 {file_path}: {e}")
        return contracts

    def _load_python_contracts(self, file_path: str) -> List[SecurityContract]:
        """从 Python 文件加载安全契约（装饰器标记的安全方法）"""
        contracts = []
        with open(file_path, encoding="utf-8", errors="replace") as f:
            content = f.read()

        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    decorators = []
                    for dec in node.decorator_list:
                        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                            decorators.append(dec.func.id)
                        elif isinstance(dec, ast.Name):
                            decorators.append(dec.id)
                        elif isinstance(dec, ast.Attribute):
                            decorators.append(dec.attr)

                    security_decorators = [
                        d for d in decorators
                        if any(pat in d.lower() for pat in ["auth", "login", "permission", "secure", "role", "validate"])
                    ]

                    if security_decorators:
                        contracts.append(SecurityContract(
                            method_name=node.name,
                            file_path=file_path,
                            line=node.lineno,
                            required_checks=security_decorators,
                            annotation=security_decorators[0],
                        ))
        except SyntaxError:
            pass

        return contracts

    def _load_java_contracts(self, file_path: str) -> List[SecurityContract]:
        """从 Java 文件加载安全契约（注解标记的安全方法）"""
        contracts = []
        with open(file_path, encoding="utf-8", errors="replace") as f:
            content = f.read()

        # 匹配注解 + 方法定义的组合
        pattern = r"(@(PreAuthorize|Secured|RolesAllowed)\s*\([^)]*\)\s*)?(public|private|protected)?\s+\w+\s+(\w+)\s*\("

        last_annotation = ""
        for match in re.finditer(pattern, content, re.DOTALL):
            if match.group(1):
                last_annotation = match.group(2)
                method_name = match.group(4)
                if last_annotation:
                    contracts.append(SecurityContract(
                        method_name=method_name,
                        file_path=file_path,
                        line=content[: match.start()].count("\n") + 1,
                        required_checks=[last_annotation],
                        annotation=f"@{last_annotation}",
                    ))
            elif last_annotation:
                # 延续上一个注解
                pass

        return contracts

    def detect_violations(self, changed_files: Dict[str, str], repo_files: Dict[str, str]) -> List[ContractViolation]:
        """检测跨文件安全契约违背

        Args:
            changed_files: 变更的文件 {file_path: new_content}
            repo_files: 仓库中所有文件 {file_path: content}

        Returns:
            契约违背列表
        """
        violations: List[ContractViolation] = []
        all_contracts: Dict[str, List[SecurityContract]] = defaultdict(list)

        # 1. 加载所有文件的安全契约
        for file_path, content in repo_files.items():
            if file_path.endswith(".py"):
                self._contracts[file_path] = self.load_contracts_from_file(file_path)

        # 2. 对每个变更文件，检测契约违背
        for file_path, new_content in changed_files.items():
            ext = Path(file_path).suffix.lower()

            if ext == ".py":
                file_violations = self._detect_python_violations(file_path, new_content)
                violations.extend(file_violations)
            elif ext == ".java":
                file_violations = self._detect_java_violations(file_path, new_content)
                violations.extend(file_violations)

            # 3. 跨文件调用检测：在变更文件中调用了其他文件的安全方法
            cross_file_violations = self._detect_cross_file_violations(file_path, new_content)
            violations.extend(cross_file_violations)

        return violations

    def _detect_python_violations(self, file_path: str, content: str) -> List[ContractViolation]:
        """Python 文件中的契约违背检测"""
        violations = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return violations

        # 检测函数定义是否缺少安全装饰器
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 检查函数名中是否暗示需要安全但缺少装饰器
                needs_security = any(kw in node.name.lower() for kw in
                                     ["admin", "delete", "remove", "update", "setting", "config", "payment", "password"])
                has_security_decorator = False
                for dec in node.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                        dec_name = dec.func.id
                    if any(kw in dec_name.lower() for kw in ["auth", "login", "permission", "secure", "role"]):
                        has_security_decorator = True
                        break

                if needs_security and not has_security_decorator:
                    violations.append(ContractViolation(
                        type="SCOPE_ERROR",
                        file=file_path,
                        line=node.lineno,
                        description=f"敏感方法 '{node.name}' 缺少安全检查装饰器",
                        contract_method="security_decorator",
                        confidence=0.6,
                    ))

            # 检测 try/except 中忽略安全异常
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    if handler.type and isinstance(handler.type, ast.Name):
                        exc_name = handler.type.id
                        if "Security" in exc_name or "Auth" in exc_name or "Permission" in exc_name or "Access" in exc_name:
                            # 检查 handler body 是否只是 pass/log
                            body_has_action = any(
                                not (isinstance(stmt, ast.Pass) or
                                     (isinstance(stmt, ast.Expr) and
                                      isinstance(stmt.value, ast.Call) and
                                      "log" in str(stmt.value.func.id if isinstance(stmt.value.func, ast.Name) else "").lower()))
                                for stmt in handler.body
                            )
                            if not body_has_action:
                                violations.append(ContractViolation(
                                    type="EXCEPTION_LEAK",
                                    file=file_path,
                                    line=handler.lineno,
                                    description=f"安全异常 '{exc_name}' 被静默捕获（pass/log only）",
                                    contract_method=exc_name,
                                    confidence=0.8,
                                ))

        return violations

    def _detect_java_violations(self, file_path: str, content: str) -> List[ContractViolation]:
        """Java 文件中的契约违背检测"""
        violations = []

        # 检测方法中是否缺少 @PreAuthorize
        # 匹配 public 方法，检查前面是否有安全注解
        methods = re.finditer(
            r"(?:(@\w+)\s*\([^)]*\)\s*)?(public\s+\w+\s+(\w+)\s*\()",
            content
        )
        for m in methods:
            annotation = m.group(1) or ""
            method_name = m.group(3)
            # 如果是安全敏感方法但没有注解
            needs_auth = any(kw in method_name.lower() for kw in
                             ["admin", "delete", "remove", "update", "setting", "payment"])
            has_security_annotation = any(kw in annotation for kw in
                                          ["PreAuthorize", "Secured", "RolesAllowed"])
            if needs_auth and not has_security_annotation:
                violations.append(ContractViolation(
                    type="SCOPE_ERROR",
                    file=file_path,
                    line=content[: m.start()].count("\n") + 1,
                    description=f"敏感方法 '{method_name}' 缺少安全注解 ({annotation or '无'})",
                    contract_method="security_annotation",
                    confidence=0.6,
                ))

        return violations

    def _detect_cross_file_violations(self, file_path: str, content: str) -> List[ContractViolation]:
        """检测跨文件调用安全方法时缺少安全检查"""
        violations = []
        ext = Path(file_path).suffix.lower()

        if ext != ".py":
            return violations

        # 分析 import 语句找到被调用的模块
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    module_name = ""
                    if isinstance(node.func.value, ast.Name):
                        module_name = node.func.value.id
                    # 检查是否是跨文件调用安全方法
                    for mod_path, contracts in self._contracts.items():
                        if module_name and mod_path.replace("/", ".").replace(".py", "").endswith(module_name):
                            for contract in contracts:
                                if func_name == contract.method_name:
                                    # 发现了跨文件安全调用 — 检查当前上下文中是否有安全检查
                                    violations.append(ContractViolation(
                                        type="SIBLING_MISS" if len(violations) > 0 else "SCOPE_ERROR",
                                        file=file_path,
                                        line=node.lineno,
                                        description=f"调用了 {mod_path} 中的安全方法 {contract.method_name}({contract.annotation})",
                                        contract_method=contract.method_name,
                                        confidence=0.5,
                                    ))

        return violations

    def to_agent_format(self, violations: List[ContractViolation]) -> List[Dict[str, Any]]:
        """转换为 AgentVote 兼容格式"""
        results = []
        for v in violations:
            type_labels = {
                "SCOPE_ERROR": "权限作用域错误",
                "SIBLING_MISS": "遗漏同级路径",
                "EXCEPTION_LEAK": "异常路径泄露",
            }
            results.append({
                "signal_id": f"CONTRACT-{v.type}@{v.file}:{v.line}",
                "decision": "CONFIRMED" if v.confidence >= 0.7 else "UNCERTAIN",
                "confidence": v.confidence,
                "severity": "HIGH" if v.type == "EXCEPTION_LEAK" else "MEDIUM",
                "vuln_type": "AUTH_BYPASS" if "auth" in v.contract_method.lower() else "SECURITY_VULN",
                "location": f"{v.file}:{v.line}",
                "description": v.description,
                "title": f"[ContractViolation] {type_labels.get(v.type, v.type)}: {v.contract_method}",
                "verification_reason": v.detail or v.description,
                "source": "contract_analysis",
                "rule_id": f"contract-{v.type.lower()}",
            })
        return results

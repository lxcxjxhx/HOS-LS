"""上下文分析器模块

追踪 MyBatis Mapper 的服务层调用链，判断 SQL 注入参数是否可控，从而识别误报。
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ContextResult:
    """上下文分析结果"""

    is_hardcoded: bool
    is_user_controllable: bool
    confidence: float
    is_false_positive: bool
    reason: str
    service_layer_file: Optional[str] = None
    service_layer_method: Optional[str] = None
    mapper_interface: Optional[str] = None
    mapper_method: Optional[str] = None
    hardcoded_params: List[str] = field(default_factory=list)
    user_controllable_params: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_hardcoded": self.is_hardcoded,
            "is_user_controllable": self.is_user_controllable,
            "confidence": self.confidence,
            "is_false_positive": self.is_false_positive,
            "reason": self.reason,
            "service_layer_file": self.service_layer_file,
            "service_layer_method": self.service_layer_method,
            "mapper_interface": self.mapper_interface,
            "mapper_method": self.mapper_method,
            "hardcoded_params": self.hardcoded_params,
            "user_controllable_params": self.user_controllable_params,
            "metadata": self.metadata,
        }


class ContextAnalyzer:
    """上下文分析器 - 追踪服务层调用链"""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self._cache: Dict[str, Any] = {}
        self._mapper_to_service_cache: Dict[str, List[Dict]] = {}

    def analyze_mapper_call(
        self, mapper_file: str, mapper_method: str, line_number: int
    ) -> ContextResult:
        """分析 Mapper 方法的调用上下文

        Args:
            mapper_file: Mapper XML 或接口文件路径
            mapper_method: Mapper 方法名 (如 "findByProperty")
            line_number: 代码行号

        Returns:
            ContextResult: 包含分析结果
        """
        mapper_interface = self._resolve_mapper_interface(mapper_file)
        if not mapper_interface:
            mapper_interface = Path(mapper_file).stem

        service_callers = self.find_service_layer_callers(mapper_interface, mapper_method)

        if not service_callers:
            return ContextResult(
                is_hardcoded=False,
                is_user_controllable=True,
                confidence=0.3,
                is_false_positive=False,
                reason=f"未找到服务层调用者，无法判断是否为误报（Mapper: {mapper_interface}.{mapper_method}）",
                mapper_interface=mapper_interface,
                mapper_method=mapper_method,
            )

        all_hardcoded = True
        all_user_controllable = False
        hardcoded_params: List[str] = []
        user_controllable_params: List[str] = []
        reasons: List[str] = []
        best_caller: Optional[Dict] = None
        best_confidence = 0.0

        for caller in service_callers:
            is_hardcoded = self.is_parameter_hardcoded(caller)
            caller_confidence = self._calculate_confidence(caller, is_hardcoded)

            if caller_confidence > best_confidence:
                best_confidence = caller_confidence
                best_caller = caller

            if is_hardcoded:
                hardcoded_params.extend(caller.get("hardcoded_args", []))
                reasons.append(
                    f"服务层 {caller['file']}::{caller['method']} 调用时参数硬编码"
                )
            else:
                all_hardcoded = False
                user_controllable_params.extend(caller.get("user_args", []))
                reasons.append(
                    f"服务层 {caller['file']}::{caller['method']} 调用时参数来自用户输入"
                )

        if best_caller:
            service_layer_file = best_caller["file"]
            service_layer_method = best_caller["method"]
        else:
            service_layer_file = None
            service_layer_method = None

        if all_hardcoded and hardcoded_params:
            return ContextResult(
                is_hardcoded=True,
                is_user_controllable=False,
                confidence=best_confidence,
                is_false_positive=True,
                reason="; ".join(reasons) if reasons else "所有服务层调用参数均为硬编码",
                service_layer_file=service_layer_file,
                service_layer_method=service_layer_method,
                mapper_interface=mapper_interface,
                mapper_method=mapper_method,
                hardcoded_params=list(set(hardcoded_params)),
                user_controllable_params=[],
            )
        elif not all_hardcoded and user_controllable_params:
            return ContextResult(
                is_hardcoded=False,
                is_user_controllable=True,
                confidence=best_confidence,
                is_false_positive=False,
                reason="; ".join(reasons) if reasons else "服务层调用参数包含用户输入",
                service_layer_file=service_layer_file,
                service_layer_method=service_layer_method,
                mapper_interface=mapper_interface,
                mapper_method=mapper_method,
                hardcoded_params=list(set(hardcoded_params)),
                user_controllable_params=list(set(user_controllable_params)),
            )
        else:
            mixed_reasons = reasons if reasons else ["无法确定参数来源"]
            return ContextResult(
                is_hardcoded=False,
                is_user_controllable=True,
                confidence=0.5,
                is_false_positive=False,
                reason="; ".join(mixed_reasons),
                service_layer_file=service_layer_file,
                service_layer_method=service_layer_method,
                mapper_interface=mapper_interface,
                mapper_method=mapper_method,
                hardcoded_params=list(set(hardcoded_params)),
                user_controllable_params=list(set(user_controllable_params)),
            )

    def find_service_layer_callers(
        self, mapper_interface: str, mapper_method: str
    ) -> List[Dict]:
        """查找服务层调用者

        Args:
            mapper_interface: Mapper 接口名 (如 "AdminMapper")
            mapper_method: Mapper 方法名 (如 "findByProperty")

        Returns:
            List of Dict: [{'file': xxx, 'method': yyy, 'line': zzz, 'params': [...]}]
        """
        cache_key = f"{mapper_interface}:{mapper_method}"
        if cache_key in self._mapper_to_service_cache:
            return self._mapper_to_service_cache[cache_key]

        callers: List[Dict] = []

        mapper_var_pattern = self._get_mapper_variable_pattern(mapper_interface)
        if not mapper_var_pattern:
            return []

        service_files = self._find_service_files()
        for service_file in service_files:
            file_callers = self._search_caller_in_file(
                service_file, mapper_var_pattern, mapper_method
            )
            callers.extend(file_callers)

        self._mapper_to_service_cache[cache_key] = callers
        return callers

    def is_parameter_hardcoded(self, service_call: Dict) -> bool:
        """判断服务层调用的参数是否硬编码

        例如:
        - adminMapper.findByProperty("username", username)  # username 可能来自用户输入
        - adminMapper.findByProperty("username", "admin")   # "admin" 是硬编码

        Args:
            service_call: 服务层调用信息

        Returns:
            bool: 参数是否硬编码
        """
        args = service_call.get("args", [])
        if not args:
            return True

        method_params = service_call.get("method_params", [])
        user_args: List[str] = []
        hardcoded_args: List[str] = []

        for i, arg in enumerate(args):
            if self._is_hardcoded_value(arg):
                hardcoded_args.append(arg)
            elif self._is_method_parameter(arg, method_params):
                user_args.append(arg)
            else:
                user_args.append(arg)

        service_call["hardcoded_args"] = hardcoded_args
        service_call["user_args"] = user_args

        return len(user_args) == 0 and len(hardcoded_args) > 0

    def _resolve_mapper_interface(self, mapper_file: str) -> Optional[str]:
        """解析 Mapper 接口名

        Args:
            mapper_file: Mapper 文件路径

        Returns:
            Mapper 接口名
        """
        path = Path(mapper_file)
        if path.suffix == ".xml":
            cache_key = f"xml:{mapper_file}"
            if cache_key in self._cache:
                return self._cache[cache_key]

            result = self._extract_mapper_name_from_xml(mapper_file)
            self._cache[cache_key] = result
            return result
        elif path.suffix == ".java":
            return path.stem
        return None

    def _extract_mapper_name_from_xml(self, xml_file: str) -> Optional[str]:
        """从 Mapper XML 文件中提取 Mapper 接口名

        Args:
            xml_file: Mapper XML 文件路径

        Returns:
            Mapper 接口名
        """
        try:
            content = Path(xml_file).read_text(encoding="utf-8")
            namespace_match = re.search(r'namespace\s*=\s*["\']([^"\']+)["\']', content)
            if namespace_match:
                namespace = namespace_match.group(1)
                return namespace.split(".")[-1]
        except Exception:
            pass
        return None

    def _get_mapper_variable_pattern(self, mapper_interface: str) -> Optional[str]:
        """获取 Mapper 变量名的正则模式

        Args:
            mapper_interface: Mapper 接口名

        Returns:
            正则表达式模式
        """
        uncapitalized = mapper_interface[0].lower() + mapper_interface[1:] if mapper_interface else ""
        return rf"\b(\w*{uncapitalized}\w*)\b"

    def _find_service_files(self) -> List[Path]:
        """查找所有服务层文件

        Returns:
            服务层文件路径列表
        """
        service_files: List[Path] = []

        patterns = [
            "**/service/impl/*.java",
            "**/service/*.java",
            "**/service/*Service.java",
            "**/*ServiceImpl.java",
            "**/controller/*.java",
            "**/web/*.java",
        ]

        for pattern in patterns:
            service_files.extend(self.project_root.glob(pattern))

        return list(set(service_files))

    def _search_caller_in_file(
        self, file_path: Path, mapper_pattern: str, mapper_method: str
    ) -> List[Dict]:
        """在文件中搜索 Mapper 调用者

        Args:
            file_path: 文件路径
            mapper_pattern: Mapper 变量名正则模式
            mapper_method: Mapper 方法名

        Returns:
            调用者信息列表
        """
        callers: List[Dict] = []

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return callers

        method_pattern = rf"(\w+)\s*\(\s*([^)]*)\s*\)"
        method_matches = list(re.finditer(method_pattern, content))

        call_pattern = rf"{mapper_pattern}\s*\.\s*{mapper_method}\s*\(\s*([^)]*)\s*\)"
        call_matches = list(re.finditer(call_pattern, content, re.MULTILINE))

        for match in call_matches:
            full_match = match.group(0)
            line_number = content[: match.start()].count("\n") + 1

            args_str = match.group(1) if match.groups() else ""
            args = [arg.strip() for arg in args_str.split(",") if arg.strip()]

            enclosing_method = self._find_enclosing_method(
                content, match.start(), method_matches
            )

            caller: Dict[str, Any] = {
                "file": str(file_path),
                "method": enclosing_method.get("name", "unknown"),
                "line": line_number,
                "args": args,
                "method_params": enclosing_method.get("params", []),
                "raw_call": full_match,
            }
            callers.append(caller)

        return callers

    def _find_enclosing_method(
        self, content: str, position: int, method_matches: List[re.Match]
    ) -> Dict[str, Any]:
        """查找包含指定位置的方法

        Args:
            content: 文件内容
            position: 位置
            method_matches: 方法匹配列表

        Returns:
            方法信息
        """
        method_info: Dict[str, Any] = {"name": "unknown", "params": []}

        for method_match in method_matches:
            if method_match.start() < position:
                method_start = method_match.start()
                method_text = method_match.group(0)

                brace_count = 0
                method_end = method_start
                for i in range(method_start, len(content)):
                    if content[i] == "{":
                        brace_count += 1
                    elif content[i] == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            method_end = i
                            break

                if method_start <= position <= method_end:
                    method_name_match = re.search(
                        r"(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(",
                        method_text,
                    )
                    if method_name_match:
                        method_info["name"] = method_name_match.group(1)

                    params_match = re.search(r"\(\s*([^)]*)\s*\)", method_text)
                    if params_match and params_match.group(1).strip():
                        params_str = params_match.group(1).strip()
                        method_info["params"] = [
                            p.strip().split()[-1]
                            for p in params_str.split(",")
                            if p.strip()
                        ]
                    else:
                        method_info["params"] = []

                    break

        return method_info

    def _is_hardcoded_value(self, value: str) -> bool:
        """判断值是否为硬编码

        Args:
            value: 值字符串

        Returns:
            bool: 是否为硬编码
        """
        if not value:
            return False

        value = value.strip()

        if re.match(r'^["\'].*["\']$', value):
            return True

        if re.match(r"^-?\d+(\.\d+)?$", value):
            return True

        if re.match(r"^-?\d+(\.\d+)?[fFdDlL]?$", value):
            return True

        if re.match(r"\b(true|false|null)\b", value, re.IGNORECASE):
            return True

        static_final_pattern = r"\b[A-Z_][A-Z0-9_]*\b"
        if re.match(static_final_pattern, value) and "_" in value:
            return True

        return False

    def _is_method_parameter(self, value: str, method_params: List[str]) -> bool:
        """判断值是否为方法参数

        Args:
            value: 值字符串
            method_params: 方法参数列表

        Returns:
            bool: 是否为方法参数
        """
        if not value or not method_params:
            return False

        value = value.strip()
        return value in method_params

    def _calculate_confidence(self, service_call: Dict, is_hardcoded: bool) -> float:
        """计算置信度

        Args:
            service_call: 服务层调用信息
            is_hardcoded: 是否硬编码

        Returns:
            float: 置信度 0-1
        """
        args = service_call.get("args", [])
        method_params = service_call.get("method_params", [])

        if not args:
            return 0.9

        if is_hardcoded:
            return 0.85

        user_args = [
            arg
            for arg in args
            if not self._is_hardcoded_value(arg)
            and not self._is_method_parameter(arg, method_params)
        ]

        if user_args:
            return 0.7

        return 0.5

    def clear_cache(self) -> None:
        """清空缓存"""
        self._cache.clear()
        self._mapper_to_service_cache.clear()


def create_context_result(
    is_hardcoded: bool,
    is_user_controllable: bool,
    confidence: float,
    is_false_positive: bool,
    reason: str,
    **kwargs,
) -> ContextResult:
    """创建上下文分析结果的工厂函数

    Args:
        is_hardcoded: 服务层是否硬编码参数
        is_user_controllable: 参数是否用户可控
        confidence: 置信度 0-1
        is_false_positive: 是否为误报
        reason: 判断原因
        **kwargs: 其他参数

    Returns:
        ContextResult: 上下文分析结果
    """
    return ContextResult(
        is_hardcoded=is_hardcoded,
        is_user_controllable=is_user_controllable,
        confidence=confidence,
        is_false_positive=is_false_positive,
        reason=reason,
        **kwargs,
    )

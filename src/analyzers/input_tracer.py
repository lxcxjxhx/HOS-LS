"""输入可控性追踪器模块

用于追踪用户输入的传播路径，判断输入是否可控，从而验证漏洞的可利用性。
支持 SQL 注入、SSRF、反序列化等漏洞的可利用性验证。
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


class InputSourceType(Enum):
    """输入源类型"""
    DIRECT_USER_INPUT = "direct_user_input"
    INDIRECT_USER_INPUT = "indirect_user_input"
    CONFIG_FILE = "config_file"
    DATABASE = "database"
    INTERNAL_VALUE = "internal_value"
    UNKNOWN = "unknown"


class ControllabilityLevel(Enum):
    """可控性级别"""
    FULLY_CONTROLLED = "fully_controlled"
    PARTIALLY_CONTROLLED = "partially_controlled"
    NOT_CONTROLLED = "not_controlled"


@dataclass
class TraceNode:
    """追踪路径节点"""
    node_type: str
    location: str
    line_number: int
    source_type: InputSourceType
    value_name: str
    annotation: Optional[str] = None
    method_signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": self.node_type,
            "location": self.location,
            "line_number": self.line_number,
            "source_type": self.source_type.value,
            "value_name": self.value_name,
            "annotation": self.annotation,
            "method_signature": self.method_signature,
            "metadata": self.metadata,
        }


@dataclass
class ControllabilityResult:
    """输入可控性分析结果"""
    is_direct_user_input: bool
    is_indirect: bool
    is_internal: bool
    attack_prerequisites: List[str]
    confidence: float
    is_exploitable: bool
    trace_path: List[Dict]
    controllability_level: ControllabilityLevel = ControllabilityLevel.NOT_CONTROLLED
    source_type: InputSourceType = InputSourceType.UNKNOWN
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_direct_user_input": self.is_direct_user_input,
            "is_indirect": self.is_indirect,
            "is_internal": self.is_internal,
            "attack_prerequisites": self.attack_prerequisites,
            "confidence": self.confidence,
            "is_exploitable": self.is_exploitable,
            "trace_path": self.trace_path,
            "controllability_level": self.controllability_level.value,
            "source_type": self.source_type.value,
            "summary": self.summary,
        }


class InputTracer:
    """输入可控性追踪器

    追踪用户输入的传播路径，判断输入是否可控，从而验证漏洞的可利用性。
    """

    USER_INPUT_ANNOTATIONS = {
        "java": {
            "@RequestParam": "从 HTTP 请求参数获取用户输入",
            "@PathVariable": "从 URL 路径变量获取用户输入",
            "@RequestBody": "从 HTTP 请求体获取用户输入",
            "@RequestHeader": "从 HTTP 请求头获取用户输入",
            "@RequestAttribute": "从请求属性获取用户输入",
            "@CookieValue": "从 Cookie 获取用户输入",
            "@ModelAttribute": "从模型属性获取用户输入",
        },
        "python": {
            "request.args": "从请求参数获取用户输入 (Flask)",
            "request.form": "从表单获取用户输入 (Flask)",
            "request.json": "从 JSON 获取用户输入 (Flask)",
            "request.data": "从原始数据获取用户输入 (Flask)",
            "request.headers": "从请求头获取用户输入 (Flask)",
            "request.files": "从文件上传获取用户输入 (Flask)",
            "request.GET": "从 GET 参数获取用户输入 (Django)",
            "request.POST": "从 POST 参数获取用户输入 (Django)",
            "request.body": "从请求体获取用户输入 (Django)",
        },
        "javascript": {
            "req.query": "从查询参数获取用户输入 (Express)",
            "req.body": "从请求体获取用户输入 (Express)",
            "req.params": "从路径参数获取用户输入 (Express)",
            "req.headers": "从请求头获取用户输入 (Express)",
        },
    }

    INTERNAL_SOURCES = {
        "java": {
            "@Value": "从配置文件注入的值",
            "@ConfigurationProperties": "从配置属性获取的值",
            "System.getenv": "从环境变量获取的值",
            "System.getProperty": "从系统属性获取的值",
        },
        "python": {
            "os.environ": "从环境变量获取的值",
            "os.getenv": "从环境变量获取的值",
            "config": "从配置文件获取的值",
            "settings": "从设置获取的值",
        },
        "javascript": {
            "process.env": "从环境变量获取的值",
            "config": "从配置文件获取的值",
        },
    }

    DANGEROUS_SINKS = {
        "java": {
            "ObjectInputStream.readObject": "反序列化漏洞",
            "readObject": "反序列化漏洞",
            "XMLDecoder.readObject": "XML 反序列化漏洞",
            "JdbcRowSetImpl.execute": "JNDI 注入",
            "InitialContext.lookup": "JNDI 注入",
        },
        "python": {
            "eval": "代码执行",
            "exec": "代码执行",
            "pickle.load": "反序列化漏洞",
            "pickle.loads": "反序列化漏洞",
            "yaml.load": "YAML 反序列化漏洞",
        },
        "javascript": {
            "eval": "代码执行",
            "Function": "动态函数创建",
            "innerHTML": "XSS 漏洞",
        },
    }

    SQL_DYNAMIC_MARKERS = ["${", "format(", "+"]

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self._file_cache: Dict[str, str] = {}
        self._annotation_cache: Dict[str, List[TraceNode]] = {}

    def trace_controllability(
        self, file_path: str, line_number: int, code_snippet: str
    ) -> ControllabilityResult:
        """追踪输入可控性

        Args:
            file_path: 文件路径
            line_number: 行号
            code_snippet: 代码片段

        Returns:
            ControllabilityResult: 可控性分析结果
        """
        trace_path: List[Dict] = []
        attack_prerequisites: List[str] = []

        language = self._detect_language(file_path)

        if language == "java":
            return self._trace_java_controllability(file_path, line_number, code_snippet)
        elif language == "python":
            return self._trace_python_controllability(file_path, line_number, code_snippet)
        elif language == "javascript":
            return self._trace_javascript_controllability(file_path, line_number, code_snippet)
        else:
            return self._create_unknown_result()

    def _trace_java_controllability(
        self, file_path: str, line_number: int, code_snippet: str
    ) -> ControllabilityResult:
        """追踪 Java 代码的输入可控性"""
        trace_path: List[Dict] = []
        attack_prerequisites: List[str] = []

        source_type = InputSourceType.UNKNOWN
        is_direct_user_input = False
        is_indirect = False
        is_internal = False
        confidence = 0.5

        content = self._read_file(file_path)
        if not content:
            return self._create_unknown_result()

        lines = content.split('\n')
        method_context = self._find_method_context(lines, line_number)

        if method_context:
            trace_path.append({
                "node_type": "method",
                "location": file_path,
                "line_number": method_context["start_line"],
                "source_type": "unknown",
                "value_name": method_context["name"],
                "method_signature": method_context["signature"],
            })

            for param_info in method_context.get("params", []):
                param_name = param_info["name"]
                param_annotation = param_info.get("annotation")

                if param_annotation in self.USER_INPUT_ANNOTATIONS["java"]:
                    source_type = InputSourceType.DIRECT_USER_INPUT
                    is_direct_user_input = True
                    confidence = 0.95
                    trace_path.append({
                        "node_type": "parameter",
                        "location": file_path,
                        "line_number": param_info["line"],
                        "source_type": InputSourceType.DIRECT_USER_INPUT.value,
                        "value_name": param_name,
                        "annotation": param_annotation,
                        "metadata": {"description": self.USER_INPUT_ANNOTATIONS["java"][param_annotation]},
                    })
                elif param_annotation in self.INTERNAL_SOURCES["java"]:
                    source_type = InputSourceType.INTERNAL_VALUE
                    is_internal = True
                    confidence = 0.9
                    trace_path.append({
                        "node_type": "parameter",
                        "location": file_path,
                        "line_number": param_info["line"],
                        "source_type": InputSourceType.INTERNAL_VALUE.value,
                        "value_name": param_name,
                        "annotation": param_annotation,
                    })
                elif self._is_suspicious_variable(param_name):
                    is_indirect = True
                    if source_type == InputSourceType.UNKNOWN:
                        source_type = InputSourceType.INDIRECT_USER_INPUT
                    confidence = max(confidence, 0.6)

        current_line = line_number
        variable_refs = self._extract_variable_references(code_snippet)

        for var_ref in variable_refs:
            var_trace = self._trace_variable_origin(
                file_path, lines, line_number, var_ref
            )
            if var_trace:
                trace_path.extend([node.to_dict() for node in var_trace])

        if "ObjectInputStream" in code_snippet or "readObject" in code_snippet:
            attack_prerequisites.append("ObjectInputStream 处理来自用户可控输入的数据")

            ois_result = self.is_objectinputstream_exploitable(file_path, line_number)
            if ois_result.is_exploitable:
                is_direct_user_input = True
                confidence = 0.95
                trace_path.extend(ois_result.trace_path)

        if "RestTemplate" in code_snippet:
            url_match = re.search(r'(?:get|post|put|delete|patch|ForEntity|getForObject|postForObject)\s*<\w+>\s*\([^,)]*,\s*([^,)]+)', code_snippet)
            if url_match:
                url_param = url_match.group(1)
                attack_prerequisites.append("RestTemplate URL 参数来自用户可控输入")

                rt_result = self.is_resttemplate_url_controllable(file_path, line_number, url_param)
                if rt_result.is_exploitable:
                    is_direct_user_input = True
                    confidence = 0.95
                    trace_path.extend(rt_result.trace_path)

        if "${" in code_snippet or any(marker in code_snippet for marker in self.SQL_DYNAMIC_MARKERS):
            attack_prerequisites.append("用户可控字符串参数进入 SQL 拼接")
            is_sql_injection_scenario = True
        else:
            is_sql_injection_scenario = False

        is_exploitable = is_direct_user_input or (
            is_indirect and confidence >= 0.7 and len(attack_prerequisites) > 0
        )

        if is_sql_injection_scenario and is_direct_user_input:
            is_exploitable = True
            confidence = 0.95
        elif is_sql_injection_scenario and is_indirect:
            is_exploitable = False
            confidence = 0.5

        controllability_level = self._determine_controllability_level(
            is_direct_user_input, is_indirect, is_internal
        )

        summary = self._generate_summary(
            is_direct_user_input, is_indirect, is_internal, controllability_level
        )

        return ControllabilityResult(
            is_direct_user_input=is_direct_user_input,
            is_indirect=is_indirect,
            is_internal=is_internal,
            attack_prerequisites=attack_prerequisites,
            confidence=confidence,
            is_exploitable=is_exploitable,
            trace_path=trace_path,
            controllability_level=controllability_level,
            source_type=source_type,
            summary=summary,
        )

    def _trace_python_controllability(
        self, file_path: str, line_number: int, code_snippet: str
    ) -> ControllabilityResult:
        """追踪 Python 代码的输入可控性"""
        trace_path: List[Dict] = []
        attack_prerequisites: List[str] = []

        source_type = InputSourceType.UNKNOWN
        is_direct_user_input = False
        is_indirect = False
        is_internal = False
        confidence = 0.5

        content = self._read_file(file_path)
        if not content:
            return self._create_unknown_result()

        lines = content.split('\n')

        for pattern, description in self.USER_INPUT_ANNOTATIONS["python"].items():
            if pattern in code_snippet:
                source_type = InputSourceType.DIRECT_USER_INPUT
                is_direct_user_input = True
                confidence = 0.95
                trace_path.append({
                    "node_type": "user_input",
                    "location": file_path,
                    "line_number": line_number,
                    "source_type": InputSourceType.DIRECT_USER_INPUT.value,
                    "value_name": pattern,
                    "metadata": {"description": description},
                })
                break

        for pattern, description in self.INTERNAL_SOURCES["python"].items():
            if pattern in code_snippet:
                source_type = InputSourceType.INTERNAL_VALUE
                is_internal = True
                confidence = 0.9
                trace_path.append({
                    "node_type": "internal",
                    "location": file_path,
                    "line_number": line_number,
                    "source_type": InputSourceType.INTERNAL_VALUE.value,
                    "value_name": pattern,
                    "metadata": {"description": description},
                })
                break

        if "pickle.load" in code_snippet or "pickle.loads" in code_snippet:
            attack_prerequisites.append("pickle 反序列化处理来自用户可控输入的数据")

        if "eval(" in code_snippet or "exec(" in code_snippet:
            attack_prerequisites.append("eval/exec 处理来自用户可控输入的代码")
            if is_direct_user_input:
                is_exploitable = True
                confidence = 0.95

        if any(marker in code_snippet for marker in self.SQL_DYNAMIC_MARKERS):
            attack_prerequisites.append("用户可控字符串参数进入 SQL 拼接")

        is_exploitable = is_direct_user_input and len(attack_prerequisites) > 0

        controllability_level = self._determine_controllability_level(
            is_direct_user_input, is_indirect, is_internal
        )

        summary = self._generate_summary(
            is_direct_user_input, is_indirect, is_internal, controllability_level
        )

        return ControllabilityResult(
            is_direct_user_input=is_direct_user_input,
            is_indirect=is_indirect,
            is_internal=is_internal,
            attack_prerequisites=attack_prerequisites,
            confidence=confidence,
            is_exploitable=is_exploitable,
            trace_path=trace_path,
            controllability_level=controllability_level,
            source_type=source_type,
            summary=summary,
        )

    def _trace_javascript_controllability(
        self, file_path: str, line_number: int, code_snippet: str
    ) -> ControllabilityResult:
        """追踪 JavaScript/TypeScript 代码的输入可控性"""
        trace_path: List[Dict] = []
        attack_prerequisites: List[str] = []

        source_type = InputSourceType.UNKNOWN
        is_direct_user_input = False
        is_indirect = False
        is_internal = False
        confidence = 0.5

        for pattern, description in self.USER_INPUT_ANNOTATIONS["javascript"].items():
            if pattern in code_snippet:
                source_type = InputSourceType.DIRECT_USER_INPUT
                is_direct_user_input = True
                confidence = 0.95
                trace_path.append({
                    "node_type": "user_input",
                    "location": file_path,
                    "line_number": line_number,
                    "source_type": InputSourceType.DIRECT_USER_INPUT.value,
                    "value_name": pattern,
                    "metadata": {"description": description},
                })
                break

        for pattern, description in self.INTERNAL_SOURCES["javascript"].items():
            if pattern in code_snippet:
                source_type = InputSourceType.INTERNAL_VALUE
                is_internal = True
                confidence = 0.9
                trace_path.append({
                    "node_type": "internal",
                    "location": file_path,
                    "line_number": line_number,
                    "source_type": InputSourceType.INTERNAL_VALUE.value,
                    "value_name": pattern,
                    "metadata": {"description": description},
                })
                break

        if "innerHTML" in code_snippet or "document.write" in code_snippet:
            attack_prerequisites.append("用户可控输入进入 DOM 操作")
            if is_direct_user_input:
                is_exploitable = True
                confidence = 0.95

        if "eval(" in code_snippet or "new Function(" in code_snippet:
            attack_prerequisites.append("用户可控输入进入代码执行")
            if is_direct_user_input:
                is_exploitable = True
                confidence = 0.95

        is_exploitable = is_direct_user_input and len(attack_prerequisites) > 0

        controllability_level = self._determine_controllability_level(
            is_direct_user_input, is_indirect, is_internal
        )

        summary = self._generate_summary(
            is_direct_user_input, is_indirect, is_internal, controllability_level
        )

        return ControllabilityResult(
            is_direct_user_input=is_direct_user_input,
            is_indirect=is_indirect,
            is_internal=is_internal,
            attack_prerequisites=attack_prerequisites,
            confidence=confidence,
            is_exploitable=is_exploitable,
            trace_path=trace_path,
            controllability_level=controllability_level,
            source_type=source_type,
            summary=summary,
        )

    def is_objectinputstream_exploitable(
        self, file_path: str, line_number: int
    ) -> ControllabilityResult:
        """判断 ObjectInputStream 是否可利用

        只有当 ObjectInputStream 处理来自用户可控输入时才返回 is_exploitable=True

        Args:
            file_path: 文件路径
            line_number: 行号

        Returns:
            ControllabilityResult: 可控性分析结果
        """
        trace_path: List[Dict] = []
        attack_prerequisites: List[str] = []

        content = self._read_file(file_path)
        if not content:
            return self._create_unknown_result()

        lines = content.split('\n')

        if line_number > len(lines):
            return self._create_unknown_result()

        current_line = lines[line_number - 1]

        if "ObjectInputStream" not in current_line and "readObject" not in current_line:
            return ControllabilityResult(
                is_direct_user_input=False,
                is_indirect=False,
                is_internal=False,
                attack_prerequisites=["未发现 ObjectInputStream.readObject 调用"],
                confidence=0.0,
                is_exploitable=False,
                trace_path=[],
                summary="未发现反序列化入口",
            )

        trace_path.append({
            "node_type": "sink",
            "location": file_path,
            "line_number": line_number,
            "source_type": "unknown",
            "value_name": "ObjectInputStream.readObject",
            "metadata": {"description": "反序列化入口点"},
        })

        attack_prerequisites.append("ObjectInputStream.readObject() 被调用")

        method_context = self._find_method_context(lines, line_number)

        if not method_context:
            return ControllabilityResult(
                is_direct_user_input=False,
                is_indirect=False,
                is_internal=False,
                attack_prerequisites=attack_prerequisites,
                confidence=0.3,
                is_exploitable=False,
                trace_path=trace_path,
                summary="无法确定输入来源，需要人工分析",
            )

        trace_path.append({
            "node_type": "method",
            "location": file_path,
            "line_number": method_context["start_line"],
            "source_type": "unknown",
            "value_name": method_context["name"],
            "method_signature": method_context["signature"],
        })

        has_user_input = False
        has_internal_input = False

        for param_info in method_context.get("params", []):
            param_annotation = param_info.get("annotation")
            param_name = param_info["name"]

            if param_annotation in self.USER_INPUT_ANNOTATIONS["java"]:
                has_user_input = True
                trace_path.append({
                    "node_type": "parameter",
                    "location": file_path,
                    "line_number": param_info["line"],
                    "source_type": InputSourceType.DIRECT_USER_INPUT.value,
                    "value_name": param_name,
                    "annotation": param_annotation,
                    "metadata": {"description": self.USER_INPUT_ANNOTATIONS["java"][param_annotation]},
                })
            elif param_annotation in self.INTERNAL_SOURCES["java"]:
                has_internal_input = True
                trace_path.append({
                    "node_type": "parameter",
                    "location": file_path,
                    "line_number": param_info["line"],
                    "source_type": InputSourceType.INTERNAL_VALUE.value,
                    "value_name": param_name,
                    "annotation": param_annotation,
                })

        if "byte[]" in current_line or "InputStream" in method_context.get("signature", ""):
            variable_data_flow = self._trace_data_flow_to_sink(
                file_path, lines, line_number, "ObjectInputStream"
            )
            if variable_data_flow:
                trace_path.extend([node.to_dict() for node in variable_data_flow])

                for node in variable_data_flow:
                    if node.source_type == InputSourceType.DIRECT_USER_INPUT:
                        has_user_input = True
                    elif node.source_type == InputSourceType.INTERNAL_VALUE:
                        has_internal_input = True

        is_exploitable = has_user_input and not has_internal_input
        confidence = 0.95 if has_user_input else (0.5 if has_internal_input else 0.3)

        if has_user_input:
            attack_prerequisites.append("反序列化数据来自用户请求参数")
            summary = "ObjectInputStream 处理用户可控输入，存在反序列化漏洞"
        elif has_internal_input:
            attack_prerequisites.append("数据来自内部配置，需要进一步分析")
            summary = "ObjectInputStream 处理的数据来源需要进一步分析"
        else:
            attack_prerequisites.append("无法确定数据来源，需要人工分析")
            summary = "ObjectInputStream 数据来源未知，需要人工分析"

        return ControllabilityResult(
            is_direct_user_input=has_user_input,
            is_indirect=False,
            is_internal=has_internal_input,
            attack_prerequisites=attack_prerequisites,
            confidence=confidence,
            is_exploitable=is_exploitable,
            trace_path=trace_path,
            controllability_level=ControllabilityLevel.FULLY_CONTROLLED if has_user_input else ControllabilityLevel.NOT_CONTROLLED,
            source_type=InputSourceType.DIRECT_USER_INPUT if has_user_input else InputSourceType.UNKNOWN,
            summary=summary,
        )

    def is_resttemplate_url_controllable(
        self, file_path: str, line_number: int, url_param: str
    ) -> ControllabilityResult:
        """判断 RestTemplate 的 URL 参数是否可控

        只有当 URL 参数直接来自用户请求时才返回 is_exploitable=True

        Args:
            file_path: 文件路径
            line_number: 行号
            url_param: URL 参数名

        Returns:
            ControllabilityResult: 可控性分析结果
        """
        trace_path: List[Dict] = []
        attack_prerequisites: List[str] = []

        content = self._read_file(file_path)
        if not content:
            return self._create_unknown_result()

        lines = content.split('\n')

        if line_number > len(lines):
            return self._create_unknown_result()

        current_line = lines[line_number - 1]

        if "RestTemplate" not in content:
            return ControllabilityResult(
                is_direct_user_input=False,
                is_indirect=False,
                is_internal=False,
                attack_prerequisites=["未发现 RestTemplate 使用"],
                confidence=0.0,
                is_exploitable=False,
                trace_path=[],
                summary="未发现 RestTemplate",
            )

        trace_path.append({
            "node_type": "sink",
            "location": file_path,
            "line_number": line_number,
            "source_type": "unknown",
            "value_name": "RestTemplate",
            "metadata": {"description": "HTTP 客户端调用点", "url_param": url_param},
        })

        attack_prerequisites.append("RestTemplate 用于发起 HTTP 请求")

        method_context = self._find_method_context(lines, line_number)

        if not method_context:
            return ControllabilityResult(
                is_direct_user_input=False,
                is_indirect=False,
                is_internal=False,
                attack_prerequisites=attack_prerequisites,
                confidence=0.3,
                is_exploitable=False,
                trace_path=trace_path,
                summary="无法确定 URL 参数来源",
            )

        trace_path.append({
            "node_type": "method",
            "location": file_path,
            "line_number": method_context["start_line"],
            "source_type": "unknown",
            "value_name": method_context["name"],
            "method_signature": method_context["signature"],
        })

        url_origin = self._trace_variable_origin(
            file_path, lines, line_number, url_param
        )

        has_user_input = False
        has_internal_input = False

        if url_origin:
            trace_path.extend([node.to_dict() for node in url_origin])

            for node in url_origin:
                if node.source_type == InputSourceType.DIRECT_USER_INPUT:
                    has_user_input = True
                elif node.source_type == InputSourceType.INTERNAL_VALUE:
                    has_internal_input = True
                elif node.source_type == InputSourceType.CONFIG_FILE:
                    has_internal_input = True

        if not url_origin:
            for param_info in method_context.get("params", []):
                if param_info["name"] == url_param:
                    param_annotation = param_info.get("annotation")

                    if param_annotation in self.USER_INPUT_ANNOTATIONS["java"]:
                        has_user_input = True
                        trace_path.append({
                            "node_type": "parameter",
                            "location": file_path,
                            "line_number": param_info["line"],
                            "source_type": InputSourceType.DIRECT_USER_INPUT.value,
                            "value_name": url_param,
                            "annotation": param_annotation,
                            "metadata": {"description": self.USER_INPUT_ANNOTATIONS["java"][param_annotation]},
                        })
                    elif param_annotation in self.INTERNAL_SOURCES["java"]:
                        has_internal_input = True
                        trace_path.append({
                            "node_type": "parameter",
                            "location": file_path,
                            "line_number": param_info["line"],
                            "source_type": InputSourceType.INTERNAL_VALUE.value,
                            "value_name": url_param,
                            "annotation": param_annotation,
                        })

        is_exploitable = has_user_input and not has_internal_input
        confidence = 0.95 if has_user_input else (0.5 if has_internal_input else 0.3)

        if has_user_input:
            attack_prerequisites.append("RestTemplate URL 参数来自用户请求")
            summary = "RestTemplate URL 参数可控，存在 SSRF 漏洞"
        elif has_internal_input:
            attack_prerequisites.append("URL 来自内部配置或数据库")
            summary = "RestTemplate URL 来自内部源，需要进一步分析"
        else:
            attack_prerequisites.append("无法确定 URL 参数来源")
            summary = "RestTemplate URL 来源未知，需要人工分析"

        return ControllabilityResult(
            is_direct_user_input=has_user_input,
            is_indirect=False,
            is_internal=has_internal_input,
            attack_prerequisites=attack_prerequisites,
            confidence=confidence,
            is_exploitable=is_exploitable,
            trace_path=trace_path,
            controllability_level=ControllabilityLevel.FULLY_CONTROLLED if has_user_input else ControllabilityLevel.NOT_CONTROLLED,
            source_type=InputSourceType.DIRECT_USER_INPUT if has_user_input else InputSourceType.UNKNOWN,
            summary=summary,
        )

    def _trace_data_flow_to_sink(
        self, file_path: str, lines: List[str], sink_line: int, sink_name: str
    ) -> List[TraceNode]:
        """追踪数据流到 sink 点"""
        trace_nodes: List[TraceNode] = []

        sink_line_content = lines[sink_line - 1] if sink_line <= len(lines) else ""

        var_match = re.search(r'(\w+)\s*\.readObject', sink_line_content)
        if var_match:
            var_name = var_match.group(1)

            origin_line = self._find_variable_assignment(lines, sink_line, var_name)
            if origin_line:
                origin_content = lines[origin_line - 1]

                if "@RequestParam" in origin_content or "@PathVariable" in origin_content:
                    trace_nodes.append(TraceNode(
                        node_type="data_flow",
                        location=file_path,
                        line_number=origin_line,
                        source_type=InputSourceType.DIRECT_USER_INPUT,
                        value_name=var_name,
                    ))
                elif "@Value" in origin_content:
                    trace_nodes.append(TraceNode(
                        node_type="data_flow",
                        location=file_path,
                        line_number=origin_line,
                        source_type=InputSourceType.INTERNAL_VALUE,
                        value_name=var_name,
                    ))

        return trace_nodes

    def _find_variable_assignment(
        self, lines: List[str], before_line: int, var_name: str
    ) -> Optional[int]:
        """查找变量赋值语句"""
        for i in range(before_line - 1, -1, -1):
            line = lines[i]

            if re.search(rf'\b{var_name}\b\s*=', line):
                return i + 1

            if re.search(r'\b(public|private|protected)\s+\w+', line):
                break

        return None

    def _trace_variable_origin(
        self, file_path: str, lines: List[str], current_line: int, var_name: str
    ) -> List[TraceNode]:
        """追踪变量来源"""
        trace_nodes: List[TraceNode] = []

        for i in range(current_line - 2, max(0, current_line - 50), -1):
            line = lines[i]

            if re.search(rf'\b{var_name}\b\s*=', line):
                assign_match = re.search(rf'(\w+)\s*=\s*(.+)', line)
                if assign_match:
                    rhs = assign_match.group(2).strip()

                    for annotation, desc in self.USER_INPUT_ANNOTATIONS["java"].items():
                        if annotation in rhs or annotation.split(".")[-1] in rhs:
                            trace_nodes.append(TraceNode(
                                node_type="assignment",
                                location=file_path,
                                line_number=i + 1,
                                source_type=InputSourceType.DIRECT_USER_INPUT,
                                value_name=var_name,
                                annotation=annotation,
                            ))
                            return trace_nodes

                    for annotation, desc in self.INTERNAL_SOURCES["java"].items():
                        if annotation in rhs:
                            trace_nodes.append(TraceNode(
                                node_type="assignment",
                                location=file_path,
                                line_number=i + 1,
                                source_type=InputSourceType.INTERNAL_VALUE,
                                value_name=var_name,
                                annotation=annotation,
                            ))
                            return trace_nodes

                    rhs_var_match = re.match(r'^(\w+)$', rhs)
                    if rhs_var_match:
                        nested_origin = self._trace_variable_origin(
                            file_path, lines, i + 1, rhs_var_match.group(1)
                        )
                        trace_nodes.extend(nested_origin)
                        return trace_nodes

            if re.search(r'\b(public|private|protected)\s+\w+', line):
                break

        return trace_nodes

    def _extract_variable_references(self, code_snippet: str) -> List[str]:
        """提取代码片段中的变量引用"""
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        matches = re.findall(var_pattern, code_snippet)

        keywords = {
            "int", "long", "float", "double", "boolean", "char", "byte", "short",
            "String", "Integer", "Long", "Float", "Double", "Boolean", "Byte", "Short",
            "Object", "Class", "System", "out", "in", "err",
            "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
            "return", "try", "catch", "finally", "throw", "throws",
            "new", "this", "super", "import", "package", "class", "interface",
            "extends", "implements", "abstract", "final", "static", "void",
            "public", "private", "protected", "default",
        }

        return [m for m in matches if m not in keywords]

    def _find_method_context(
        self, lines: List[str], line_number: int
    ) -> Optional[Dict[str, Any]]:
        """查找方法上下文"""
        for i in range(line_number - 1, -1, -1):
            line = lines[i]

            method_match = re.search(
                r'((?:public|private|protected)?\s*(?:static)?\s*\w+\s+)?'
                r'(\w+)\s*\(([^)]*)\)',
                line
            )

            if method_match and not any(kw in line for kw in ["if", "for", "while", "switch"]):
                modifiers = method_match.group(1) or ""
                method_name = method_match.group(2)
                params_str = method_match.group(3)

                params = []
                if params_str.strip():
                    param_pattern = r'(?:@(\w+)\s+)?(\w+)\s+(\w+)'
                    for param_match in re.finditer(param_pattern, params_str):
                        annotation = param_match.group(1)
                        param_type = param_match.group(2)
                        param_name = param_match.group(3)
                        params.append({
                            "annotation": f"@{annotation}" if annotation else None,
                            "type": param_type,
                            "name": param_name,
                            "line": i + 1,
                        })

                return {
                    "name": method_name,
                    "signature": line.strip(),
                    "start_line": i + 1,
                    "params": params,
                }

        return None

    def _is_suspicious_variable(self, var_name: str) -> bool:
        """判断变量名是否可疑"""
        suspicious_patterns = [
            r'^(id|Ids|ID)$',
            r'(Id|Name|Name)$',
            r'(keyword|search|query)$',
            r'(url|uri|link|href)$',
            r'(file|path)$',
            r'(user|input|param)$',
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, var_name, re.IGNORECASE):
                return True

        return False

    def _read_file(self, file_path: str) -> Optional[str]:
        """读取文件内容，带缓存"""
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                self._file_cache[file_path] = content
                return content
        except Exception as e:
            logger.debug(f"无法读取文件 {file_path}: {e}")
            return None

    def _detect_language(self, file_path: str) -> str:
        """检测编程语言"""
        ext = Path(file_path).suffix.lower()
        language_map = {
            '.java': 'java',
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.jsx': 'javascript',
            '.tsx': 'javascript',
        }
        return language_map.get(ext, 'unknown')

    def _determine_controllability_level(
        self, is_direct: bool, is_indirect: bool, is_internal: bool
    ) -> ControllabilityLevel:
        """确定可控性级别"""
        if is_direct:
            return ControllabilityLevel.FULLY_CONTROLLED
        elif is_indirect:
            return ControllabilityLevel.PARTIALLY_CONTROLLED
        elif is_internal:
            return ControllabilityLevel.NOT_CONTROLLED
        else:
            return ControllabilityLevel.NOT_CONTROLLED

    def _generate_summary(
        self, is_direct: bool, is_indirect: bool, is_internal: bool, level: ControllabilityLevel
    ) -> str:
        """生成结果摘要"""
        if level == ControllabilityLevel.FULLY_CONTROLLED:
            return "输入直接来自用户，可利用性高"
        elif level == ControllabilityLevel.PARTIALLY_CONTROLLED:
            return "输入间接来自用户，可利用性中等"
        elif is_internal:
            return "输入来自内部配置，可利用性低"
        else:
            return "无法确定输入来源"

    def _create_unknown_result(self) -> ControllabilityResult:
        """创建未知结果"""
        return ControllabilityResult(
            is_direct_user_input=False,
            is_indirect=False,
            is_internal=False,
            attack_prerequisites=["无法分析代码上下文"],
            confidence=0.0,
            is_exploitable=False,
            trace_path=[],
            controllability_level=ControllabilityLevel.NOT_CONTROLLED,
            source_type=InputSourceType.UNKNOWN,
            summary="无法确定输入可控性",
        )

    def verify_sql_injection_prerequisites(
        self, file_path: str, line_number: int, code_snippet: str
    ) -> ControllabilityResult:
        """验证 SQL 注入攻击前提条件

        Args:
            file_path: 文件路径
            line_number: 行号
            code_snippet: 代码片段

        Returns:
            ControllabilityResult: 可控性分析结果
        """
        result = self.trace_controllability(file_path, line_number, code_snippet)

        if "${" not in code_snippet and "format(" not in code_snippet and "+" not in code_snippet:
            result.attack_prerequisites.append("未发现动态 SQL 拼接")
            result.is_exploitable = False
            result.confidence = 0.3
            result.summary = "未发现动态 SQL 拼接，SQL 注入不可利用"

        if result.is_direct_user_input and "${" in code_snippet:
            result.attack_prerequisites.append("用户可控字符串参数进入 ${}")
            result.is_exploitable = True
            result.confidence = 0.95
            result.summary = "SQL 注入漏洞可利用：用户输入直接进入动态 SQL"
        elif result.is_indirect and "${" in code_snippet:
            result.attack_prerequisites.append("间接输入进入 SQL 拼接，需要进一步验证")
            result.is_exploitable = False
            result.confidence = 0.5
            result.summary = "SQL 注入需要进一步分析输入来源"

        return result

    def verify_ssrp_prerequisites(
        self, file_path: str, line_number: int, url_param: str
    ) -> ControllabilityResult:
        """验证 SSRF 攻击前提条件

        Args:
            file_path: 文件路径
            line_number: 行号
            url_param: URL 参数名

        Returns:
            ControllabilityResult: 可控性分析结果
        """
        return self.is_resttemplate_url_controllable(file_path, line_number, url_param)

    def verify_deserialization_prerequisites(
        self, file_path: str, line_number: int
    ) -> ControllabilityResult:
        """验证反序列化攻击前提条件

        Args:
            file_path: 文件路径
            line_number: 行号

        Returns:
            ControllabilityResult: 可控性分析结果
        """
        return self.is_objectinputstream_exploitable(file_path, line_number)

    def generate_trace_report(self, result: ControllabilityResult) -> str:
        """生成追踪报告

        Args:
            result: 可控性分析结果

        Returns:
            str: 格式化的追踪报告
        """
        lines = []
        lines.append("=" * 60)
        lines.append("输入可控性追踪报告")
        lines.append("=" * 60)
        lines.append(f"可利用性: {'是' if result.is_exploitable else '否'}")
        lines.append(f"置信度: {result.confidence:.2f}")
        lines.append(f"可控性级别: {result.controllability_level.value}")
        lines.append(f"输入类型: {result.source_type.value}")
        lines.append(f"直接用户输入: {'是' if result.is_direct_user_input else '否'}")
        lines.append(f"间接输入: {'是' if result.is_indirect else '否'}")
        lines.append(f"内部值: {'是' if result.is_internal else '否'}")
        lines.append("")

        if result.attack_prerequisites:
            lines.append("攻击前提条件:")
            for prereq in result.attack_prerequisites:
                lines.append(f"  - {prereq}")
            lines.append("")

        if result.trace_path:
            lines.append("追踪路径:")
            for i, node in enumerate(result.trace_path, 1):
                lines.append(f"  {i}. [{node.get('node_type', 'unknown')}]")
                lines.append(f"     位置: {node.get('location', 'unknown')}:{node.get('line_number', 0)}")
                lines.append(f"     值: {node.get('value_name', 'unknown')}")
                if node.get('annotation'):
                    lines.append(f"     注解: {node.get('annotation')}")
                if node.get('source_type'):
                    lines.append(f"     来源类型: {node.get('source_type')}")
                lines.append("")

        lines.append(f"摘要: {result.summary}")
        lines.append("=" * 60)

        return "\n".join(lines)

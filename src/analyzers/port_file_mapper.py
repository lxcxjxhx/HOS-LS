"""端口关联文件识别模块

建立端口与功能文件的映射关系，识别:
- 路由处理器
- 安全配置
- CORS配置
- 过滤器/拦截器

支持的技术栈:
- Spring Boot (@RestController, @RequestMapping)
- Express (app.route)
- Flask (@app.route)
- Django (path(), re_path())
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ComponentType(Enum):
    """组件类型"""

    ROUTE_HANDLER = "route_handler"
    MIDDLEWARE = "middleware"
    SECURITY_CONFIG = "security_config"
    CORS_CONFIG = "cors_config"
    FILTER = "filter"
    INTERCEPTOR = "interceptor"
    SWAGGER_CONFIG = "swagger_config"


@dataclass
class PortBinding:
    """端口绑定信息"""

    port: int
    protocol: str = "HTTP"
    file_path: str = ""
    line_number: int = 0
    context: str = ""


@dataclass
class PortComponent:
    """端口关联组件"""

    component_type: ComponentType
    file_path: str
    line_number: int
    name: str
    pattern: str
    context: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PortMapping:
    """端口映射信息"""

    port: int
    bindings: List[PortBinding] = field(default_factory=list)
    components: List[PortComponent] = field(default_factory=list)
    route_handlers: List[PortComponent] = field(default_factory=list)
    security_configs: List[PortComponent] = field(default_factory=list)
    cors_configs: List[PortComponent] = field(default_factory=list)
    filters: List[PortComponent] = field(default_factory=list)
    interceptors: List[PortComponent] = field(default_factory=list)
    api_docs: List[PortComponent] = field(default_factory=list)

    def get_all_components(self) -> List[PortComponent]:
        """获取所有组件"""
        return self.components

    def get_components_by_type(self, component_type: ComponentType) -> List[PortComponent]:
        """按类型获取组件"""
        return [c for c in self.components if c.component_type == component_type]


@dataclass
class PortMappingResult:
    """端口映射扫描结果"""

    total_ports: int = 0
    total_components: int = 0
    port_mappings: Dict[int, PortMapping] = field(default_factory=dict)

    def get_ports(self) -> List[int]:
        return list(self.port_mappings.keys())

    def get_mapping(self, port: int) -> Optional[PortMapping]:
        return self.port_mappings.get(port)


class PortPatterns:
    """端口检测模式"""

    SERVER_PORT_PATTERNS = [
        (r"server\.port\s*=\s*(\d+)", "server_port", "Spring Boot 服务端口"),
        (r"port\s*:\s*(\d+)", "port", "通用端口配置"),
        (r"listen\s+(\d+)", "listen", "Nginx/Node.js 监听端口"),
        (r'binding\s*:\s*["\']?(\d+)', "binding", "服务绑定端口"),
        (r"--server\.port\s*(\d+)", "server_port", "命令行端口"),
        (r"process\.env\.PORT\s*=\s*(\d+)", "env_port", "环境变量端口"),
        (r"process\.env\.VITE_SERVER_PORT\s*=\s*(\d+)", "vite_port", "Vite 开发服务器端口"),
    ]

    EXPRESS_ROUTE_PATTERNS = [
        (
            r'app\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
            "express_route",
            "Express 路由",
        ),
        (
            r'router\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
            "express_router",
            "Express Router 路由",
        ),
        (
            r"router\.(get|post|put|delete|patch|options|head)\s*\(\s*`([^`]+)`",
            "express_router_template",
            "Express Router 模板路由",
        ),
    ]

    FLASK_ROUTE_PATTERNS = [
        (r'@app\.route\(["\']([^"\']+)["\']', "flask_route", "Flask 路由"),
        (r'@blueprint\.route\(["\']([^"\']+)["\']', "flask_blueprint", "Flask Blueprint 路由"),
    ]

    SPRING_ROUTE_PATTERNS = [
        (r"@(RestController|Controller)\b", "spring_controller", "Spring Controller"),
        (
            r'@RequestMapping\s*\(\s*value\s*=\s*["\']([^"\']+)["\']',
            "spring_request_mapping",
            "Spring RequestMapping",
        ),
        (
            r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*value\s*=\s*["\']([^"\']+)["\']',
            "spring_rest_mapping",
            "Spring REST Mapping",
        ),
        (
            r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*["\']([^"\']+)["\']',
            "spring_rest_mapping_short",
            "Spring REST Mapping 简写",
        ),
    ]

    DJANGO_ROUTE_PATTERNS = [
        (r'path\(["\']([^"\']+)["\']', "django_path", "Django path"),
        (r're_path\(["\']([^"\']+)["\']', "django_re_path", "Django re_path"),
    ]

    MIDDLEWARE_PATTERNS = [
        (r"class\s+\w+Middleware", "middleware_class", "中间件类"),
        (r"@Middleware\s*\(\s*\)", "middleware_decorator", "中间件装饰器"),
        (r'app\.use\s*\(\s*["\']([^"\']+)["\']', "express_middleware", "Express 中间件"),
        (r"app\.use\s*\(\s*function", "express_middleware_fn", "Express 中间件函数"),
        (r"function\s+\w+\s*\([^)]*\)\s*{[^}]*next\s*\(\)", "middleware_function", "中间件函数"),
    ]

    FILTER_PATTERNS = [
        (r"@Filter\s*\(\s*\)", "filter_decorator", "Filter 装饰器"),
        (r"class\s+\w+Filter\s+extends", "filter_class", "Filter 类"),
        (r"class\s+\w+Filter\s*:\s*.*Filter", "python_filter", "Python Filter"),
        (r"class\s+\w+HandlerFilter", "handler_filter", "Handler Filter"),
    ]

    INTERCEPTOR_PATTERNS = [
        (r"@Interceptor\s*\(\s*\)", "interceptor_decorator", "Interceptor 装饰器"),
        (r"class\s+\w+Interceptor", "interceptor_class", "Interceptor 类"),
        (r"class\s+\w+HandlerInterceptorAdapter", "handler_interceptor", "Handler Interceptor"),
    ]

    SECURITY_PATTERNS = [
        (
            r"@Configuration\s*(?:class\s+\w+)?\s*extends\s+WebSecurityConfigurerAdapter",
            "security_config",
            "Spring Security 配置",
        ),
        (r"class\s+\w+SecurityConfig", "security_config_class", "Security 配置类"),
        (
            r"class\s+\w+Config\s*extends\s+WebSecurityConfigurerAdapter",
            "security_config_extends",
            "Security 配置扩展",
        ),
        (r"@EnableWebSecurity", "enable_web_security", "启用 Web Security"),
        (r"@EnableGlobalMethodSecurity", "enable_method_security", "启用方法级安全"),
        (r"SecurityConfig|WebSecurityConfigurerAdapter", "security_keyword", "Security 关键字"),
    ]

    CORS_PATTERNS = [
        (r"@CrossOrigin\s*\(", "cors_annotation", "CORS 注解"),
        (r"CorsConfiguration\s*\(", "cors_configuration", "CORS 配置类"),
        (r"cors\s*\(\s*{", "cors_middleware", "CORS 中间件"),
        (
            r"allowedOrigins|allowedOriginPatterns|allowedHeaders|allowedMethods|exposedHeaders",
            "cors_keywords",
            "CORS 关键字",
        ),
        (r"addCorsMappings\s*\(\s*registry", "cors_registry", "CORS 注册"),
    ]

    API_DOC_PATTERNS = [
        (r"@Api\s*\(", "swagger_api", "Swagger @Api"),
        (r"@ApiOperation\s*\(", "swagger_operation", "Swagger @ApiOperation"),
        (r"@OpenAPI\s*\(", "openapi_annotation", "OpenAPI 注解"),
        (r"@Operation\s*\(", "openapi_operation", "OpenAPI @Operation"),
        (r"SwaggerConfig|OpenApiConfig", "swagger_config_class", "Swagger 配置类"),
        (r"Redoc|scalar", "api_doc_tool", "API 文档工具"),
    ]

    @classmethod
    def get_all_route_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        """获取所有路由模式"""
        patterns = []
        for pattern_str, name, desc in cls.EXPRESS_ROUTE_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc))
        for pattern_str, name, desc in cls.FLASK_ROUTE_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc))
        for pattern_str, name, desc in cls.SPRING_ROUTE_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc))
        for pattern_str, name, desc in cls.DJANGO_ROUTE_PATTERNS:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), name, desc))
        return patterns

    @classmethod
    def get_all_component_patterns(cls) -> Dict[ComponentType, List[Tuple[re.Pattern, str, str]]]:
        """获取所有组件模式"""
        return {
            ComponentType.ROUTE_HANDLER: cls.get_all_route_patterns(),
            ComponentType.MIDDLEWARE: [
                (re.compile(p, re.IGNORECASE), n, d) for p, n, d in cls.MIDDLEWARE_PATTERNS
            ],
            ComponentType.FILTER: [
                (re.compile(p, re.IGNORECASE), n, d) for p, n, d in cls.FILTER_PATTERNS
            ],
            ComponentType.INTERCEPTOR: [
                (re.compile(p, re.IGNORECASE), n, d) for p, n, d in cls.INTERCEPTOR_PATTERNS
            ],
            ComponentType.SECURITY_CONFIG: [
                (re.compile(p, re.IGNORECASE), n, d) for p, n, d in cls.SECURITY_PATTERNS
            ],
            ComponentType.CORS_CONFIG: [
                (re.compile(p, re.IGNORECASE), n, d) for p, n, d in cls.CORS_PATTERNS
            ],
            ComponentType.SWAGGER_CONFIG: [
                (re.compile(p, re.IGNORECASE), n, d) for p, n, d in cls.API_DOC_PATTERNS
            ],
        }


class PortFileMapper:
    """端口关联文件映射器"""

    SOURCE_EXTENSIONS = {
        ".java",
        ".kt",
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".scala",
        ".yml",
        ".yaml",
        ".json",
        ".xml",
        ".properties",
        ".env",
    }

    CONFIG_EXTENSIONS = {".yml", ".yaml", ".json", ".xml", ".properties", ".env", ".toml"}

    def __init__(self):
        self.port_patterns = PortPatterns.get_all_component_patterns()
        self.server_port_patterns = [
            (re.compile(p, re.IGNORECASE), n, d) for p, n, d in PortPatterns.SERVER_PORT_PATTERNS
        ]
        self._result: PortMappingResult = PortMappingResult()
        self._default_port: int = 8080
        self._current_port: int = self._default_port

    def is_source_file(self, file_path: str) -> bool:
        """判断是否为源代码文件

        Args:
            file_path: 文件路径

        Returns:
            是否为源代码文件
        """
        path = Path(file_path)
        return path.suffix in self.SOURCE_EXTENSIONS

    def is_config_file(self, file_path: str) -> bool:
        """判断是否为配置文件

        Args:
            file_path: 文件路径

        Returns:
            是否为配置文件
        """
        path = Path(file_path)
        return path.suffix in self.CONFIG_EXTENSIONS

    def detect_port(self, content: str, file_path: str) -> Optional[int]:
        """检测文件中的端口配置

        Args:
            content: 文件内容
            file_path: 文件路径

        Returns:
            端口号，如果未找到则返回 None
        """
        port = self._detect_port_in_properties(content, file_path)
        if port:
            return port

        port = self._detect_port_in_json(content, file_path)
        if port:
            return port

        port = self._detect_port_in_yaml(content, file_path)
        if port:
            return port

        return None

    def _detect_port_in_properties(self, content: str, file_path: str) -> Optional[int]:
        """检测 properties 文件中的端口"""
        if not file_path.endswith((".properties", ".env")):
            return None

        for line_num, line in enumerate(content.split("\n"), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for pattern, name, desc in self.server_port_patterns:
                match = pattern.search(line)
                if match:
                    try:
                        port = int(match.group(1))
                        if 1 <= port <= 65535:
                            logger.debug(f"在 {file_path}:{line_num} 检测到端口 {port}")
                            return port
                    except (ValueError, IndexError):
                        continue
        return None

    def _detect_port_in_json(self, content: str, file_path: str) -> Optional[int]:
        """检测 JSON 文件中的端口"""
        if not file_path.endswith(".json"):
            return None

        import json

        try:
            data = json.loads(content)
            port = self._extract_port_from_dict(data)
            if port:
                return port
        except json.JSONDecodeError:
            pass
        return None

    def _detect_port_in_yaml(self, content: str, file_path: str) -> Optional[int]:
        """检测 YAML 文件中的端口"""
        if not file_path.endswith((".yml", ".yaml")):
            return None

        try:
            import yaml

            data = yaml.safe_load(content)
            if isinstance(data, dict):
                if "server" in data and isinstance(data["server"], dict):
                    port = data["server"].get("port")
                    if port and isinstance(port, int):
                        return int(port)
                if "port" in data and isinstance(data["port"], int):
                    return int(data["port"])
        except ImportError:
            for line in content.split("\n"):
                for pattern, name, desc in self.server_port_patterns:
                    match = pattern.search(line)
                    if match:
                        try:
                            return int(match.group(1))
                        except (ValueError, IndexError):
                            continue
        except Exception:
            pass
        return None

    def _extract_port_from_dict(self, data: Any) -> Optional[int]:
        """从字典中提取端口"""
        if isinstance(data, dict):
            if "server" in data and isinstance(data["server"], dict):
                port = data["server"].get("port")
                if isinstance(port, int):
                    return port
            if "port" in data and isinstance(data["port"], int):
                return data["port"]
            if "ports" in data and isinstance(data["ports"], dict):
                for key in ["http", "api", "app"]:
                    if key in data["ports"] and isinstance(data["ports"][key], int):
                        return int(data["ports"][key])
        return None

    def analyze_file(
        self, file_path: str, content: Optional[str] = None
    ) -> Dict[int, List[PortComponent]]:
        """分析单个文件，识别端口关联组件

        Args:
            file_path: 文件路径
            content: 文件内容（如果为 None 则读取文件）

        Returns:
            端口到组件的映射
        """
        port_components: Dict[int, List[PortComponent]] = {}

        if content is None:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                logger.debug(f"无法读取文件 {file_path}: {e}")
                return port_components

        detected_port = self.detect_port(content, file_path)
        current_port = detected_port if detected_port else self._default_port

        lines = content.split("\n")

        for component_type, patterns in self.port_patterns.items():
            for line_num, line in enumerate(lines, start=1):
                for pattern, name, desc in patterns:
                    match = pattern.search(line)
                    if match:
                        component = self._create_component(
                            component_type, file_path, line_num, line, match, name, desc
                        )
                        if component:
                            if current_port not in port_components:
                                port_components[current_port] = []
                            port_components[current_port].append(component)

        return port_components

    def _create_component(
        self,
        component_type: ComponentType,
        file_path: str,
        line_num: int,
        line: str,
        match: re.Match,
        name: str,
        desc: str,
    ) -> Optional[PortComponent]:
        """创建组件对象

        Args:
            component_type: 组件类型
            file_path: 文件路径
            line_num: 行号
            line: 行内容
            match: 正则匹配结果
            name: 组件名称
            desc: 组件描述

        Returns:
            组件对象
        """
        pattern = match.group(0) if match.groups() else line.strip()[:50]
        extracted_name = self._extract_component_name(component_type, match, line)

        context_lines = []
        try:
            context_lines.append(line.strip())
        except Exception:
            pass

        metadata = {}
        if component_type == ComponentType.ROUTE_HANDLER:
            if match.groups():
                metadata["route"] = match.group(1) if len(match.groups()) >= 1 else ""
                if len(match.groups()) >= 2:
                    metadata["path"] = match.group(2)

        return PortComponent(
            component_type=component_type,
            file_path=file_path,
            line_number=line_num,
            name=extracted_name,
            pattern=pattern,
            context=" | ".join(context_lines) if context_lines else line.strip()[:100],
            metadata=metadata,
        )

    def _extract_component_name(
        self, component_type: ComponentType, match: re.Match, line: str
    ) -> str:
        """提取组件名称

        Args:
            component_type: 组件类型
            match: 正则匹配结果
            line: 行内容

        Returns:
            组件名称
        """
        if component_type == ComponentType.ROUTE_HANDLER:
            if match.groups() and len(match.groups()) >= 2:
                return str(match.group(2))
            return str(line.strip()[:50])

        class_match = re.search(r"class\s+(\w+)", line)
        if class_match:
            return str(class_match.group(1))

        decorator_match = re.search(r"@(\w+)", line)
        if decorator_match:
            return str(decorator_match.group(1))

        return str(component_type.value)

    def scan_directory(self, directory: str, recursive: bool = True) -> PortMappingResult:
        """扫描目录中的端口关联文件

        Args:
            directory: 目录路径
            recursive: 是否递归扫描子目录

        Returns:
            端口映射结果
        """
        result = PortMappingResult()
        dir_path = Path(directory)

        if not dir_path.exists():
            logger.warning(f"目录不存在: {directory}")
            return result

        for file_path in dir_path.rglob("*") if recursive else dir_path.glob("*"):
            if not file_path.is_file():
                continue

            if not (self.is_source_file(str(file_path)) or self.is_config_file(str(file_path))):
                continue

            try:
                port_components = self.analyze_file(str(file_path))
                for port, components in port_components.items():
                    if port not in result.port_mappings:
                        result.port_mappings[port] = PortMapping(port=port)

                    mapping = result.port_mappings[port]
                    for component in components:
                        mapping.components.append(component)
                        self._classify_component(mapping, component)

                    detected_binding = self._detect_port_binding(str(file_path), components)
                    if detected_binding:
                        mapping.bindings.append(detected_binding)

            except Exception as e:
                logger.debug(f"扫描文件出错 {file_path}: {e}")

        result.total_ports = len(result.port_mappings)
        result.total_components = sum(len(m.components) for m in result.port_mappings.values())

        return result

    def scan_files(self, file_paths: List[str]) -> PortMappingResult:
        """扫描多个文件

        Args:
            file_paths: 文件路径列表

        Returns:
            端口映射结果
        """
        result = PortMappingResult()

        for file_path in file_paths:
            if not (self.is_source_file(file_path) or self.is_config_file(file_path)):
                continue

            try:
                port_components = self.analyze_file(file_path)
                for port, components in port_components.items():
                    if port not in result.port_mappings:
                        result.port_mappings[port] = PortMapping(port=port)

                    mapping = result.port_mappings[port]
                    for component in components:
                        mapping.components.append(component)
                        self._classify_component(mapping, component)

                    detected_binding = self._detect_port_binding(file_path, components)
                    if detected_binding:
                        mapping.bindings.append(detected_binding)

            except Exception as e:
                logger.debug(f"扫描文件出错 {file_path}: {e}")

        result.total_ports = len(result.port_mappings)
        result.total_components = sum(len(m.components) for m in result.port_mappings.values())

        return result

    def _classify_component(self, mapping: PortMapping, component: PortComponent) -> None:
        """将组件分类到对应列表

        Args:
            mapping: 端口映射
            component: 组件
        """
        if component.component_type == ComponentType.ROUTE_HANDLER:
            mapping.route_handlers.append(component)
        elif component.component_type == ComponentType.SECURITY_CONFIG:
            mapping.security_configs.append(component)
        elif component.component_type == ComponentType.CORS_CONFIG:
            mapping.cors_configs.append(component)
        elif component.component_type == ComponentType.FILTER:
            mapping.filters.append(component)
        elif component.component_type == ComponentType.INTERCEPTOR:
            mapping.interceptors.append(component)
        elif component.component_type == ComponentType.SWAGGER_CONFIG:
            mapping.api_docs.append(component)
        elif component.component_type == ComponentType.MIDDLEWARE:
            mapping.filters.append(component)

    def _detect_port_binding(
        self, file_path: str, components: List[PortComponent]
    ) -> Optional[PortBinding]:
        """检测端口绑定信息

        Args:
            file_path: 文件路径
            components: 组件列表

        Returns:
            端口绑定信息
        """
        if not components:
            return None

        first_component = components[0]
        binding = PortBinding(
            port=0,
            file_path=file_path,
            line_number=first_component.line_number,
            context=first_component.context,
        )

        for component in components:
            if component.component_type == ComponentType.ROUTE_HANDLER:
                binding.protocol = "HTTP"
                break

        return binding

    def get_port_summary(self, result: PortMappingResult) -> Dict[int, Dict[str, Any]]:
        """获取端口映射摘要

        Args:
            result: 端口映射结果

        Returns:
            摘要信息
        """
        summary = {}
        for port, mapping in result.port_mappings.items():
            summary[port] = {
                "total_components": len(mapping.components),
                "route_handlers": len(mapping.route_handlers),
                "security_configs": len(mapping.security_configs),
                "cors_configs": len(mapping.cors_configs),
                "filters": len(mapping.filters),
                "interceptors": len(mapping.interceptors),
                "api_docs": len(mapping.api_docs),
                "files": list(set(c.file_path for c in mapping.components)),
            }
        return summary


def scan_port_mappings(directory: str, recursive: bool = True) -> PortMappingResult:
    """快速扫描目录中的端口映射

    Args:
        directory: 目录路径
        recursive: 是否递归扫描

    Returns:
        端口映射结果
    """
    mapper = PortFileMapper()
    return mapper.scan_directory(directory, recursive)


def scan_port_files(file_paths: List[str]) -> PortMappingResult:
    """快速扫描多个文件的端口映射

    Args:
        file_paths: 文件路径列表

    Returns:
        端口映射结果
    """
    mapper = PortFileMapper()
    return mapper.scan_files(file_paths)

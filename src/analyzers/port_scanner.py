"""API端口配置静态识别模块

专门用于快速扫描配置文件和代码中的端口配置信息。
使用正则模式匹配，速度快。

支持的文件类型:
- YAML (.yml, .yaml)
- Properties (.properties)
- JSON (.json)
- XML (.xml)
- ENV (.env)

支持的代码类型:
- Java Spring/Netty
- Python Flask/Django
- Node.js Express
- Go
- C/C++
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PortType(Enum):
    """端口类型"""
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    UDP = "udp"
    UNKNOWN = "unknown"


class PortSource(Enum):
    """端口来源"""
    CONFIG_YAML = "config_yaml"
    CONFIG_PROPERTIES = "config_properties"
    CONFIG_JSON = "config_json"
    CONFIG_XML = "config_xml"
    CONFIG_ENV = "config_env"
    CODE_JAVA_SPRING = "code_java_spring"
    CODE_JAVA_NETTY = "code_java_netty"
    CODE_PYTHON_FLASK = "code_python_flask"
    CODE_PYTHON_DJANGO = "code_python_django"
    CODE_NODE_EXPRESS = "code_node_express"
    CODE_GO = "code_go"
    CODE_CPP = "code_cpp"
    DYNAMIC_ENV = "dynamic_env"
    DYNAMIC_RANDOM = "dynamic_random"
    DYNAMIC_CONFIG_READ = "dynamic_config_read"


class PortProtocol(Enum):
    """端口协议类型"""
    STATIC = "static"
    DYNAMIC = "dynamic"


@dataclass
class PortFinding:
    """端口扫描发现"""
    file_path: str
    line_number: int
    port: str
    port_type: PortType
    source: PortSource
    protocol: PortProtocol
    pattern_name: str
    description: str
    context: str = ""


@dataclass
class PortScanResult:
    """端口扫描结果"""
    total_files: int = 0
    files_with_ports: int = 0
    findings: List[PortFinding] = field(default_factory=list)

    def get_static_ports(self) -> List[PortFinding]:
        return [f for f in self.findings if f.protocol == PortProtocol.STATIC]

    def get_dynamic_ports(self) -> List[PortFinding]:
        return [f for f in self.findings if f.protocol == PortProtocol.DYNAMIC]

    def get_http_ports(self) -> List[PortFinding]:
        return [f for f in self.findings if f.port_type == PortType.HTTP]

    def get_unique_ports(self) -> Set[str]:
        return set(f.port for f in self.findings if f.protocol == PortProtocol.STATIC)


class PortPatterns:
    """端口配置检测模式"""

    YAML_PATTERNS = [
        (r'server\s*:\s*port\s*:\s*(\d+)', 'yaml_server_port', 'YAML server.port 配置'),
        (r'port\s*:\s*(\d+)', 'yaml_port', 'YAML port 配置'),
        (r'ports\s*:\s*(\d+)', 'yaml_ports', 'YAML ports 配置'),
        (r'http\s*:\s*port\s*:\s*(\d+)', 'yaml_http_port', 'YAML http.port 配置'),
        (r'https\s*:\s*port\s*:\s*(\d+)', 'yaml_https_port', 'YAML https.port 配置'),
        (r'listen\s*:\s*(\d+)', 'yaml_listen', 'YAML listen 配置'),
        (r'bind\s*:\s*(\d+)', 'yaml_bind', 'YAML bind 配置'),
        (r'address\s*:\s*\S+:(\d+)', 'yaml_address_port', 'YAML 地址:端口'),
    ]

    PROPERTIES_PATTERNS = [
        (r'server\.port\s*=\s*(\d+)', 'props_server_port', 'Properties server.port'),
        (r'port\s*=\s*(\d+)', 'props_port', 'Properties port'),
        (r'http\.port\s*=\s*(\d+)', 'props_http_port', 'Properties http.port'),
        (r'https\.port\s*=\s*(\d+)', 'props_https_port', 'Properties https.port'),
        (r'listen\.port\s*=\s*(\d+)', 'props_listen_port', 'Properties listen.port'),
    ]

    JSON_PATTERNS = [
        (r'"port"\s*:\s*(\d+)', 'json_port', 'JSON port'),
        (r'"server"\s*:\s*\{[^}]*"port"\s*:\s*(\d+)', 'json_server_port', 'JSON server.port'),
        (r'"http"\s*:\s*\{[^}]*"port"\s*:\s*(\d+)', 'json_http_port', 'JSON http.port'),
        (r'"https"\s*:\s*\{[^}]*"port"\s*:\s*(\d+)', 'json_https_port', 'JSON https.port'),
        (r'"listen"\s*:\s*(\d+)', 'json_listen', 'JSON listen'),
    ]

    XML_PATTERNS = [
        (r'<port>(\d+)</port>', 'xml_port', 'XML port'),
        (r'<server-port>(\d+)</server-port>', 'xml_server_port', 'XML server-port'),
        (r'<http-port>(\d+)</http-port>', 'xml_http_port', 'XML http-port'),
        (r'<listener-port>(\d+)</listener-port>', 'xml_listener_port', 'XML listener-port'),
    ]

    ENV_PATTERNS = [
        (r'^PORT\s*=\s*(\d+)', 'env_port', 'ENV PORT'),
        (r'^SERVER_PORT\s*=\s*(\d+)', 'env_server_port', 'ENV SERVER_PORT'),
        (r'^HTTP_PORT\s*=\s*(\d+)', 'env_http_port', 'ENV HTTP_PORT'),
        (r'^HTTPS_PORT\s*=\s*(\d+)', 'env_https_port', 'ENV HTTPS_PORT'),
        (r'^LISTEN_PORT\s*=\s*(\d+)', 'env_listen_port', 'ENV LISTEN_PORT'),
    ]

    JAVA_SPRING_PATTERNS = [
        (r'@RestController[^@]*public\s+class\s+\w+', 'java_rest_controller', 'Java REST Controller'),
        (r'@RequestMapping[^)]*\([^)]*value\s*=\s*"[^"]*"', 'java_request_mapping', 'Java RequestMapping'),
        (r'@GetMapping[^)]*\([^)]*value\s*=\s*"[^"]*"', 'java_get_mapping', 'Java GET Mapping'),
        (r'@PostMapping[^)]*\([^)]*value\s*=\s*"[^"]*"', 'java_post_mapping', 'Java POST Mapping'),
        (r'\.port\s*\(\s*(\d+)\s*\)', 'java_server_port', 'Java Server port()'),
        (r'ServerProperties[^}]*port\s*=\s*(\d+)', 'java_server_props_port', 'Java ServerProperties port'),
    ]

    JAVA_NETTY_PATTERNS = [
        (r'ServerBootstrap\(\)', 'java_netty_bootstrap', 'Java Netty ServerBootstrap'),
        (r'\.bind\s*\(\s*new\s+InetSocketAddress\s*\([^,]+,\s*(\d+)\s*\)', 'java_netty_bind', 'Java Netty bind()'),
        (r'\.bind\s*\s*(\d+)\s*\)', 'java_netty_bind_port', 'Java Netty bind(port)'),
        (r'\.localAddress\s*\(\s*(\d+)\s*\)', 'java_netty_local_port', 'Java Netty localAddress()'),
    ]

    PYTHON_FLASK_PATTERNS = [
        (r'@app\.route\s*\([^)]*\)', 'python_flask_route', 'Python Flask @app.route'),
        (r'\.run\s*\([^)]*host\s*=\s*[^,)]*,\s*port\s*=\s*(\d+)', 'python_flask_run_port', 'Python Flask app.run(port)'),
        (r'\.run\s*\([^)]*port\s*=\s*(\d+)', 'python_flask_run_port_short', 'Python Flask app.run(port)'),
        (r'app\s*=\s*Flask\s*\([^)]*\)', 'python_flask_app', 'Python Flask app'),
        (r'run\s*\(\s*host\s*=\s*[^,)]*,\s*port\s*=\s*(\d+)', 'python_flask_run_host_port', 'Python Flask run(host, port)'),
    ]

    PYTHON_DJANGO_PATTERNS = [
        (r'python_manage\.py\s+runserver\s+(\d+)', 'python_django_runserver', 'Python Django runserver'),
        (r'--port\s*=\s*(\d+)', 'django_port_option', 'Django --port'),
        (r'PORT\s*=\s*(\d+)', 'django_port_setting', 'Django PORT setting'),
    ]

    NODE_EXPRESS_PATTERNS = [
        (r'app\.listen\s*\(\s*(\d+)', 'node_express_listen', 'Node.js Express app.listen(port)'),
        (r'server\.listen\s*\(\s*(\d+)', 'node_server_listen', 'Node.js server.listen(port)'),
        (r'\.listen\s*\(\s*process\.env\.PORT', 'node_dynamic_port', 'Node.js dynamic PORT'),
        (r'const\s+port\s*=\s*process\.env\.PORT', 'node_port_env', 'Node.js PORT from env'),
        (r'app\.set\s*\(\s*["\']port["\']\s*,\s*(\d+)', 'node_app_set_port', 'Node.js app.set(port)'),
    ]

    GO_PATTERNS = [
        (r'http\.ListenAndServe\s*\(\s*"[^"]*:(\d+)"', 'go_listen_serve', 'Go http.ListenAndServe'),
        (r'http\.ListenAndServe\s*\(\s*":(\d+)"', 'go_listen_serve_short', 'Go http.ListenAndServe(":port")'),
        (r'net\.Listen\s*\(\s*"tcp"\s*,\s*":(\d+)"', 'go_net_listen', 'Go net.Listen'),
        (r'ListenAndServeTLS\s*\(\s*"[^"]*:(\d+)"', 'go_listen_tls', 'Go ListenAndServeTLS'),
        (r'\.Listen\s*\(\s*":(\d+)"', 'go_listener_listen', 'Go listener.Listen'),
    ]

    CPP_PATTERNS = [
        (r'socket\s*\([^)]*PF_INET[^)]*htons\s*\(\s*(\d+)\s*\)', 'cpp_socket_bind', 'C/C++ socket bind'),
        (r'bind\s*\([^)]*htons\s*\(\s*(\d+)\s*\)', 'cpp_bind_port', 'C/C++ bind port'),
        (r'listen\s*\(\s*sock\s*,\s*(\d+)\s*\)', 'cpp_listen', 'C listen backlog'),
        (r'port\s*=\s*(\d+)', 'cpp_port_assign', 'C/C++ port assignment'),
    ]

    DYNAMIC_ENV_PATTERNS = [
        (r'System\.getenv\s*\(\s*["\']PORT["\']', 'java_system_getenv', 'Java System.getenv(PORT)'),
        (r'System\.getProperty\s*\(\s*["\']port["\']', 'java_system_getproperty', 'Java System.getProperty(port)'),
        (r'process\.env\.PORT', 'node_env_port', 'Node.js process.env.PORT'),
        (r'process\.env\.[A-Z_]+PORT', 'node_env_dynamic_port', 'Node.js process.env.*PORT'),
        (r'os\.environ\s*\[["\']PORT["\']\]', 'python_os_environ', 'Python os.environ PORT'),
        (r'os\.getenv\s*\(["\']PORT["\']', 'python_os_getenv', 'Python os.getenv PORT'),
        (r'os\.environ\.get\s*\(["\']PORT["\']', 'python_environ_get', 'Python environ.get PORT'),
        (r'const\s+\w+\s*=\s*process\.env\.\w+PORT', 'node_env_var_port', 'Node.js env variable with PORT'),
    ]

    DYNAMIC_RANDOM_PATTERNS = [
        (r'Math\.random\s*\(\s*\)', 'java_math_random', 'Java Math.random()'),
        (r'new\s+Random\s*\(\s*\)', 'java_random_new', 'Java new Random()'),
        (r'UUID\.randomUUID\s*\(\s*\)', 'java_uuid', 'Java UUID.randomUUID()'),
        (r'timestamp', 'dynamic_timestamp', 'Dynamic timestamp port'),
        (r'Timestamp\.now\s*\(\s*\)', 'java_timestamp', 'Java Timestamp.now()'),
        (r'random\.randint\s*\(\s*\)', 'python_random', 'Python random.randint()'),
        (r'randomNumber', 'js_random', 'JavaScript randomNumber'),
    ]

    DYNAMIC_CONFIG_PATTERNS = [
        (r'ConfigFactory\.load\s*\([^)]*\)', 'java_config_load', 'Java ConfigFactory.load()'),
        (r'Yaml\s*\.load\s*\([^)]*\)', 'python_yaml_load', 'Python YAML load'),
        (r'JSON\.parse\s*\([^)]*\)', 'js_json_parse', 'JavaScript JSON.parse'),
        (r'json\.loads\s*\([^)]*\)', 'python_json_loads', 'Python json.loads()'),
        (r'ConfigurationManager\.getInstance\s*\([^)]*\)', 'java_config_manager', 'Java ConfigurationManager'),
    ]

    @classmethod
    def get_yaml_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.YAML_PATTERNS]

    @classmethod
    def get_properties_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.PROPERTIES_PATTERNS]

    @classmethod
    def get_json_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.DOTALL), n, d) for p, n, d in cls.JSON_PATTERNS]

    @classmethod
    def get_xml_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.XML_PATTERNS]

    @classmethod
    def get_env_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.ENV_PATTERNS]

    @classmethod
    def get_java_spring_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE | re.DOTALL), n, d) for p, n, d in cls.JAVA_SPRING_PATTERNS]

    @classmethod
    def get_java_netty_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.JAVA_NETTY_PATTERNS]

    @classmethod
    def get_python_flask_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.PYTHON_FLASK_PATTERNS]

    @classmethod
    def get_python_django_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.PYTHON_DJANGO_PATTERNS]

    @classmethod
    def get_node_express_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.NODE_EXPRESS_PATTERNS]

    @classmethod
    def get_go_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.GO_PATTERNS]

    @classmethod
    def get_cpp_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.CPP_PATTERNS]

    @classmethod
    def get_dynamic_env_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.DYNAMIC_ENV_PATTERNS]

    @classmethod
    def get_dynamic_random_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.DYNAMIC_RANDOM_PATTERNS]

    @classmethod
    def get_dynamic_config_patterns(cls) -> List[Tuple[re.Pattern, str, str]]:
        return [(re.compile(p, re.MULTILINE), n, d) for p, n, d in cls.DYNAMIC_CONFIG_PATTERNS]


class PortScanner:
    """API端口配置扫描器"""

    CONFIG_EXTENSIONS = {'.yml', '.yaml', '.properties', '.xml', '.json', '.env'}
    CODE_EXTENSIONS = {
        '.java', '.kt', '.py', '.js', '.ts', '.go', '.c', '.cpp', '.h', '.hpp'
    }

    def __init__(self, include_dynamic: bool = True):
        """初始化端口扫描器

        Args:
            include_dynamic: 是否检测动态端口配置
        """
        self.include_dynamic = include_dynamic
        self._findings: List[PortFinding] = []

    def is_port_relevant_file(self, file_path: str) -> bool:
        """判断是否为端口相关文件

        Args:
            file_path: 文件路径

        Returns:
            是否为端口相关文件
        """
        path = Path(file_path)
        suffix = path.suffix.lower()

        return suffix in self.CONFIG_EXTENSIONS or suffix in self.CODE_EXTENSIONS

    def _detect_port_type(self, port_str: str, context: str = "") -> PortType:
        """检测端口类型

        Args:
            port_str: 端口字符串
            context: 上下文信息

        Returns:
            端口类型
        """
        context_lower = context.lower()
        if 'ssl' in context_lower or 'tls' in context_lower or 'https' in context_lower:
            return PortType.HTTPS
        if 'udp' in context_lower or 'datagram' in context_lower:
            return PortType.UDP
        if 'tcp' in context_lower or 'http' in context_lower or 'web' in context_lower:
            return PortType.TCP
        if 'http' in context_lower or 'web' in context_lower or 'api' in context_lower:
            return PortType.HTTP
        return PortType.UNKNOWN

    def _is_common_port(self, port: str) -> bool:
        """判断是否为常见端口

        Args:
            port: 端口号

        Returns:
            是否为常见端口
        """
        common_ports = {
            '80', '443', '8080', '8443', '3000', '5000', '5432', '3306',
            '6379', '27017', '9200', '5672', '9092', '8081', '8000', '8888',
            '22', '21', '25', '587', '110', '143', '993', '995', '3306'
        }
        return port in common_ports

    def scan_file(self, file_path: str, content: Optional[str] = None) -> List[PortFinding]:
        """扫描单个文件

        Args:
            file_path: 文件路径
            content: 文件内容（如果为None则读取文件）

        Returns:
            发现列表
        """
        findings = []

        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                logger.debug(f"无法读取文件 {file_path}: {e}")
                return findings

        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix in self.CONFIG_EXTENSIONS:
            findings.extend(self._scan_config_file(file_path, content, suffix))
        if suffix in self.CODE_EXTENSIONS:
            findings.extend(self._scan_code_file(file_path, content, suffix))

        return findings

    def _scan_config_file(self, file_path: str, content: str, suffix: str) -> List[PortFinding]:
        """扫描配置文件

        Args:
            file_path: 文件路径
            content: 文件内容
            suffix: 文件扩展名

        Returns:
            发现列表
        """
        findings = []
        lines = content.split('\n')

        if suffix in {'.yml', '.yaml'}:
            patterns = PortPatterns.get_yaml_patterns()
            source = PortSource.CONFIG_YAML
        elif suffix == '.properties':
            patterns = PortPatterns.get_properties_patterns()
            source = PortSource.CONFIG_PROPERTIES
        elif suffix == '.json':
            patterns = PortPatterns.get_json_patterns()
            source = PortSource.CONFIG_JSON
        elif suffix == '.xml':
            patterns = PortPatterns.get_xml_patterns()
            source = PortSource.CONFIG_XML
        elif suffix == '.env':
            patterns = PortPatterns.get_env_patterns()
            source = PortSource.CONFIG_ENV
        else:
            return findings

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                continue

            for pattern, name, desc in patterns:
                match = pattern.search(line)
                if match:
                    port = match.group(1)
                    if not port or not port.isdigit():
                        continue

                    port_type = self._detect_port_type(port, line)

                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port=port,
                        port_type=port_type,
                        source=source,
                        protocol=PortProtocol.STATIC,
                        pattern_name=name,
                        description=f"{desc}: {port}",
                        context=line_stripped
                    )
                    findings.append(finding)

        if self.include_dynamic:
            findings.extend(self._scan_dynamic_config(file_path, lines, source))

        return findings

    def _scan_code_file(self, file_path: str, content: str, suffix: str) -> List[PortFinding]:
        """扫描代码文件

        Args:
            file_path: 文件路径
            content: 文件内容
            suffix: 文件扩展名

        Returns:
            发现列表
        """
        findings = []
        lines = content.split('\n')

        if suffix in {'.java', '.kt'}:
            findings.extend(self._scan_java_code(file_path, content, lines))
        elif suffix == '.py':
            findings.extend(self._scan_python_code(file_path, content, lines))
        elif suffix in {'.js', '.ts'}:
            findings.extend(self._scan_node_code(file_path, content, lines))
        elif suffix == '.go':
            findings.extend(self._scan_go_code(file_path, content, lines))
        elif suffix in {'.c', '.cpp', '.h', '.hpp'}:
            findings.extend(self._scan_cpp_code(file_path, content, lines))

        if self.include_dynamic:
            findings.extend(self._scan_dynamic_code(file_path, content, lines))

        return findings

    def _scan_java_code(self, file_path: str, content: str, lines: List[str]) -> List[PortFinding]:
        """扫描Java代码

        Args:
            file_path: 文件路径
            content: 文件内容
            lines: 文件行列表

        Returns:
            发现列表
        """
        findings = []
        spring_patterns = PortPatterns.get_java_spring_patterns()
        netty_patterns = PortPatterns.get_java_netty_patterns()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            for pattern, name, desc in spring_patterns:
                if pattern.search(line):
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port="",
                        port_type=PortType.HTTP,
                        source=PortSource.CODE_JAVA_SPRING,
                        protocol=PortProtocol.STATIC,
                        pattern_name=name,
                        description=f"Java Spring: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

            for pattern, name, desc in netty_patterns:
                match = pattern.search(line)
                if match:
                    port = match.group(1) if match.groups() else ""
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port=port,
                        port_type=PortType.TCP,
                        source=PortSource.CODE_JAVA_NETTY,
                        protocol=PortProtocol.STATIC,
                        pattern_name=name,
                        description=f"Java Netty: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

        return findings

    def _scan_python_code(self, file_path: str, content: str, lines: List[str]) -> List[PortFinding]:
        """扫描Python代码

        Args:
            file_path: 文件路径
            content: 文件内容
            lines: 文件行列表

        Returns:
            发现列表
        """
        findings = []
        flask_patterns = PortPatterns.get_python_flask_patterns()
        django_patterns = PortPatterns.get_python_django_patterns()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                continue

            for pattern, name, desc in flask_patterns:
                match = pattern.search(line)
                if match:
                    port = match.group(1) if match.groups() else ""
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port=port,
                        port_type=PortType.HTTP,
                        source=PortSource.CODE_PYTHON_FLASK,
                        protocol=PortProtocol.STATIC if port else PortProtocol.DYNAMIC,
                        pattern_name=name,
                        description=f"Python Flask: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

            for pattern, name, desc in django_patterns:
                match = pattern.search(line)
                if match:
                    port = match.group(1) if match.groups() else ""
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port=port,
                        port_type=PortType.HTTP,
                        source=PortSource.CODE_PYTHON_DJANGO,
                        protocol=PortProtocol.STATIC if port else PortProtocol.DYNAMIC,
                        pattern_name=name,
                        description=f"Python Django: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

        return findings

    def _scan_node_code(self, file_path: str, content: str, lines: List[str]) -> List[PortFinding]:
        """扫描Node.js代码

        Args:
            file_path: 文件路径
            content: 文件内容
            lines: 文件行列表

        Returns:
            发现列表
        """
        findings = []
        express_patterns = PortPatterns.get_node_express_patterns()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//'):
                continue

            for pattern, name, desc in express_patterns:
                match = pattern.search(line)
                if match:
                    port = match.group(1) if match.groups() else ""
                    is_dynamic = 'process.env' in line or 'dynamic' in name
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port=port,
                        port_type=PortType.HTTP,
                        source=PortSource.CODE_NODE_EXPRESS,
                        protocol=PortProtocol.DYNAMIC if is_dynamic else PortProtocol.STATIC,
                        pattern_name=name,
                        description=f"Node.js Express: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

        return findings

    def _scan_go_code(self, file_path: str, content: str, lines: List[str]) -> List[PortFinding]:
        """扫描Go代码

        Args:
            file_path: 文件路径
            content: 文件内容
            lines: 文件行列表

        Returns:
            发现列表
        """
        findings = []
        go_patterns = PortPatterns.get_go_patterns()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//'):
                continue

            for pattern, name, desc in go_patterns:
                match = pattern.search(line)
                if match:
                    port = match.group(1) if match.groups() else ""
                    port_type = PortType.HTTPS if 'TLS' in name else PortType.HTTP
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port=port,
                        port_type=port_type,
                        source=PortSource.CODE_GO,
                        protocol=PortProtocol.STATIC,
                        pattern_name=name,
                        description=f"Go: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

        return findings

    def _scan_cpp_code(self, file_path: str, content: str, lines: List[str]) -> List[PortFinding]:
        """扫描C/C++代码

        Args:
            file_path: 文件路径
            content: 文件内容
            lines: 文件行列表

        Returns:
            发现列表
        """
        findings = []
        cpp_patterns = PortPatterns.get_cpp_patterns()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue

            for pattern, name, desc in cpp_patterns:
                match = pattern.search(line)
                if match:
                    port = match.group(1) if match.groups() else ""
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port=port,
                        port_type=PortType.TCP,
                        source=PortSource.CODE_CPP,
                        protocol=PortProtocol.STATIC if port else PortProtocol.DYNAMIC,
                        pattern_name=name,
                        description=f"C/C++: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

        return findings

    def _scan_dynamic_config(self, file_path: str, lines: List[str], source: PortSource) -> List[PortFinding]:
        """扫描配置文件中的动态端口

        Args:
            file_path: 文件路径
            lines: 文件行列表
            source: 端口来源

        Returns:
            发现列表
        """
        findings = []
        env_patterns = PortPatterns.get_dynamic_env_patterns()
        config_patterns = PortPatterns.get_dynamic_config_patterns()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                continue

            for pattern, name, desc in env_patterns:
                if pattern.search(line):
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port="",
                        port_type=PortType.UNKNOWN,
                        source=PortSource.DYNAMIC_ENV,
                        protocol=PortProtocol.DYNAMIC,
                        pattern_name=name,
                        description=f"动态端口: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

            for pattern, name, desc in config_patterns:
                if pattern.search(line):
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port="",
                        port_type=PortType.UNKNOWN,
                        source=PortSource.DYNAMIC_CONFIG_READ,
                        protocol=PortProtocol.DYNAMIC,
                        pattern_name=name,
                        description=f"动态配置读取: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

        return findings

    def _scan_dynamic_code(self, file_path: str, content: str, lines: List[str]) -> List[PortFinding]:
        """扫描代码中的动态端口

        Args:
            file_path: 文件路径
            content: 文件内容
            lines: 文件行列表

        Returns:
            发现列表
        """
        findings = []
        env_patterns = PortPatterns.get_dynamic_env_patterns()
        random_patterns = PortPatterns.get_dynamic_random_patterns()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            for pattern, name, desc in env_patterns:
                if pattern.search(line):
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port="",
                        port_type=PortType.UNKNOWN,
                        source=PortSource.DYNAMIC_ENV,
                        protocol=PortProtocol.DYNAMIC,
                        pattern_name=name,
                        description=f"动态端口: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

            for pattern, name, desc in random_patterns:
                if pattern.search(line):
                    finding = PortFinding(
                        file_path=file_path,
                        line_number=line_num,
                        port="",
                        port_type=PortType.UNKNOWN,
                        source=PortSource.DYNAMIC_RANDOM,
                        protocol=PortProtocol.DYNAMIC,
                        pattern_name=name,
                        description=f"随机端口生成: {desc}",
                        context=line_stripped
                    )
                    findings.append(finding)

        return findings

    def scan_directory(self, directory: str, recursive: bool = True) -> PortScanResult:
        """扫描目录中的所有文件

        Args:
            directory: 目录路径
            recursive: 是否递归扫描子目录

        Returns:
            扫描结果
        """
        result = PortScanResult()
        dir_path = Path(directory)

        if not dir_path.exists():
            logger.warning(f"目录不存在: {directory}")
            return result

        for file_path in dir_path.rglob('*') if recursive else dir_path.glob('*'):
            if not file_path.is_file():
                continue

            if not self.is_port_relevant_file(str(file_path)):
                continue

            result.total_files += 1

            findings = self.scan_file(str(file_path))
            if findings:
                result.files_with_ports += 1
                result.findings.extend(findings)

        return result

    def scan_files(self, file_paths: List[str]) -> PortScanResult:
        """扫描多个文件

        Args:
            file_paths: 文件路径列表

        Returns:
            扫描结果
        """
        result = PortScanResult()

        for file_path in file_paths:
            if not self.is_port_relevant_file(file_path):
                continue

            result.total_files += 1

            findings = self.scan_file(file_path)
            if findings:
                result.files_with_ports += 1
                result.findings.extend(findings)

        return result


def scan_port_directory(directory: str, include_dynamic: bool = True) -> PortScanResult:
    """快速扫描端口配置目录

    Args:
        directory: 目录路径
        include_dynamic: 是否检测动态端口配置

    Returns:
        扫描结果
    """
    scanner = PortScanner(include_dynamic=include_dynamic)
    return scanner.scan_directory(directory)


def scan_port_files(file_paths: List[str]) -> PortScanResult:
    """快速扫描多个文件的端口配置

    Args:
        file_paths: 文件路径列表

    Returns:
        扫描结果
    """
    scanner = PortScanner()
    return scanner.scan_files(file_paths)

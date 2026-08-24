"""Sink注册表

定义高危Sink集合，用于SAL路径探索。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class SinkCategory(str, Enum):
    """Sink类别枚举"""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    DESERIALIZATION = "deserialization"
    FILE_INCLUSION = "file_inclusion"
    TEMPLATE_INJECTION = "template_injection"
    RACE_CONDITION = "race_condition"
    OTHER = "other"


@dataclass
class SinkDefinition:
    """Sink定义"""
    category: SinkCategory
    name: str
    patterns: List[str]  # 函数名/方法名模式
    languages: List[str]  # 支持的语言
    severity: str = "HIGH"
    description: str = ""
    
    def matches(self, func_name: str, language: str) -> bool:
        """检查函数名是否匹配此Sink"""
        if language.lower() not in [l.lower() for l in self.languages]:
            return False
        func_lower = func_name.lower()
        return any(p.lower() in func_lower for p in self.patterns)


class SinkRegistry:
    """Sink注册表
    
    管理所有高危Sink定义，支持按类别、语言查询。
    """
    
    def __init__(self):
        self._sinks: Dict[str, SinkDefinition] = {}
        self._category_index: Dict[SinkCategory, List[str]] = {}
        self._language_index: Dict[str, List[str]] = {}
        self._register_default_sinks()
    
    def _register_default_sinks(self):
        """注册默认Sink集合"""
        default_sinks = [
            # SQL注入
            SinkDefinition(
                category=SinkCategory.SQL_INJECTION,
                name="execute_query",
                patterns=["execute", "query", "raw_sql", "raw_query", "executemany", 
                         "executeNonQuery", "executeReader", "executeScalar",
                         "cursor.execute", "db.execute", "connection.execute"],
                languages=["python", "javascript", "typescript", "java", "csharp", "php", "ruby", "go"],
                severity="CRITICAL",
                description="SQL查询执行点"
            ),
            SinkDefinition(
                category=SinkCategory.SQL_INJECTION,
                name="orm_raw",
                patterns=["raw", "extra", "RawSQL", "RawQuery", "fromRaw",
                         "sequelize.literal", "knex.raw", "prisma.raw"],
                languages=["python", "javascript", "typescript", "java", "csharp"],
                severity="CRITICAL",
                description="ORM原始查询点"
            ),
            
            # 命令注入
            SinkDefinition(
                category=SinkCategory.COMMAND_INJECTION,
                name="os_command",
                patterns=["os.system", "os.popen", "subprocess.call", "subprocess.run",
                         "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
                         "exec", "eval", "execfile", "compile",
                         "Runtime.exec", "ProcessBuilder", "ProcessBuilder.start"],
                languages=["python", "javascript", "typescript", "java", "csharp", "ruby", "go"],
                severity="CRITICAL",
                description="操作系统命令执行点"
            ),
            SinkDefinition(
                category=SinkCategory.COMMAND_INJECTION,
                name="shell_execution",
                patterns=["shell", "popen", "spawn", "execSync", "execFileSync",
                         "child_process.exec", "child_process.spawn",
                         "ShellExecute", "CreateProcess"],
                languages=["python", "javascript", "typescript", "java", "csharp", "go"],
                severity="CRITICAL",
                description="Shell执行点"
            ),
            
            # 路径遍历
            SinkDefinition(
                category=SinkCategory.PATH_TRAVERSAL,
                name="file_operation",
                patterns=["open", "read_file", "write_file", "readFileSync", "writeFileSync",
                         "fs.readFile", "fs.writeFile", "fs.readFileSync", "fs.writeFileSync",
                         "path.join", "path.resolve", "os.path.join",
                         "File", "FileInputStream", "FileOutputStream",
                         "StreamReader", "StreamWriter"],
                languages=["python", "javascript", "typescript", "java", "csharp", "ruby", "go"],
                severity="HIGH",
                description="文件操作点"
            ),
            SinkDefinition(
                category=SinkCategory.PATH_TRAVERSAL,
                name="file_inclusion",
                patterns=["include", "require", "import", "load",
                         "include_once", "require_once",
                         "Module.require", "import()"],
                languages=["python", "javascript", "typescript", "php", "ruby"],
                severity="HIGH",
                description="文件包含点"
            ),
            
            # XSS
            SinkDefinition(
                category=SinkCategory.XSS,
                name="html_output",
                patterns=["innerHTML", "outerHTML", "document.write", "document.writeln",
                         "insertAdjacentHTML", "dangerouslySetInnerHTML",
                         "html", "render", "template", "mark_safe", "safe",
                         "escape", "unescape", "unescapeHtml"],
                languages=["python", "javascript", "typescript", "java", "csharp", "php", "ruby"],
                severity="HIGH",
                description="HTML输出点"
            ),
            SinkDefinition(
                category=SinkCategory.XSS,
                name="javascript_execution",
                patterns=["eval", "Function", "setTimeout", "setInterval",
                         "setImmediate", "execScript",
                         "ScriptEngine", "ScriptEngine.eval"],
                languages=["javascript", "typescript", "java", "csharp"],
                severity="HIGH",
                description="JavaScript执行点"
            ),
            
            # SSRF
            SinkDefinition(
                category=SinkCategory.SSRF,
                name="http_request",
                patterns=["requests.get", "requests.post", "requests.put", "requests.delete",
                         "http.get", "http.post", "http.put", "http.delete",
                         "fetch", "axios.get", "axios.post", "axios.put", "axios.delete",
                         "urllib.request", "urlopen", "urlretrieve",
                         "HttpClient", "RestTemplate", "WebClient",
                         "net.http", "http.Get", "http.Post"],
                languages=["python", "javascript", "typescript", "java", "csharp", "go"],
                severity="HIGH",
                description="HTTP请求点"
            ),
            SinkDefinition(
                category=SinkCategory.SSRF,
                name="url_open",
                patterns=["urlopen", "urlretrieve", "URL.open", "openURL",
                         "open-uri", "Net::HTTP", "Faraday", "HTTParty"],
                languages=["python", "ruby", "java"],
                severity="HIGH",
                description="URL打开点"
            ),
            
            # 认证绕过
            SinkDefinition(
                category=SinkCategory.AUTH_BYPASS,
                name="permission_check",
                patterns=["check_permission", "check_auth", "authenticate", "authorize",
                         "verify_token", "verify_session", "validate_token",
                         "is_authenticated", "is_authorized", "has_permission",
                         "require_auth", "login_required", "permission_required",
                         "CheckPermission", "Authorize", "Authenticate"],
                languages=["python", "javascript", "typescript", "java", "csharp", "ruby", "go"],
                severity="CRITICAL",
                description="权限检查点"
            ),
            SinkDefinition(
                category=SinkCategory.AUTH_BYPASS,
                name="session_management",
                patterns=["session", "cookie", "token", "jwt", "oauth",
                         "create_session", "destroy_session", "invalidate_session",
                         "Session", "Cookie", "Token", "JWT"],
                languages=["python", "javascript", "typescript", "java", "csharp", "ruby", "go"],
                severity="HIGH",
                description="会话管理点"
            ),
            
            # 反序列化
            SinkDefinition(
                category=SinkCategory.DESERIALIZATION,
                name="deserialize",
                patterns=["pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load",
                         "marshal.loads", "shelve.open", "jsonpickle.decode",
                         "ObjectInputStream.readObject", "readObject",
                         "JSON.parse", "JSON.parseObject", "fromJSON",
                         "deserialize", "unserialize", "decode"],
                languages=["python", "java", "javascript", "typescript", "php", "ruby", "csharp"],
                severity="CRITICAL",
                description="反序列化点"
            ),
            
            # 模板注入
            SinkDefinition(
                category=SinkCategory.TEMPLATE_INJECTION,
                name="template_render",
                patterns=["render_template", "render", "template", "jinja", "mako",
                         "Template", "Environment", "from_string",
                         "renderToString", "renderToStaticMarkup",
                         "compile", "eval_template"],
                languages=["python", "javascript", "typescript", "java", "csharp", "ruby", "php"],
                severity="HIGH",
                description="模板渲染点"
            ),
            
            # 竞态条件
            SinkDefinition(
                category=SinkCategory.RACE_CONDITION,
                name="file_lock",
                patterns=["lock", "unlock", "flock", "fcntl.lockf",
                         "FileLock", "LockFile", "Mutex", "Semaphore",
                         "acquire", "release", "wait", "notify"],
                languages=["python", "java", "csharp", "go", "rust"],
                severity="MEDIUM",
                description="文件锁/同步点"
            ),
        ]
        
        for sink in default_sinks:
            self.register(sink)
    
    def register(self, sink: SinkDefinition):
        """注册Sink定义"""
        self._sinks[sink.name] = sink
        
        # 更新类别索引
        if sink.category not in self._category_index:
            self._category_index[sink.category] = []
        self._category_index[sink.category].append(sink.name)
        
        # 更新语言索引
        for lang in sink.languages:
            if lang not in self._language_index:
                self._language_index[lang] = []
            self._language_index[lang].append(sink.name)
    
    def get(self, name: str) -> Optional[SinkDefinition]:
        """获取Sink定义"""
        return self._sinks.get(name)
    
    def get_by_category(self, category: SinkCategory) -> List[SinkDefinition]:
        """按类别获取Sink列表"""
        names = self._category_index.get(category, [])
        return [self._sinks[n] for n in names if n in self._sinks]
    
    def get_by_language(self, language: str) -> List[SinkDefinition]:
        """按语言获取Sink列表"""
        names = self._language_index.get(language.lower(), [])
        return [self._sinks[n] for n in names if n in self._sinks]
    
    def get_all(self) -> List[SinkDefinition]:
        """获取所有Sink定义"""
        return list(self._sinks.values())
    
    def find_matching_sinks(self, func_name: str, language: str) -> List[SinkDefinition]:
        """查找匹配给定函数名和语言的所有Sink"""
        return [sink for sink in self._sinks.values() 
                if sink.matches(func_name, language)]
    
    def is_sink(self, func_name: str, language: str) -> bool:
        """检查函数是否是Sink"""
        return len(self.find_matching_sinks(func_name, language)) > 0
    
    def get_sink_categories(self) -> List[SinkCategory]:
        """获取所有Sink类别"""
        return list(self._category_index.keys())
    
    def export_for_prompt(self, language: str = None) -> str:
        """导出Sink信息供Prompt使用"""
        sinks = self.get_by_language(language) if language else self.get_all()
        
        lines = ["=== 高危Sink集合 ==="]
        for category in SinkCategory:
            category_sinks = [s for s in sinks if s.category == category]
            if category_sinks:
                lines.append(f"\n## {category.value}")
                for sink in category_sinks:
                    lines.append(f"- {sink.name}: {sink.description}")
                    lines.append(f"  模式: {', '.join(sink.patterns[:5])}...")
        
        return "\n".join(lines)

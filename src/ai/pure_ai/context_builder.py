import ast
import os
import re
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class SIREntry:
    """Security Intermediate Representation - 安全中间表示
    
    统一表示不同语言代码中的安全相关信息，不依赖具体语言
    """
    file_path: str
    inputs: List[Dict[str, Any]] = field(default_factory=list)
    processes: List[Dict[str, Any]] = field(default_factory=list)
    sinks: List[Dict[str, Any]] = field(default_factory=list)
    sanitizers: List[Dict[str, Any]] = field(default_factory=list)
    auth_checks: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'file_path': self.file_path,
            'inputs': self.inputs,
            'processes': self.processes,
            'sinks': self.sinks,
            'sanitizers': self.sanitizers,
            'auth_checks': self.auth_checks
        }


class ContextBuilder:
    """上下文构建器（伪RAG）
    
    在不使用embedding的情况下构建代码分析上下文
    """
    
    DATA_FLOW_KEYWORDS = {
        'SOURCE': {
            'java': [
                'getParameter', 'getQueryString', 'getHeader', 'getInputStream',
                '@RequestParam', '@PathVariable', '@RequestBody', '@RequestHeader',
                'HttpServletRequest', 'RequestFacade', 'Request',
                'request.getParameter', 'request.getQueryString',
            ],
            'python': [
                'request.args', 'request.form', 'request.data', 'request.json',
                'request.files', 'request.values', 'request.values',
                'request.GET', 'request.POST', 'request.COOKIES',
                'input(', 'raw_input(', 'sys.argv',
            ],
            'javascript': [
                'req.body', 'req.query', 'req.params', 'req.headers',
                'request.body', 'request.query', 'request.params',
                'process.argv', 'process.env',
            ],
            'common': [
                'user_input', 'userdata', 'formData', 'FormData',
            ]
        },
        'SINK': {
            'java': [
                'executeQuery', 'executeUpdate', 'execute', 'createStatement',
                'Runtime.exec', 'ProcessBuilder', 'ProcessImpl',
                'ProcessImpl.start', 'ProcessImpl.exec',
                'Statement.execute', 'PreparedStatement.execute',
                'DriverManager.getConnection',
            ],
            'python': [
                'cursor.execute', 'cursor.executemany',
                'os.system', 'os.popen', 'os.spawn',
                'subprocess.call', 'subprocess.run', 'subprocess.Popen',
                'eval(', 'exec(', 'compile(',
                'sqlite3.connect', 'pymongo',
            ],
            'javascript': [
                'child_process.exec', 'child_process.spawn',
                'eval(', 'new Function(',
                'document.write', 'innerHTML', 'outerHTML',
                'eval', 'Function',
            ],
            'common': [
                'sql_query', 'db_query', 'execute_sql',
            ]
        },
        'SANITIZER': {
            'java': [
                'StringEscapeUtils.escapeHtml', 'StringEscapeUtils.escapeSql',
                'escapeHtml', 'escapeXml', 'escapeJavaScript',
                '@Valid', '@Validated', 'isValid',
                'Pattern.matches', 'Matcher.matches',
                'PreparedStatement', 'ParameterMarker', 'Parameter',
            ],
            'python': [
                'html.escape', 'cgi.escape', 'markupsafe.escape',
                'sqlalchemy.text', 'cursor.mogrify',
                'param', 'placeholder',
                're.escape', 'urllib.parse.quote',
            ],
            'javascript': [
                'DOMPurify.sanitize', 'sanitize-html',
                'escapeHtml', 'escapeXml',
                'textContent', 'innerText',
            ],
            'common': [
                'escape', 'sanitize', 'validate', 'filter',
                'htmlspecialchars', 'strip_tags',
            ]
        }
    }
    
    def __init__(self, config: Optional[Any] = None, priority_parser=None, code_graph_engine=None):
        """初始化上下文构建器
        
        Args:
            config: 配置参数
            priority_parser: 自定义优先级解析器实例，用于相关文件选择
            code_graph_engine: 代码图引擎实例，用于获取调用上下文
        """
        self.config = config
        self.priority_parser = priority_parser
        self.code_graph_engine = code_graph_engine
        self._file_cache: Dict[str, str] = {}
        if hasattr(config, 'get'):
            self.max_related_files = config.get('max_related_files', 3)
        else:
            self.max_related_files = getattr(config, 'max_related_files', 3)
    
    SIR_PATTERNS = {
        'inputs': {
            'patterns': [
                r'getParameter\s*\([^)]+\)',
                r'request\.get\s*\([^)]+\)',
                r'request\[',
                r'request\.body',
                r'request\.query',
                r'request\.params',
                r'request\.form',
                r'\$\w+',
                r'\$_GET|\$_POST|\$_REQUEST',
                r'@RequestParam|@PathVariable|@RequestBody',
                r'@RequestMapping|@GetMapping|@PostMapping',
                r'input\(|prompt\(|readline\('
            ],
            'category': 'input'
        },
        'sinks': {
            'patterns': [
                r'execute\s*\(|exec\s*\(',
                r'cursor\.execute|statement\.execute',
                r'eval\s*\(',
                r'Runtime\.exec|ProcessBuilder',
                r'os\.system|os\.popen|subprocess',
                r'shell_exec|system\(|passthru',
                r'innerHTML|outerHTML|document\.write',
                r'sqlite3\.(execute|exec)',
                r'mysqli?_query|pg_query',
                r'child_process|exec\s*\(',
            ],
            'category': 'sink'
        },
        'sanitizers': {
            'patterns': [
                r'escape\s*\(|sanitize\s*\(',
                r'htmlspecialchars|strip_tags',
                r'PreparedStatement|ParameterizedQuery',
                r'bindParam|bindValue',
                r'param\s*=|placeholder\s*=',
                r'validate\s*\(|check\s*\(|filter\s*\(',
                r'Regex|Pattern\.matches',
                r'secure\s*=|httpOnly\s*=',
            ],
            'category': 'sanitizer'
        },
        'auth_checks': {
            'patterns': [
                r'isAuthenticated|isAuthorized',
                r'hasPermission|hasRole|checkRole',
                r'@PreAuthorize|@Secured|@RolesAllowed',
                r'require_permission|check_permission',
                r'authenticate\s*\(|login\s*\(',
                r'verify\s*\(.*token|jwt\.verify',
                r'@AuthenticationPrincipal',
            ],
            'category': 'auth'
        }
    }
    
    def build_context(self, file_path: str) -> Dict[str, Any]:
        """构建文件的分析上下文

        Args:
            file_path: 文件路径

        Returns:
            包含上下文信息的字典
        """
        print(f"[DEBUG] 开始构建上下文: {file_path}")

        ext = Path(file_path).suffix.lower()
        file_name = Path(file_path).name.lower()

        if ext == '.java':
            return self._build_java_context(file_path)
        elif ext in ['.xml', '.yml', '.yaml', '.properties']:
            return self._build_config_context(file_path)
        elif ext in ['.sql']:
            return self._build_sql_context(file_path)
        elif ext in ['.html', '.jsp', '.thtml', '.ejs', '.pug', '.vue', '.svelte']:
            return self._build_template_context(file_path)
        elif ext in ['.css', '.scss', '.less']:
            return self._build_style_context(file_path)
        elif ext in ['.tf'] or file_name.startswith('dockerfile'):
            return self._build_infra_context(file_path)
        else:
            return self._build_generic_context(file_path)
    
    def _normalize_content_for_ai(self, content: str) -> str:
        """Normalize content for AI input to avoid line number shifts.

        Args:
            content: Original file content

        Returns:
            Normalized content with preserved line structure but uniform whitespace
        """
        lines = content.split('\n')
        normalized_lines = []
        for line in lines:
            normalized_line = re.sub(r'[ \t]+', ' ', line)
            normalized_line = re.sub(r'//.*$', '', normalized_line)
            normalized_line = re.sub(r'/\*.*?\*/', '', normalized_line)
            normalized_line = normalized_line.strip()
            normalized_lines.append(normalized_line)
        print("[DEBUG] 文件内容规范化已增强")
        return '\n'.join(normalized_lines)

    def _read_file(self, file_path: str, max_size: int = 1048576) -> str:
        """读取文件内容

        Args:
            file_path: 文件路径
            max_size: 最大读取大小（字节），默认1MB

        Returns:
            文件内容
        """
        if file_path in self._file_cache:
            print(f"[DEBUG] 从缓存读取文件: {file_path}")
            return self._file_cache[file_path]

        try:
            file_size = os.path.getsize(file_path)
            print(f"[DEBUG] 读取文件: {file_path}, 大小: {file_size} 字节")

            if file_size > max_size:
                print(f"[DEBUG] 文件过大，截断为 {max_size} 字节")
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read(max_size)
                content = content + "\n... [文件过大，已截断]"
            else:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                print(f"[DEBUG] 成功读取文件，内容长度: {len(content)} 字符")

            content = self._normalize_content_for_ai(content)

            self._file_cache[file_path] = content
            return content
        except Exception as e:
            print(f"[DEBUG] 读取文件失败: {file_path}, 错误: {e}")
            return ''
    
    def _extract_imports(self, file_path: str) -> List[str]:
        """提取文件中的导入语句（支持 Python、Java、JavaScript/TypeScript）
        
        Args:
            file_path: 文件路径
            
        Returns:
            导入语句列表
        """
        ext = Path(file_path).suffix.lower()
        
        if ext == '.java':
            return self._extract_java_imports_from_file(file_path)
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            return self._extract_js_ts_imports(file_path)
        
        # Default: Python
        imports = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(f"import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        imports.append(f"from {module} import {alias.name}")
        except Exception:
            pass
        return imports
    
    def _extract_java_imports_from_file(self, file_path: str) -> List[str]:
        """提取 Java 文件中的导入语句
        
        Args:
            file_path: Java 文件路径
            
        Returns:
            导入语句列表
        """
        imports = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import_pattern = r'^import\s+(static\s+)?([\w\.]+(?:\.\*)?)\s*;'
            for match in re.finditer(import_pattern, content, re.MULTILINE):
                is_static = match.group(1) is not None
                import_path = match.group(2)
                prefix = "import static " if is_static else "import "
                imports.append(f"{prefix}{import_path};")
        except Exception:
            pass
        return imports
    
    def _extract_js_ts_imports(self, file_path: str) -> List[str]:
        """提取 JavaScript/TypeScript 文件中的导入语句
        
        Args:
            file_path: JS/TS 文件路径
            
        Returns:
            导入语句列表
        """
        imports = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # ES6 import: import X from 'Y'
            es6_import = r"import\s+(?:\{[^}]*\}|\*\s+as\s+\w+|\w+(?:\s*,\s*\{[^}]*\})?|\w+)\s+from\s+['\"]([^'\"]+)['\"]"
            for match in re.finditer(es6_import, content):
                imports.append(f"import ... from '{match.group(1)}'")
            
            # Side-effect import: import 'Y'
            side_effect_import = r"import\s+['\"]([^'\"]+)['\"]"
            for match in re.finditer(side_effect_import, content):
                imports.append(f"import '{match.group(1)}'")
            
            # CommonJS require: require('Y')
            require_import = r"(?:const|let|var)\s+(?:\{[^}]*\}|\w+)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
            for match in re.finditer(require_import, content):
                imports.append(f"require('{match.group(1)}')")
            
            # Dynamic import: import('Y')
            dynamic_import = r"import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
            for match in re.finditer(dynamic_import, content):
                imports.append(f"dynamic import('{match.group(1)}')")
                
        except Exception:
            pass
        return imports
    
    def _build_project_context(self, file_path: str) -> Dict[str, Any]:
        """构建项目级上下文：文件角色、正向/反向导入关系
        
        Args:
            file_path: 当前文件路径
            
        Returns:
            项目上下文信息，包含 file_role, forward_imports, reverse_imports
        """
        result = {
            'file_role': 'unknown',
            'forward_imports': [],
            'reverse_imports': [],
            'project_structure': ''
        }
        
        try:
            ext = Path(file_path).suffix.lower()
            
            # 1. 确定文件角色
            result['file_role'] = self._determine_file_role(file_path)
            
            # 2. 正向导入（当前文件导入哪些模块）
            all_imports = self._extract_imports(file_path)
            result['forward_imports'] = all_imports[:20]  # 限制数量
            
            # 3. 反向导入（哪些文件导入当前文件）
            result['reverse_imports'] = self._find_reverse_imports(file_path)
            
            # 4. 项目简要结构
            result['project_structure'] = self._scan_project_index(file_path)
            
        except Exception as e:
            logger.debug(f"项目级上下文构建失败 {file_path}: {e}")
        
        return result
    
    def _determine_file_role(self, file_path: str) -> str:
        """根据文件路径和命名模式判断文件角色
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件角色描述
        """
        path_lower = file_path.lower()
        file_name = Path(file_path).name.lower()
        
        # Java 角色判断
        if path_lower.endswith('.java'):
            if any(kw in path_lower for kw in ['controller', 'resource', 'restcontroller']):
                return 'controller'
            if any(kw in path_lower for kw in ['service', 'serviceimpl', 'service_impl']):
                return 'service'
            if any(kw in path_lower for kw in ['repository', 'mapper', 'dao', 'jpa', 'entity']):
                return 'repository'
            if any(kw in path_lower for kw in ['config', 'configuration', 'application.yml']):
                return 'config'
            if any(kw in path_lower for kw in ['util', 'helper', 'common', 'constants']):
                return 'util'
            if any(kw in path_lower for kw in ['model', 'dto', 'vo', 'entity', 'pojo']):
                return 'model'
            if any(kw in path_lower for kw in ['middleware', 'filter', 'interceptor']):
                return 'middleware'
            return 'java_class'
        
        # Python 角色判断
        if path_lower.endswith(('.py', '.pyw')):
            if any(kw in path_lower for kw in ['view', 'route', 'controller', 'endpoint', 'api']):
                return 'controller'
            if any(kw in path_lower for kw in ['service', 'business', 'logic']):
                return 'service'
            if any(kw in path_lower for kw in ['model', 'entity', 'schema', 'db']):
                return 'model'
            if any(kw in path_lower for kw in ['repository', 'dao', 'query']):
                return 'repository'
            if any(kw in path_lower for kw in ['config', 'setting', 'env']):
                return 'config'
            if any(kw in path_lower for kw in ['util', 'helper', 'common', 'tools']):
                return 'util'
            if any(kw in path_lower for kw in ['middleware', 'filter', 'hook']):
                return 'middleware'
            return 'python_module'
        
        # JavaScript/TypeScript 角色判断
        if path_lower.endswith(('.js', '.jsx', '.ts', '.tsx')):
            if any(kw in path_lower for kw in ['controller', 'route', 'api', 'handler']):
                return 'controller'
            if any(kw in path_lower for kw in ['service', 'business']):
                return 'service'
            if any(kw in path_lower for kw in ['model', 'schema', 'entity']):
                return 'model'
            if any(kw in path_lower for kw in ['repository', 'dao', 'repository']):
                return 'repository'
            if any(kw in path_lower for kw in ['config', 'env', 'setting']):
                return 'config'
            if any(kw in path_lower for kw in ['util', 'helper', 'common', 'lib']):
                return 'util'
            if any(kw in path_lower for kw in ['middleware', 'guard', 'interceptor']):
                return 'middleware'
            if any(kw in path_lower for kw in ['component', 'page', 'view']):
                return 'component'
            return 'js_ts_module'
        
        # 配置文件
        if path_lower.endswith(('.yml', '.yaml', '.properties', '.xml', '.json', '.env', '.toml')):
            return 'config'
        
        # 模板文件
        if path_lower.endswith(('.html', '.jsp', '.thtml', '.ejs', '.pug', '.vue', '.svelte')):
            if any(kw in path_lower for kw in ['component', 'page', 'view']):
                return 'component'
            return 'template'
        
        # 样式文件
        if path_lower.endswith(('.css', '.scss', '.less')):
            return 'style'
        
        # 数据库文件
        if path_lower.endswith('.sql'):
            return 'database'
        
        # 基础设施文件
        if path_lower.endswith('.tf') or file_name.startswith('dockerfile'):
            return 'infrastructure'
        
        return 'other'
    
    def _find_reverse_imports(self, file_path: str) -> List[str]:
        """查找哪些文件导入了当前文件（反向导入查找）
        
        Args:
            file_path: 当前文件路径
            
        Returns:
            引用当前文件的文件路径列表
        """
        reverse = []
        try:
            project_root = self._find_project_root(file_path)
            if not project_root:
                # 回退：使用当前文件父目录
                project_root = Path(file_path).parent
            
            file_name = Path(file_path).stem
            ext = Path(file_path).suffix.lower()
            target_files = self._get_scan_extensions(ext)
            
            scan_count = 0
            max_scan = 100  # 限制扫描数量
            
            for target_ext in target_files:
                for candidate in project_root.rglob(f'*{target_ext}'):
                    if scan_count >= max_scan:
                        break
                    if str(candidate) == file_path:
                        continue
                    if candidate.name.startswith('__') and target_ext == '.py':
                        continue
                    
                    scan_count += 1
                    try:
                        with open(candidate, 'r', encoding='utf-8', errors='replace') as f:
                            content = f.read(50000)  # 只读前50KB
                        
                        # 检查是否引用了当前文件
                        if self._file_is_importer(content, file_name, file_path):
                            rel_path = str(candidate)
                            if len(rel_path) > 80:
                                rel_path = '...' + rel_path[-77:]
                            reverse.append(rel_path)
                    except Exception:
                        continue
                
                if scan_count >= max_scan:
                    break
            
        except Exception:
            pass
        
        return reverse[:10]
    
    def _file_is_importer(self, content: str, file_name: str, file_path: str) -> bool:
        """检查文件内容是否导入了目标文件
        
        Args:
            content: 文件内容
            file_name: 目标文件名（不含扩展名）
            file_path: 目标文件完整路径
            
        Returns:
            是否存在导入关系
        """
        # Python: import X / from X import
        python_patterns = [
            rf'import\s+{re.escape(file_name)}',
            rf'from\s+[\w.]*{re.escape(file_name)}\s+import',
        ]
        
        # Java: import com.xxx.ClassName
        java_patterns = [
            rf'import\s+[\w.]*{re.escape(file_name)}\s*;',
        ]
        
        # JS/TS: import ... from '...' / require('...')
        js_patterns = [
            rf"from\s+['\"].*?{re.escape(file_name)}['\"]",
            rf"require\s*\(\s*['\"].*?{re.escape(file_name)}['\"]",
        ]
        
        all_patterns = python_patterns + java_patterns + js_patterns
        for pattern in all_patterns:
            if re.search(pattern, content):
                return True
        return False
    
    def _get_scan_extensions(self, ext: str) -> List[str]:
        """根据文件扩展名获取要扫描的目标扩展名
        
        Args:
            ext: 当前文件扩展名
            
        Returns:
            要扫描的扩展名列表
        """
        if ext == '.java':
            return ['.java']
        elif ext in ['.py', '.pyw']:
            return ['.py', '.pyw']
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            return ['.js', '.jsx', '.ts', '.tsx']
        elif ext in ['.html', '.jsp', '.thtml', '.ejs', '.pug', '.vue', '.svelte']:
            return ['.html', '.jsp', '.ejs', '.vue', '.svelte']
        elif ext in ['.css', '.scss', '.less']:
            return ['.css', '.scss', '.less']
        elif ext in ['.sql']:
            return ['.sql']
        elif ext in ['.tf']:
            return ['.tf']
        else:
            return ['.java', '.py', '.js', '.ts']
    
    def _scan_project_index(self, file_path: str) -> str:
        """扫描项目目录，生成简要文件索引
        
        Args:
            file_path: 当前文件路径
            
        Returns:
            项目文件索引字符串
        """
        lines = []
        try:
            project_root = self._find_project_root(file_path)
            if not project_root:
                project_root = Path(file_path).parent.parent
            
            # 扫描顶层目录结构
            dirs = []
            file_counts = {}
            
            for item in project_root.iterdir():
                if item.is_dir() and not item.name.startswith('.') and item.name not in ('node_modules', 'target', 'build', 'dist', '__pycache__', '.git'):
                    dirs.append(item.name)
                    # 统计每个目录下的源码文件数
                    code_count = 0
                    for ext in ['.java', '.py', '.js', '.ts', '.yml', '.xml', '.json']:
                        code_count += len(list(item.rglob(f'*{ext}')))
                    if code_count > 0:
                        file_counts[item.name] = code_count
            
            if dirs:
                lines.append('Project directories:')
                for d in sorted(dirs):
                    count = file_counts.get(d, 0)
                    suffix = f' ({count} code files)' if count > 0 else ''
                    lines.append(f'  - {d}{suffix}')
            
            # 标记当前文件位置
            try:
                rel = Path(file_path).relative_to(project_root)
                lines.append(f'Current file location: {rel}')
            except ValueError:
                pass
                
        except Exception:
            pass
        
        return '\n'.join(lines) if lines else ''
    
    def _extract_function_calls(self, file_path: str) -> List[str]:
        """提取文件中的函数调用
        
        Args:
            file_path: 文件路径
            
        Returns:
            函数调用列表
        """
        function_calls = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        function_calls.append(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        function_calls.append(f"{node.func.attr}")
        except Exception:
            pass
        return function_calls
    
    def _load_related_files(self, file_path: str) -> List[Dict[str, str]]:
        """加载相关文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            相关文件列表，每个文件包含路径和内容
        """
        related_files = []
        try:
            current_path = Path(file_path)
            current_dir = current_path.parent
            imports = self._extract_imports(file_path)
            
            if self.priority_parser is not None:
                related_files = self._apply_priority_rules(file_path, current_dir, imports)
            else:
                related_files = self._load_related_files_default(current_dir, current_path, imports)
            
        except Exception:
            pass
        
        return related_files
    
    def _build_call_graph_context(self, file_path: str, file_content: str) -> str:
        """构建调用图上下文字符串，注入到 AI context 中
        
        Args:
            file_path: 文件路径
            file_content: 文件内容
            
        Returns:
            调用图上下文字符串，如果不可用则返回空字符串
        """
        if self.code_graph_engine is None:
            return ""
        
        try:
            import ast
            
            symbols = []
            try:
                tree = ast.parse(file_content, filename=file_path)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                        symbols.append(node.name)
            except Exception:
                pass
            
            if not symbols:
                return ""
            
            context_parts = []
            context_parts.append("## 代码调用图上下文")
            context_parts.append("Use the call graph context below to understand how this code is used. Callers show where user input comes from, callees shows where data goes.")
            context_parts.append("")
            
            found_any = False
            for symbol in symbols[:10]:
                try:
                    callers_info = self._get_callers_for_symbol(symbol, max_depth=3)
                    callees_info = self._get_callees_for_symbol(symbol, max_depth=3)
                    
                    if callers_info or callees_info:
                        found_any = True
                        context_parts.append(f"### Symbol: {symbol}")
                        
                        if callers_info:
                            context_parts.append(f"  Callers ({len(callers_info)}):")
                            for caller in callers_info[:5]:
                                context_parts.append(f"    - {caller}")
                        
                        if callees_info:
                            context_parts.append(f"  Callees ({len(callees_info)}):")
                            for callee in callees_info[:8]:
                                context_parts.append(f"    - {callee}")
                        
                        context_parts.append("")
                except Exception:
                    continue
            
            if not found_any:
                return ""
            
            imports_text = self._extract_imports_text(file_path)
            if imports_text:
                context_parts.append(f"  Imports: {', '.join(imports_text[:5])}")
                context_parts.append("")
            
            context_parts.append("## 代码调用图上下文结束")
            
            return "\n".join(context_parts)
        except Exception:
            return ""
    
    def _get_callers_for_symbol(self, symbol_name: str, max_depth: int = 3) -> List[str]:
        """获取符号的调用者信息
        
        Args:
            symbol_name: 符号名称
            max_depth: 最大深度
            
        Returns:
            调用者信息列表
        """
        callers = []
        try:
            from src.core.call_graph_analyzer import CallGraphAnalyzer
            analyzer = CallGraphAnalyzer(self.code_graph_engine)
            call_paths = analyzer.get_callers(symbol_name, max_depth=max_depth)
            
            for path in call_paths[:5]:
                if path.path:
                    caller_node = path.path[0]
                    rel_path = caller_node.file_path
                    if len(rel_path) > 60:
                        rel_path = "..." + rel_path[-57:]
                    callers.append(f"{rel_path}:{caller_node.symbol_name}() [depth:{path.depth}]")
        except Exception:
            pass
        
        return callers
    
    def _get_callees_for_symbol(self, symbol_name: str, max_depth: int = 3) -> List[str]:
        """获取符号的被调用者信息
        
        Args:
            symbol_name: 符号名称
            max_depth: 最大深度
            
        Returns:
            被调用者信息列表
        """
        callees = []
        try:
            from src.core.call_graph_analyzer import CallGraphAnalyzer
            analyzer = CallGraphAnalyzer(self.code_graph_engine)
            call_paths = analyzer.get_callees(symbol_name, max_depth=max_depth)
            
            for path in call_paths[:8]:
                if path.path and len(path.path) > 1:
                    callee_node = path.path[-1]
                    callees.append(f"{callee_node.symbol_name}() [depth:{path.depth}]")
        except Exception:
            pass
        
        return callees
    
    def _extract_imports_text(self, file_path: str) -> List[str]:
        """提取导入语句文本
        
        Args:
            file_path: 文件路径
            
        Returns:
            导入语句列表
        """
        try:
            return self._extract_imports(file_path)
        except Exception:
            return []
    
    def _apply_priority_rules(self, file_path: str, current_dir: Path, imports: List[str]) -> List[Dict[str, str]]:
        """使用自定义优先级规则加载相关文件
        
        Args:
            file_path: 当前文件路径
            current_dir: 当前目录
            imports: 导入语句列表
            
        Returns:
            相关文件列表
        """
        related_files = []
        try:
            if hasattr(self.priority_parser, 'get_priority_rules'):
                rules = self.priority_parser.get_priority_rules(file_path)
                if rules and isinstance(rules, list):
                    for rule in rules:
                        if len(related_files) >= self.max_related_files:
                            break
                        
                        if isinstance(rule, dict):
                            target_path = rule.get('path') or rule.get('file')
                            if target_path:
                                target_path = Path(target_path) if not isinstance(target_path, Path) else target_path
                                if target_path.exists() and target_path.suffix in ['.py', '.pyw']:
                                    related_files.append({
                                        'path': str(target_path),
                                        'content': self._read_file(str(target_path), max_size=524288)
                                    })
            
            remaining = self.max_related_files - len(related_files)
            if remaining > 0:
                default_files = self._load_related_files_default(
                    current_dir, Path(file_path), imports, max_files=remaining
                )
                existing_paths = {f['path'] for f in related_files}
                for f in default_files:
                    if f['path'] not in existing_paths and len(related_files) < self.max_related_files:
                        related_files.append(f)
                        
        except Exception:
            pass
        
        return related_files
    
    def _load_related_files_default(self, current_dir: Path, current_path: Path, imports: List[str], max_files: int = None) -> List[Dict[str, str]]:
        """默认的相关文件加载逻辑
        
        Args:
            current_dir: 当前目录
            current_path: 当前文件路径
            imports: 导入语句列表
            max_files: 最大文件数量
            
        Returns:
            相关文件列表
        """
        related_files = []
        limit = max_files if max_files is not None else self.max_related_files
        
        for imp in imports:
            if len(related_files) >= limit:
                break
            
            imp_parts = imp.split()
            if len(imp_parts) >= 2:
                if imp_parts[0] == 'from':
                    module_path = imp_parts[1].replace('.', '/')
                    for ext in ['.py', '.pyw', '.pyc']:
                        potential_path = current_dir / f"{module_path}{ext}"
                        if potential_path.exists():
                            related_files.append({
                                'path': str(potential_path),
                                'content': self._read_file(str(potential_path), max_size=524288)
                            })
                            break
                        potential_init = current_dir / module_path / '__init__.py'
                        if potential_init.exists():
                            related_files.append({
                                'path': str(potential_init),
                                'content': self._read_file(str(potential_init), max_size=524288)
                            })
                            break
                elif imp_parts[0] == 'import':
                    module_name = imp_parts[1]
                    for ext in ['.py', '.pyw', '.pyc']:
                        potential_path = current_dir / f"{module_name.replace('.', '/')}{ext}"
                        if potential_path.exists():
                            related_files.append({
                                'path': str(potential_path),
                                'content': self._read_file(str(potential_path), max_size=524288)
                            })
                            break
                        potential_init = current_dir / module_name.replace('.', '/') / '__init__.py'
                        if potential_init.exists():
                            related_files.append({
                                'path': str(potential_init),
                                'content': self._read_file(str(potential_init), max_size=524288)
                            })
                            break
        
        if len(related_files) < limit:
            python_files = []
            for file in current_dir.iterdir():
                if file.suffix == '.py' and file.name != current_path.name:
                    try:
                        file_size = file.stat().st_size
                        python_files.append((file_size, file))
                    except Exception:
                        pass
            
            python_files.sort(reverse=True, key=lambda x: x[0])
            
            for _, file in python_files:
                if len(related_files) >= limit:
                    break
                related_files.append({
                    'path': str(file),
                    'content': self._read_file(str(file), max_size=524288)
                })
        
        return related_files
    
    def _extract_file_structure(self, file_path: str) -> Dict[str, Any]:
        """提取文件结构
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件结构信息
        """
        structure = {
            'functions': [],
            'classes': [],
            'variables': [],
            'imports': [],
            'class_methods': {},
            'function_calls': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            
            # 提取导入语句
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(f"import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        imports.append(f"from {module} import {alias.name}")
            structure['imports'] = imports
            
            # 提取函数调用
            function_calls = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        function_calls.append(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        function_calls.append(f"{node.func.attr}")
            structure['function_calls'] = function_calls
            
            # 提取类和函数
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # 提取函数参数
                    args = []
                    for arg in node.args.args:
                        args.append(arg.arg)
                    # 提取默认参数
                    defaults = []
                    for default in node.args.defaults:
                        if isinstance(default, ast.Constant):
                            defaults.append(default.value)
                        else:
                            defaults.append(None)
                    # 提取函数文档字符串
                    docstring = ast.get_docstring(node, clean=False)
                    structure['functions'].append({
                        'name': node.name,
                        'args': args,
                        'defaults': defaults,
                        'line': node.lineno,
                        'docstring': docstring
                    })
                elif isinstance(node, ast.ClassDef):
                    # 提取类文档字符串
                    docstring = ast.get_docstring(node, clean=False)
                    structure['classes'].append({
                        'name': node.name,
                        'line': node.lineno,
                        'docstring': docstring
                    })
                    # 提取类方法
                    class_methods = []
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            method_args = []
                            for arg in item.args.args:
                                method_args.append(arg.arg)
                            method_docstring = ast.get_docstring(item, clean=False)
                            class_methods.append({
                                'name': item.name,
                                'args': method_args,
                                'line': item.lineno,
                                'docstring': method_docstring
                            })
                    structure['class_methods'][node.name] = class_methods
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # 尝试提取变量值
                            value = None
                            if isinstance(node.value, ast.Constant):
                                value = node.value.value
                            structure['variables'].append({
                                'name': target.id,
                                'line': node.lineno,
                                'value': value
                            })
        except Exception:
            pass

        return structure

    def _build_generic_context(self, file_path: str) -> Dict[str, Any]:
        """构建通用（Python）文件上下文"""
        file_content = self._read_file(file_path)
        context = {
            'current_file': file_path,
            'file_content': file_content,
            'imports': [],
            'related_files': [],
            'function_calls': [],
            'file_structure': {},
            'file_type': 'python',
            'data_flow': {},
            'call_graph_context': ''
        }

        context['imports'] = self._extract_imports(file_path)
        context['function_calls'] = self._extract_function_calls(file_path)
        context['related_files'] = self._load_related_files(file_path)
        context['file_structure'] = self._extract_file_structure(file_path)
        context['data_flow'] = self._track_data_flow(file_path)
        context['call_graph_context'] = self._build_call_graph_context(file_path, file_content)
        context['project_context'] = self._build_project_context(file_path)

        print(f"[DEBUG] 上下文构建完成，文件内容长度: {len(context['file_content'])} 字符")
        return context

    def _build_java_context(self, file_path: str) -> Dict[str, Any]:
        """构建 Java 文件上下文

        增强版本，增加了对以下内容的检测：
        - Spring MVC 映射（包括 lambda 风格路由）
        - Bean 注入关系（@Autowired, @Resource, @Inject）
        - 类继承关系（extends, implements）
        """
        content = self._read_file(file_path)

        standard_mappings = self._extract_spring_mappings(content)
        bean_references = self._extract_bean_references(content)
        class_hierarchy = self._track_class_hierarchy(content)

        lambda_mappings = self._extract_lambda_router_mappings(content)

        all_mappings = {
            'standard_mappings': standard_mappings,
            'lambda_mappings': lambda_mappings,
            'bean_references': bean_references,
            'class_hierarchy': class_hierarchy
        }

        total_mappings = (
            len(standard_mappings) +
            len(lambda_mappings) +
            len(bean_references) +
            len(class_hierarchy.get('extends', [])) +
            len(class_hierarchy.get('implements', []))
        )

        context = {
            'current_file': file_path,
            'file_content': content,
            'spring_mappings': standard_mappings,
            'lambda_mappings': lambda_mappings,
            'bean_references': bean_references,
            'class_hierarchy': class_hierarchy,
            'all_mappings': all_mappings,
            'class_structure': self._extract_java_classes(content),
            'security_relevant': self._detect_security_patterns(content),
            'related_files': self._load_related_java_files(file_path),
            'imports': self._extract_java_imports(content),
            'function_calls': self._extract_java_function_calls(content),
            'file_type': 'java',
            'data_flow': self._track_data_flow(file_path),
            'call_graph_context': ''
        }

        context['call_graph_context'] = self._build_call_graph_context(file_path, content)
        context['project_context'] = self._build_project_context(file_path)

        print(f"[DEBUG] Java上下文构建完成: 标准映射 {len(standard_mappings)} 个, Lambda映射 {len(lambda_mappings)} 个, Bean引用 {len(bean_references)} 个, 类继承 {len(class_hierarchy.get('extends', [])) + len(class_hierarchy.get('implements', []))} 个 (共 {total_mappings} 个)")
        return context

    def _extract_spring_mappings(self, content: str) -> List[Dict]:
        """提取标准 Spring MVC 映射

        Args:
            content: 文件内容

        Returns:
            映射列表
        """
        patterns = [
            (r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\("([^"]+)"\)', 'standard'),
            (r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(\s*value\s*=\s*"([^"]+)"', 'standard'),
            (r'@RequestMapping\s*\(\s*path\s*=\s*"([^"]+)"', 'standard'),
        ]

        results = []
        for pattern, _ in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                results.append({
                    'type': 'spring_mapping',
                    'mapping_type': match.group(1) if match.lastindex >= 1 else 'RequestMapping',
                    'path': match.group(2) if match.lastindex >= 2 else match.group(1),
                    'line': line_num,
                    'match': match.group(0)
                })
        return results

    def _extract_lambda_router_mappings(self, content: str) -> List[Dict]:
        """提取 lambda 风格的 Spring Cloud Gateway 路由映射

        Args:
            content: 文件内容

        Returns:
            Lambda 映射列表
        """
        results = []

        router_lambda_patterns = [
            (r'\.route\s*\(\s*(?:predicate|routes)\s*->\s*[^)]*\.path\s*\("([^"]+)"\)', 'path_route'),
            (r'\.route\s*\(\s*(?:predicate|routes)\s*->\s*[^)]*\.Method\s*\.\s*([A-Z]+)\s*,\s*"([^"]+)"', 'method_route'),
            (r'routerFunction\s*\(\s*\.\s*path\s*\("([^"]+)"\)\s*\.and\s*\.\s*method\s*\([^)]+\)', 'functional_route'),
        ]

        for pattern, route_type in router_lambda_patterns:
            for match in re.finditer(pattern, content, re.DOTALL):
                line_num = content[:match.start()].count('\n') + 1
                path = match.group(1) if match.lastindex >= 1 else match.group(0)
                results.append({
                    'type': 'lambda_mapping',
                    'route_type': route_type,
                    'path': path,
                    'line': line_num,
                    'match': match.group(0)[:100]
                })

        return results

    def _extract_bean_references(self, content: str) -> List[Dict]:
        """提取 Bean 注入引用关系

        检测 @Autowired, @Resource, @Inject 等注解标记的依赖注入。

        Args:
            content: 文件内容

        Returns:
            Bean 引用列表
        """
        results = []

        bean_patterns = [
            (r'@Autowired\s+(?:private|public|protected)?\s*(\w+(?:<[^>]+>)?)\s+(\w+)\s*;', 'field'),
            (r'@Resource\s*\(\s*(?:name\s*=\s*"([^"]+)",?\s*)?(?:type\s*=\s*([\w.]+))?\s*\)\s*(?:private|public|protected)?\s*(\w+(?:<[^>]+>)?)\s+(\w+)\s*;', 'resource'),
            (r'@Inject\s+(?:private|public|protected)?\s*(\w+(?:<[^>]+>)?)\s+(\w+)\s*;', 'inject_field'),
            (r'(?:private|public|protected)\s+(\w+(?:<[^>]+>)?)\s+(\w+)\s*;\s*//\s*@Autowired', 'comment_autowired'),
            (r'@Bean\s+(?:public|private|protected)?\s*(\w+(?:<[^>]+>)?)\s+(\w+)\s*\(', 'bean_definition'),
        ]

        for pattern, ref_type in bean_patterns:
            for match in re.finditer(pattern, content, re.DOTALL):
                line_num = content[:match.start()].count('\n') + 1
                if ref_type == 'resource':
                    if match.lastindex >= 4:
                        results.append({
                            'type': 'bean_reference',
                            'injection_type': 'resource',
                            'field_type': match.group(2) or match.group(3),
                            'field_name': match.group(4),
                            'line': line_num
                        })
                elif ref_type == 'bean_definition':
                    if match.lastindex >= 2:
                        results.append({
                            'type': 'bean_definition',
                            'return_type': match.group(1),
                            'method_name': match.group(2),
                            'line': line_num
                        })
                else:
                    if match.lastindex >= 2:
                        results.append({
                            'type': 'bean_reference',
                            'injection_type': ref_type,
                            'field_type': match.group(1),
                            'field_name': match.group(2),
                            'line': line_num
                        })

        return results

    def _track_class_hierarchy(self, content: str) -> Dict[str, List[Dict]]:
        """追踪类的继承和实现关系

        Args:
            content: 文件内容

        Returns:
            包含 extends 和 implements 关系的字典
        """
        result = {
            'extends': [],
            'implements': []
        }

        extends_pattern = r'(?:public|private|protected)?\s*class\s+(\w+)\s+extends\s+([\w.<>]+)'
        for match in re.finditer(extends_pattern, content):
            line_num = content[:match.start()].count('\n') + 1
            result['extends'].append({
                'class': match.group(1),
                'parent': match.group(2),
                'line': line_num
            })

        implements_pattern = r'(?:public|private|protected)?\s*class\s+(\w+)\s+(?:implements|extends)\s+([\w.,\s<>]+)'
        for match in re.finditer(implements_pattern, content):
            line_num = content[:match.start()].count('\n') + 1
            interfaces = [i.strip() for i in match.group(2).split(',')]
            result['implements'].append({
                'class': match.group(1),
                'interfaces': interfaces,
                'line': line_num
            })

        return result

    def _build_config_context(self, file_path: str) -> Dict[str, Any]:
        """构建配置文件上下文 (XML/YAML/PROPERTIES)"""
        content = self._read_file(file_path)

        findings = []

        if str(file_path).endswith('.xml'):
            findings.extend(self._scan_mybatis_sql_injection(file_path, content))

        findings.extend(self._scan_config_security(file_path, content))

        return {
            'current_file': file_path,
            'file_content': content,
            'security_findings': findings,
            'related_files': [],
            'file_type': 'config',
            'project_context': self._build_project_context(file_path)
        }

    def _extract_patterns(self, content: str, pattern: str) -> List[Dict]:
        """提取正则匹配结果"""
        results = []
        for match in re.finditer(pattern, content):
            results.append({
                'match': match.group(0),
                'line': content[:match.start()].count('\n') + 1
            })
        return results

    def _extract_java_classes(self, content: str) -> List[Dict]:
        """提取 Java 类结构"""
        classes = []
        class_pattern = r'(public|private|protected)?\s*(class|interface|enum)\s+(\w+)'

        for match in re.finditer(class_pattern, content):
            line_num = content[:match.start()].count('\n') + 1
            classes.append({
                'name': match.group(3),
                'type': match.group(2),
                'line': line_num
            })
        return classes

    def _detect_security_patterns(self, content: str) -> List[Dict]:
        """检测 Java 代码中的安全相关模式"""
        findings = []
        security_patterns = [
            (r'SQL|sql|Connection|Statement|PreparedStatement', 'DATABASE_OPERATION'),
            (r'password|secret|token|credential', 'SENSITIVE_DATA'),
            (r'@RequestParam|@RequestBody|@PathVariable', 'USER_INPUT'),
            (r'Runtime\.getRuntime\(\)|ProcessBuilder', 'COMMAND_EXECUTION'),
            (r'eval\(|execute\(|exec\(', 'CODE_EXECUTION'),
            (r'SecurityConfig|WebSecurityConfigurerAdapter', 'AUTH_CONFIG'),
        ]

        for pattern, pattern_type in security_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': pattern_type,
                    'line': content[:match.start()].count('\n') + 1,
                    'snippet': content[max(0, match.start()-20):match.end()+20]
                })
        return findings

    def _track_data_flow_chain(self, file_path: str) -> Dict[str, Any]:
        """追踪完整的数据流链路

        Args:
            file_path: 文件路径

        Returns:
            数据流链路信息
        """
        import re

        chain = {
            'sources': [],
            'transforms': [],
            'sinks': [],
            'sanitizers': [],
            'chains': [],
            'risk_level': 'LOW'
        }

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            language = self._detect_language(file_path, content)

            source_keywords = self.DATA_FLOW_KEYWORDS['SOURCE'].get(language, []) + \
                             self.DATA_FLOW_KEYWORDS['SOURCE'].get('common', [])
            sink_keywords = self.DATA_FLOW_KEYWORDS['SINK'].get(language, []) + \
                           self.DATA_FLOW_KEYWORDS['SINK'].get('common', [])
            sanitizer_keywords = self.DATA_FLOW_KEYWORDS['SANITIZER'].get(language, []) + \
                               self.DATA_FLOW_KEYWORDS['SANITIZER'].get('common', [])

            for line_no, line in enumerate(lines, 1):
                line_lower = line.lower()

                for keyword in source_keywords:
                    if keyword.lower() in line_lower:
                        chain['sources'].append({
                            'line': line_no,
                            'code': line.strip(),
                            'keyword': keyword
                        })

                for keyword in sink_keywords:
                    if keyword.lower() in line_lower:
                        chain['sinks'].append({
                            'line': line_no,
                            'code': line.strip(),
                            'keyword': keyword
                        })

                for keyword in sanitizer_keywords:
                    if keyword.lower() in line_lower:
                        chain['sanitizers'].append({
                            'line': line_no,
                            'code': line.strip(),
                            'keyword': keyword
                        })

            for source in chain['sources']:
                current_chain = [source]
                current_line = source['line']

                for transform in chain['transforms']:
                    if transform['line'] > current_line:
                        current_chain.append(transform)
                        current_line = transform['line']

                for sink in chain['sinks']:
                    if sink['line'] > current_line:
                        current_chain.append(sink)
                        sink_line = sink['line']

                        has_sanitizer = any(
                            s['line'] > source['line'] and s['line'] < sink_line
                            for s in chain['sanitizers']
                        )

                        if not has_sanitizer:
                            chain['chains'].append({
                                'path': current_chain + [sink],
                                'risk_level': 'HIGH',
                                'has_sanitizer': False
                            })
                        else:
                            chain['chains'].append({
                                'path': current_chain + [sink],
                                'risk_level': 'MEDIUM',
                                'has_sanitizer': True
                            })
                        break

            if any(c['risk_level'] == 'HIGH' for c in chain['chains']):
                chain['risk_level'] = 'HIGH'
            elif any(c['risk_level'] == 'MEDIUM' for c in chain['chains']):
                chain['risk_level'] = 'MEDIUM'

        except Exception as e:
            logger.debug(f"数据流追踪失败 {file_path}: {e}")

        return chain

    def _detect_language(self, file_path: str, content: str) -> str:
        """检测文件语言类型

        Args:
            file_path: 文件路径
            content: 文件内容

        Returns:
            语言类型: 'java', 'python', 'javascript'
        """
        ext = Path(file_path).suffix.lower()
        if ext == '.java':
            return 'java'
        elif ext in ['.py', '.pyw']:
            return 'python'
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            return 'javascript'
        else:
            if 'def ' in content and ('import ' in content or 'from ' in content):
                return 'python'
            elif '{' in content and ('interface ' in content or 'class ' in content):
                if '@' in content or 'public ' in content:
                    return 'java'
                return 'javascript'
        return 'common'

    def _detect_sanitizers(self, file_path: str, line_start: int, line_end: int) -> List[Dict[str, Any]]:
        """检测两个行号之间的净化函数

        Args:
            file_path: 文件路径
            line_start: 起始行号
            line_end: 结束行号

        Returns:
            净化函数列表
        """
        import re

        sanitizers = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            language = self._detect_language(file_path, ''.join(lines))

            sanitizer_keywords = self.DATA_FLOW_KEYWORDS['SANITIZER'].get(language, []) + \
                               self.DATA_FLOW_KEYWORDS['SANITIZER'].get('common', [])

            for line_no in range(line_start - 1, min(line_end, len(lines))):
                line = lines[line_no]
                line_lower = line.lower()

                for keyword in sanitizer_keywords:
                    if keyword.lower() in line_lower:
                        sanitizers.append({
                            'line': line_no + 1,
                            'code': line.strip(),
                            'keyword': keyword
                        })

        except Exception:
            pass

        return sanitizers

    def build_sir(self, file_path: str) -> SIREntry:
        """构建文件的安全中间表示(SIR)

        Args:
            file_path: 文件路径

        Returns:
            SIREntry对象，包含文件的安全相关信息
        """
        import re

        sir = SIREntry(file_path=file_path)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for line_no, line in enumerate(lines, 1):
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith('//'):
                    continue

                for category, pattern_def in self.SIR_PATTERNS.items():
                    for pattern in pattern_def['patterns']:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            entry = {
                                'line': line_no,
                                'code': line_stripped,
                                'match': match.group(),
                                'category': category
                            }

                            if category == 'inputs':
                                sir.inputs.append(entry)
                            elif category == 'sinks':
                                sir.sinks.append(entry)
                            elif category == 'sanitizers':
                                sir.sanitizers.append(entry)
                            elif category == 'auth_checks':
                                sir.auth_checks.append(entry)

        except Exception as e:
            logger.debug(f"SIR构建失败 {file_path}: {e}")

        return sir

    def match_sir_patterns(self, sir: SIREntry) -> Dict[str, Any]:
        """匹配SIR中的SOURCE→SINK模式

        Args:
            sir: SIREntry对象

        Returns:
            匹配结果，包含危险流和信息
        """
        dangerous_flows = []
        has_auth_protection = len(sir.auth_checks) > 0

        for input_entry in sir.inputs:
            for sink_entry in sir.sinks:
                between_sanitizers = [
                    s for s in sir.sanitizers
                    if input_entry['line'] < s['line'] < sink_entry['line']
                ]

                if not between_sanitizers:
                    dangerous_flows.append({
                        'type': 'UNSANITIZED_INPUT_TO_SINK',
                        'input': input_entry,
                        'sink': sink_entry,
                        'sanitizers': between_sanitizers,
                        'risk_level': 'HIGH' if not has_auth_protection else 'MEDIUM'
                    })
                elif len(between_sanitizers) > 0:
                    dangerous_flows.append({
                        'type': 'PARTIALLY_SANITIZED_INPUT_TO_SINK',
                        'input': input_entry,
                        'sink': sink_entry,
                        'sanitizers': between_sanitizers,
                        'risk_level': 'LOW'
                    })

        return {
            'has_dangerous_flows': len(dangerous_flows) > 0,
            'dangerous_flows': dangerous_flows,
            'has_auth_protection': has_auth_protection,
            'summary': {
                'input_count': len(sir.inputs),
                'sink_count': len(sir.sinks),
                'sanitizer_count': len(sir.sanitizers),
                'auth_check_count': len(sir.auth_checks)
            }
        }

    def _extract_java_imports(self, content: str) -> List[str]:
        """提取 Java 文件中的导入语句

        Args:
            content: Java 文件内容

        Returns:
            导入语句列表
        """
        imports = []
        import_pattern = r'^import\s+([\w\.]+);'
        for match in re.finditer(import_pattern, content, re.MULTILINE):
            imports.append(f"import {match.group(1)};")
        return imports

    def _extract_java_function_calls(self, content: str) -> List[str]:
        """提取 Java 文件中的方法调用

        Args:
            content: Java 文件内容

        Returns:
            方法调用列表
        """
        function_calls = []
        call_pattern = r'(\w+)\s*\([^)]*\)\s*;'
        for match in re.finditer(call_pattern, content):
            func_name = match.group(1)
            if len(func_name) > 2 and not func_name[0].isupper():
                function_calls.append(func_name)
        return function_calls[:50]

    def _load_related_java_files(self, file_path: str) -> List[Dict]:
        """加载相关的 Java 文件"""
        related = []
        try:
            call_chain_files = self._analyze_call_chain(file_path)
            related.extend(call_chain_files)
            
            remaining = self.max_related_files - len(related)
            if remaining > 0:
                current_dir = Path(file_path).parent
                java_files = list(current_dir.glob('*.java'))
                
                existing_paths = {f['path'] for f in related}
                for java_file in java_files:
                    if java_file.name != Path(file_path).name and str(java_file) not in existing_paths:
                        if len(related) >= self.max_related_files:
                            break
                        related.append({
                            'path': str(java_file),
                            'content': self._read_file(str(java_file), max_size=524288)
                        })
        except Exception:
            pass
        return related
    
    def _analyze_call_chain(self, file_path: str) -> List[Dict]:
        """分析跨文件调用链
        
        Args:
            file_path: 当前文件路径
            
        Returns:
            调用链相关文件列表
        """
        related_files = []
        try:
            content = self._read_file(file_path)
            current_dir = Path(file_path).parent
            project_root = self._find_project_root(file_path)
            
            imports = self._extract_java_imports(content)
            
            class_references = re.findall(r'(?:class|interface|implements|extends)\s+(\w+)', content)
            
            method_calls = re.findall(r'(\w+)\s*\.\s*(\w+)\s*\(', content)
            
            autowired_fields = re.findall(r'@(?:Autowired|Inject|Resource)\s+(?:private|protected|public)\s+(\w+)\s+(\w+)', content)
            
            target_classes = set()
            for imp in imports:
                class_name = imp.split('.')[-1].replace(';', '').replace('*', '')
                if class_name and len(class_name) > 1:
                    target_classes.add(class_name)
            
            target_classes.update(class_references)
            
            for field_type, field_name in autowired_fields:
                target_classes.add(field_type)
            
            for obj, method in method_calls:
                if obj[0].isupper():
                    target_classes.add(obj)
            
            if project_root:
                for java_file in project_root.rglob('*.java'):
                    if len(related_files) >= self.max_related_files:
                        break
                    
                    if str(java_file) == file_path:
                        continue
                    
                    java_content = self._read_file(str(java_file), max_size=262144)
                    java_class_name = None
                    class_match = re.search(r'(?:public\s+)?(?:class|interface)\s+(\w+)', java_content)
                    if class_match:
                        java_class_name = class_match.group(1)
                    
                    if java_class_name and java_class_name in target_classes:
                        related_files.append({
                            'path': str(java_file),
                            'content': java_content
                        })
            
        except Exception:
            pass
        
        return related_files
    
    def _find_project_root(self, file_path: str) -> Optional[Path]:
        """查找项目根目录
        
        Args:
            file_path: 文件路径
            
        Returns:
            项目根目录路径
        """
        try:
            current = Path(file_path).parent
            for _ in range(10):
                if (current / 'pom.xml').exists() or (current / 'build.gradle').exists():
                    return current
                if current == current.parent:
                    break
                current = current.parent
        except Exception:
            pass
        return None
    
    def _track_data_flow(self, file_path: str) -> Dict[str, Any]:
        """追踪跨文件数据流
        
        Args:
            file_path: 当前文件路径
            
        Returns:
            数据流分析结果
        """
        data_flow = {
            'entry_points': [],
            'service_calls': [],
            'data_access': [],
            'flow_paths': []
        }
        
        try:
            ext = Path(file_path).suffix.lower()
            content = self._read_file(file_path, max_size=524288)
            
            if ext == '.java':
                data_flow = self._track_java_data_flow(content, file_path, data_flow)
            elif ext in ['.py', '.pyw']:
                data_flow = self._track_python_data_flow(content, file_path, data_flow)
                
        except Exception:
            pass
        
        return data_flow
    
    def _track_java_data_flow(self, content: str, file_path: str, data_flow: Dict) -> Dict:
        """追踪Java数据流"""
        mapping_methods = re.finditer(
            r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)(?:\("([^"]+)"\))?\s*\n\s*(?:public|private|protected)\s+\w+\s+(\w+)\s*\(([^)]*)\)',
            content
        )
        
        for match in mapping_methods:
            url = match.group(1) or ''
            method_name = match.group(2)
            params = match.group(3) or ''
            
            request_params = re.findall(r'@RequestParam(?:\("([^"]+)"\))?\s+\w+\s+(\w+)', params)
            path_variables = re.findall(r'@PathVariable(?:\("([^"]+)"\))?\s+\w+\s+(\w+)', params)
            request_body = re.findall(r'@RequestBody\s+(\w+)\s+(\w+)', params)
            
            data_flow['entry_points'].append({
                'method': method_name,
                'url': url,
                'request_params': [p[1] for p in request_params],
                'path_variables': [p[1] for p in path_variables],
                'request_body': request_body
            })
        
        service_calls = re.finditer(r'(\w+Service)\.(\w+)\s*\(', content)
        for match in service_calls:
            service_name = match.group(1)
            method_name = match.group(2)
            data_flow['service_calls'].append({
                'service': service_name,
                'method': method_name,
                'file': file_path
            })
        
        mapper_calls = re.finditer(r'(\w+Mapper|\w+Repository)\.(\w+)\s*\(', content)
        for match in mapper_calls:
            mapper_name = match.group(1)
            method_name = match.group(2)
            data_flow['data_access'].append({
                'mapper': mapper_name,
                'method': method_name,
                'file': file_path
            })
        
        for entry in data_flow['entry_points']:
            flow_path = {
                'entry': entry['method'],
                'url': entry['url'],
                'steps': []
            }
            
            for service_call in data_flow['service_calls']:
                flow_path['steps'].append({
                    'type': 'service_call',
                    'target': service_call['service'],
                    'method': service_call['method']
                })
            
            for data_access in data_flow['data_access']:
                flow_path['steps'].append({
                    'type': 'data_access',
                    'target': data_access['mapper'],
                    'method': data_access['method']
                })
            
            if flow_path['steps']:
                data_flow['flow_paths'].append(flow_path)
        
        return data_flow
    
    def _track_python_data_flow(self, content: str, file_path: str, data_flow: Dict) -> Dict:
        """追踪Python数据流"""
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    args = [arg.arg for arg in node.args.args if arg.arg != 'self']
                    
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            func_name = None
                            if isinstance(child.func, ast.Attribute):
                                func_name = child.func.attr
                                if isinstance(child.func.value, ast.Name):
                                    obj_name = child.func.value.id
                                    if 'service' in obj_name.lower():
                                        data_flow['service_calls'].append({
                                            'service': obj_name,
                                            'method': func_name,
                                            'file': file_path,
                                            'caller': node.name
                                        })
                                    elif 'mapper' in obj_name.lower() or 'repository' in obj_name.lower():
                                        data_flow['data_access'].append({
                                            'mapper': obj_name,
                                            'method': func_name,
                                            'file': file_path,
                                            'caller': node.name
                                        })
            
            for child in ast.walk(tree):
                if isinstance(child, ast.FunctionDef):
                    is_entry = False
                    for decorator in child.decorator_list:
                        if isinstance(decorator, ast.Name) and 'route' in decorator.id.lower():
                            is_entry = True
                        elif isinstance(decorator, ast.Attribute) and 'route' in decorator.attr.lower():
                            is_entry = True
                        elif isinstance(decorator, ast.Call):
                            if isinstance(decorator.func, ast.Attribute) and 'route' in decorator.func.attr.lower():
                                is_entry = True
                            elif isinstance(decorator.func, ast.Name) and 'route' in decorator.func.id.lower():
                                is_entry = True
                    
                    if is_entry:
                        args = [arg.arg for arg in child.args.args if arg.arg != 'self']
                        data_flow['entry_points'].append({
                            'function': child.name,
                            'args': args,
                            'line': child.lineno
                        })
                        
        except Exception:
            pass
        
        for entry in data_flow['entry_points']:
            flow_path = {
                'entry': entry['function'],
                'args': entry['args'],
                'steps': []
            }
            
            for service_call in data_flow['service_calls']:
                if service_call.get('caller') == entry['function']:
                    flow_path['steps'].append({
                        'type': 'service_call',
                        'target': service_call['service'],
                        'method': service_call['method']
                    })
            
            for data_access in data_flow['data_access']:
                if data_access.get('caller') == entry['function']:
                    flow_path['steps'].append({
                        'type': 'data_access',
                        'target': data_access['mapper'],
                        'method': data_access['method']
                    })
            
            if flow_path['steps']:
                data_flow['flow_paths'].append(flow_path)
        
        return data_flow

    def _scan_mybatis_sql_injection(self, xml_path: str, content: str) -> List[Dict]:
        """检测 MyBatis Mapper XML 中的 SQL 注入"""
        findings = []

        dangerous_patterns = [
            (r'\$\{[^}]+\}', 'DOLLAR_BRACE_INTERPOLATION', 'CRITICAL'),
            (r'\$\{.*sqlSegment.*\}', 'MYBATIS_PLUS_SQL_SEGMENT', 'CRITICAL'),
            (r'\$\{.*ew\.sqlSegment.*\}', 'MYBATIS_PLUS_EW_SQL_SEGMENT', 'CRITICAL'),
            (r'\$\{.*propertyName.*\}', 'DYNAMIC_PROPERTY_NAME', 'HIGH'),
        ]

        for pattern, name, severity in dangerous_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'type': 'SQL_INJECTION',
                    'subtype': name,
                    'severity': severity,
                    'file': xml_path,
                    'pattern': match.group(),
                    'line': content[:match.start()].count('\n') + 1,
                })

        return findings

    def _scan_config_security(self, file_path: str, content: str) -> List[Dict]:
        """检测配置安全问题"""
        findings = []

        security_patterns = [
            (r'nacos\.core\.auth\.enabled\s*=\s*false', 'NACOS_AUTH_BYPASS', 'CRITICAL'),
            (r'spring\.security\.enabled\s*=\s*false', 'SPRING_SECURITY_DISABLED', 'HIGH'),
            (r'password\s*=\s*[\'"]?(\w+)', 'HARDCODED_PASSWORD', 'HIGH'),
            (r'secret\s*=\s*[\'"](.{10,})', 'JWT_SECRET_EXPOSED', 'CRITICAL'),
            (r'auth\.enabled\s*=\s*false', 'AUTH_BYPASS', 'CRITICAL'),
            (r' spring\.security\.user\.password', 'SPRING_SECURITY_PASSWORD', 'HIGH'),
        ]

        for pattern, name, severity in security_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    'type': 'INSECURE_CONFIG',
                    'subtype': name,
                    'severity': severity,
                    'file': file_path,
                })

        return findings

    def _build_sql_context(self, file_path: str) -> Dict[str, Any]:
        """构建 SQL 文件上下文

        检测 SQL 注入风险、敏感数据暴露等安全问题。
        """
        content = self._read_file(file_path)
        findings = []

        sql_injection_patterns = [
            (r"(?i)(concat\s*\(|group_concat\s*\()", 'DYNAMIC_SQL_CONCAT', 'HIGH'),
            (r"(?i)(prepare\s+.*@|execute\s+immediate)", 'DYNAMIC_SQL_EXECUTE', 'HIGH'),
            (r"(?i)(create|alter|drop)\s+(user|role|grant|privilege)", 'DDL_PRIVILEGE_CHANGE', 'MEDIUM'),
            (r"(?i)(password|secret|token|api_key)\s*=\s*['\"]", 'HARDCODED_CREDENTIALS', 'CRITICAL'),
            (r"(?i)(grant\s+all\s+privileges|grant\s+.*\*)", 'EXCESSIVE_PRIVILEGES', 'HIGH'),
            (r"(?i)(insert\s+into.*user|insert\s+into.*account)", 'SENSITIVE_DATA_INSERT', 'MEDIUM'),
        ]

        for pattern, name, severity in sql_injection_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'type': 'SQL_SECURITY',
                    'subtype': name,
                    'severity': severity,
                    'file': file_path,
                    'pattern': match.group(),
                    'line': content[:match.start()].count('\n') + 1,
                })

        return {
            'current_file': file_path,
            'file_content': content,
            'security_findings': findings,
            'related_files': [],
            'file_type': 'sql',
            'project_context': self._build_project_context(file_path)
        }

    def _build_template_context(self, file_path: str) -> Dict[str, Any]:
        """构建模板文件上下文

        检测 XSS、模板注入等安全问题。
        """
        content = self._read_file(file_path)
        findings = []

        ext = Path(file_path).suffix.lower()

        xss_patterns = [
            (r"(?i)innerHTML\s*=", 'INNERHTML_ASSIGNMENT', 'HIGH'),
            (r"(?i)document\.write\s*\(", 'DOCUMENT_WRITE', 'HIGH'),
            (r"(?i)v-on:click\s*=\s*['\"]", 'INLINE_EVENT_HANDLER', 'MEDIUM'),
            (r"(?i)@click\s*=\s*['\"]", 'INLINE_EVENT_HANDLER', 'MEDIUM'),
            (r"(?i)v-html\s*=\s*['\"]", 'VHTML_USAGE', 'HIGH'),
            (r"(?i)v-bind:html\s*=\s*['\"]", 'VHTML_USAGE', 'HIGH'),
            (r"(?i)\{\{[^}]*\|raw\}\}", 'RAW_OUTPUT', 'HIGH'),
            (r"(?i)\{%\s*autoescape\s+false\s*%\}", 'AUTOESCAPE_DISABLED', 'HIGH'),
        ]

        template_injection_patterns = [
            (r"(?i)\{\{[^}]*request\.", 'TEMPLATE_REQUEST_ACCESS', 'HIGH'),
            (r"(?i)\{\{[^}]*config\.", 'TEMPLATE_CONFIG_ACCESS', 'HIGH'),
            (r"(?i)\{%\s*include\s+.*request\.", 'TEMPLATE_INCLUDE_INJECTION', 'CRITICAL'),
        ]

        all_patterns = xss_patterns + template_injection_patterns

        for pattern, name, severity in all_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'type': 'TEMPLATE_SECURITY',
                    'subtype': name,
                    'severity': severity,
                    'file': file_path,
                    'pattern': match.group(),
                    'line': content[:match.start()].count('\n') + 1,
                })

        return {
            'current_file': file_path,
            'file_content': content,
            'security_findings': findings,
            'related_files': [],
            'file_type': 'template',
            'template_engine': self._detect_template_engine(ext),
            'project_context': self._build_project_context(file_path)
        }

    def _build_style_context(self, file_path: str) -> Dict[str, Any]:
        """构建样式文件上下文

        检测 CSS 注入、敏感信息泄露等安全问题。
        """
        content = self._read_file(file_path)
        findings = []

        css_security_patterns = [
            (r"(?i)url\s*\(\s*['\"]?javascript:", 'CSS_JAVASCRIPT_URL', 'HIGH'),
            (r"(?i)expression\s*\(", 'CSS_EXPRESSION', 'HIGH'),
            (r"(?i)-moz-binding\s*:\s*url", 'CSS_MOZ_BINDING', 'HIGH'),
            (r"(?i)(password|secret|api[_-]?key|token)\s*:\s*['\"]", 'CSS_CREDENTIAL_LEAK', 'CRITICAL'),
            (r"(?i)@import\s+.*http", 'CSS_EXTERNAL_IMPORT', 'LOW'),
        ]

        for pattern, name, severity in css_security_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'type': 'CSS_SECURITY',
                    'subtype': name,
                    'severity': severity,
                    'file': file_path,
                    'pattern': match.group(),
                    'line': content[:match.start()].count('\n') + 1,
                })

        return {
            'current_file': file_path,
            'file_content': content,
            'security_findings': findings,
            'related_files': [],
            'file_type': 'style',
            'project_context': self._build_project_context(file_path)
        }

    def _build_infra_context(self, file_path: str) -> Dict[str, Any]:
        """构建基础设施文件上下文

        检测 Dockerfile、Terraform 等配置文件的安全问题。
        """
        content = self._read_file(file_path)
        findings = []

        ext = Path(file_path).suffix.lower()
        file_name = Path(file_path).name.lower()

        if file_name.startswith('dockerfile'):
            findings.extend(self._scan_dockerfile_security(file_path, content))
        elif ext == '.tf':
            findings.extend(self._scan_terraform_security(file_path, content))

        return {
            'current_file': file_path,
            'file_content': content,
            'security_findings': findings,
            'related_files': [],
            'file_type': 'infrastructure',
            'infra_type': 'dockerfile' if file_name.startswith('dockerfile') else 'terraform',
            'project_context': self._build_project_context(file_path)
        }

    def _scan_dockerfile_security(self, file_path: str, content: str) -> List[Dict]:
        """检测 Dockerfile 安全问题"""
        findings = []

        dockerfile_patterns = [
            (r"(?i)FROM\s+(?!alpine|distroless|scratch|ubuntu:)[^\n]*:latest", 'USE_LATEST_TAG', 'MEDIUM'),
            (r"(?i)ADD\s+https?://", 'ADD_REMOTE_URL', 'MEDIUM'),
            (r"(?i)ENV\s+.*\b(password|secret|key|token)\b", 'ENV_SECRET', 'CRITICAL'),
            (r"(?i)EXPOSE\s+.*22\b", 'EXPOSE_SSH', 'HIGH'),
            (r"(?i)USER\s+root", 'RUN_AS_ROOT', 'HIGH'),
        ]

        for pattern, name, severity in dockerfile_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'type': 'DOCKER_SECURITY',
                    'subtype': name,
                    'severity': severity,
                    'file': file_path,
                    'pattern': match.group(),
                    'line': content[:match.start()].count('\n') + 1,
                })

        return findings

    def _scan_terraform_security(self, file_path: str, content: str) -> List[Dict]:
        """检测 Terraform 安全问题"""
        findings = []

        terraform_patterns = [
            (r"(?i)default\s*=\s*['\"]", 'DEFAULT_CREDENTIAL', 'HIGH'),
            (r"(?i)ingress\s*\{[^}]*cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\]", 'OPEN_CIDR_INGRESS', 'CRITICAL'),
            (r"(?i)public_access\s*=\s*true", 'PUBLIC_ACCESS_ENABLED', 'HIGH'),
            (r"(?i)encrypt\s*=\s*false", 'ENCRYPTION_DISABLED', 'HIGH'),
            (r"(?i)logging\s*=\s*false", 'LOGGING_DISABLED', 'MEDIUM'),
        ]

        for pattern, name, severity in terraform_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'type': 'TERRAFORM_SECURITY',
                    'subtype': name,
                    'severity': severity,
                    'file': file_path,
                    'pattern': match.group(),
                    'line': content[:match.start()].count('\n') + 1,
                })

        return findings

    def _detect_template_engine(self, ext: str) -> str:
        """检测模板引擎类型"""
        engine_map = {
            '.html': 'html',
            '.jsp': 'jsp',
            '.thtml': 'thymeleaf',
            '.ejs': 'ejs',
            '.pug': 'pug',
            '.vue': 'vue',
            '.svelte': 'svelte',
        }
        return engine_map.get(ext, 'unknown')

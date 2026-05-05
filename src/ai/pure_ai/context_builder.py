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
    
    def __init__(self, config: Optional[Any] = None, priority_parser=None):
        """初始化上下文构建器
        
        Args:
            config: 配置参数
            priority_parser: 自定义优先级解析器实例，用于相关文件选择
        """
        self.config = config
        self.priority_parser = priority_parser
        # 尝试从配置中获取max_related_files，如果不存在则使用默认值3
        if hasattr(config, 'get'):
            # 配置是字典
            self.max_related_files = config.get('max_related_files', 3)
        else:
            # 配置是对象
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

        if ext == '.java':
            return self._build_java_context(file_path)
        elif ext in ['.xml', '.yml', '.yaml', '.properties']:
            return self._build_config_context(file_path)
        else:
            return self._build_generic_context(file_path)
    
    def _read_file(self, file_path: str, max_size: int = 1048576) -> str:
        """读取文件内容

        Args:
            file_path: 文件路径
            max_size: 最大读取大小（字节），默认1MB

        Returns:
            文件内容
        """
        try:
            # 检查文件大小
            file_size = os.path.getsize(file_path)
            print(f"[DEBUG] 读取文件: {file_path}, 大小: {file_size} 字节")
            
            if file_size > max_size:
                # 文件过大，只读取前max_size字节
                print(f"[DEBUG] 文件过大，截断为 {max_size} 字节")
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read(max_size)
                return content + "\n... [文件过大，已截断]"
            else:
                # 文件大小正常，读取全部内容
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                print(f"[DEBUG] 成功读取文件，内容长度: {len(content)} 字符")
                return content
        except Exception as e:
            print(f"[DEBUG] 读取文件失败: {file_path}, 错误: {e}")
            return ''
    
    def _extract_imports(self, file_path: str) -> List[str]:
        """提取文件中的导入语句
        
        Args:
            file_path: 文件路径
            
        Returns:
            导入语句列表
        """
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
        context = {
            'current_file': file_path,
            'file_content': self._read_file(file_path),
            'imports': [],
            'related_files': [],
            'function_calls': [],
            'file_structure': {},
            'file_type': 'python',
            'data_flow': {}
        }

        context['imports'] = self._extract_imports(file_path)
        context['function_calls'] = self._extract_function_calls(file_path)
        context['related_files'] = self._load_related_files(file_path)
        context['file_structure'] = self._extract_file_structure(file_path)
        context['data_flow'] = self._track_data_flow(file_path)

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
            'data_flow': self._track_data_flow(file_path)
        }

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
            'file_type': 'config'
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

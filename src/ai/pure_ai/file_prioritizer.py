import asyncio
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

from src.ai.client import get_model_manager, AIProvider
from src.ai.pure_ai.prompt_templates import PromptTemplates
from src.ai.pure_ai.cache import CacheManager
from src.ai.models import AIRequest

class FilePrioritizer:
    """文件优先级分析器
    
    根据文件相对路径、文件名称、文件类型和内容判断其重要性和出现问题的概率
    """
    
    def __init__(self):
        """初始化文件优先级分析器"""
        # 目录重要性权重
        self.directory_weights = {
            'src': 0.8,
            'lib': 0.7,
            'utils': 0.6,
            'core': 0.9,
            'cli': 0.7,
            'ai': 0.8,
            'api': 0.9,
            'auth': 0.95,
            'security': 0.95,
            'config': 0.85,
            'database': 0.85,
            'mapper': 0.92,
            'models': 0.75,
            'routes': 0.7,
            'services': 0.75,
            'controllers': 0.7,
            'middleware': 0.8,
            'handlers': 0.7,
            'backend': 0.85,
            'frontend': 0.65,
            'mobile': 0.7,
            'desktop': 0.65,
            'server': 0.9,
            'client': 0.65,
            'admin': 0.9,
            'user': 0.7,
            'public': 0.5,
            'private': 0.8,
            'external': 0.6,
            'internal': 0.8,
            'resources': 0.7,
            'mybatis': 0.92,
            'ibatis': 0.92
        }
        
        # 文件名重要性关键词
        self.file_name_keywords = {
            'api': 0.8,
            'auth': 0.95,
            'key': 0.95,
            'token': 0.9,
            'password': 0.95,
            'security': 0.95,
            'config': 0.85,
            'database': 0.8,
            'secret': 0.95,
            'credential': 0.95,
            'login': 0.85,
            'register': 0.8,
            'user': 0.75,
            'admin': 0.85,
            'permission': 0.85,
            'role': 0.8,
            'session': 0.8,
            'jwt': 0.9,
            'oauth': 0.85,
            'encryption': 0.9,
            'decryption': 0.9,
            'hash': 0.85,
            'validate': 0.8,
            'sanitize': 0.8,
            'filter': 0.75,
            'authz': 0.95,
            'authn': 0.95,
            'access': 0.85,
            'privilege': 0.85,
            'csrf': 0.9,
            'xss': 0.9,
            'sqli': 0.9,
            'sql': 0.9,
            'mapper': 0.85,
            'query': 0.85,
            'statement': 0.85,
            'jdbc': 0.9,
            'mybatis': 0.9,
            'hibernate': 0.9,
            'orm': 0.8,
            'injection': 0.9,
            'rce': 0.95,
            'lfi': 0.9,
            'rfi': 0.9,
            'xxe': 0.9,
            'ssrf': 0.9,
            'cors': 0.85,
            'csp': 0.85,
            'headers': 0.8,
            'cookies': 0.85,
            'session': 0.85,
            'token': 0.9,
            'jwt': 0.9,
            'oauth': 0.85,
            'openid': 0.85,
            'saml': 0.85,
            'ldap': 0.85,
            'radius': 0.8,
            'kerberos': 0.85,
            'password': 0.95,
            'hash': 0.85,
            'salt': 0.85,
            'encryption': 0.9,
            'decryption': 0.9,
            'key': 0.95,
            'cert': 0.9,
            'ssl': 0.9,
            'tls': 0.9,
            'https': 0.85,
            'network': 0.8,
            'socket': 0.8,
            'http': 0.8,
            'server': 0.85,
            'client': 0.75,
            'proxy': 0.8,
            'firewall': 0.85,
            'waf': 0.85,
            'ids': 0.85,
            'ips': 0.85,
            'vpn': 0.85,
            'api': 0.85,
            'graphql': 0.85,
            'rest': 0.8,
            'soap': 0.8,
            'grpc': 0.8,
            'microservice': 0.85,
            'container': 0.8,
            'docker': 0.8,
            'k8s': 0.8,
            'kubernetes': 0.8,
            'cloud': 0.8,
            'aws': 0.85,
            'azure': 0.85,
            'gcp': 0.85,
            'iam': 0.95,
            'policy': 0.85,
            'rule': 0.8,
            'audit': 0.85,
            'log': 0.8,
            'monitor': 0.8,
            'alert': 0.8,
            'incident': 0.85,
            'forensic': 0.85,
            'compliance': 0.85,
            'gdpr': 0.9,
            'hipaa': 0.9,
            'pci': 0.9,
            'iso': 0.85,
            'nist': 0.85,
            'cve': 0.9,
            'vulnerability': 0.9,
            'exploit': 0.9,
            'patch': 0.85,
            'update': 0.8,
            'security': 0.95,
            'safe': 0.8,
            'risk': 0.85,
            'threat': 0.85,
            'attack': 0.85,
            'defense': 0.85,
            'hardening': 0.85,
            'baseline': 0.8,
            'standard': 0.8,
            'best': 0.8,
            'practice': 0.8
        }
        
        # 文件类型问题概率权重
        self.file_type_weights = {
            '.py': 0.85,
            '.js': 0.8,
            '.ts': 0.75,
            '.jsx': 0.7,
            '.tsx': 0.65,
            '.php': 0.8,
            '.java': 0.7,
            '.c': 0.65,
            '.cpp': 0.65,
            '.cs': 0.7,
            '.go': 0.6,
            '.rb': 0.75,
            '.pl': 0.6,
            '.sh': 0.8,
            '.bat': 0.7,
            '.ps1': 0.7,
            '.yml': 0.6,
            '.yaml': 0.6,
            '.json': 0.55,
            '.xml': 0.75,
            '.ini': 0.5,
            '.env': 0.95,
            '.config': 0.7,
            '.php5': 0.8,
            '.php7': 0.8,
            '.pyw': 0.85,
            '.pyx': 0.85,
            '.pyd': 0.85,
            '.jsm': 0.8,
            '.mjs': 0.8,
            '.tsx': 0.65,
            '.jsx': 0.7,
            '.vue': 0.7,
            '.svelte': 0.65,
            '.html': 0.6,
            '.htm': 0.6,
            '.css': 0.55,
            '.scss': 0.55,
            '.less': 0.55,
            '.styl': 0.55,
            '.md': 0.4,
            '.rst': 0.4,
            '.txt': 0.35,
            '.log': 0.4,
            '.sql': 0.85,
            '.sqlite': 0.75,
            '.db': 0.75,
            '.mongo': 0.75,
            '.redis': 0.7,
            '.memcached': 0.7,
            '.conf': 0.7,
            '.cfg': 0.7,
            '.settings': 0.7,
            '.properties': 0.65,
            '.gradle': 0.7,
            '.maven': 0.7,
            '.pom': 0.7,
            '.gradle': 0.7,
            '.npmrc': 0.8,
            '.yarnrc': 0.8,
            '.pnpmrc': 0.8,
            '.gitignore': 0.3,
            '.dockerignore': 0.3,
            '.env.local': 0.95,
            '.env.development': 0.95,
            '.env.production': 0.95,
            '.env.test': 0.95,
            '.key': 0.95,
            '.pem': 0.95,
            '.crt': 0.95,
            '.cer': 0.95,
            '.pfx': 0.95,
            '.p12': 0.95,
            '.ssh': 0.95,
            '.private': 0.95,
            '.secret': 0.95,
            '.token': 0.95,
            '.credential': 0.95,
            '.auth': 0.95,
            '.pass': 0.95,
            '.password': 0.95,
            '.hash': 0.9,
            '.salt': 0.9,
            '.enc': 0.9,
            '.dec': 0.9,
            '.crypt': 0.9,
            '.secure': 0.9,
            '.ssl': 0.9,
            '.tls': 0.9,
            '.https': 0.85,
            '.http': 0.8,
            '.api': 0.85,
            '.rest': 0.8,
            '.graphql': 0.85,
            '.grpc': 0.8,
            '.soap': 0.8,
            '.wsdl': 0.75,
            '.raml': 0.75,
            '.oas': 0.75,
            '.swagger': 0.75,
            '.openapi': 0.75
        }
        
        # 安全问题模式
        self.security_patterns = {
            'sql_injection': ['execute', 'query', 'raw', 'sql', 'cursor', 'db.execute'],
            'xss': ['innerHTML', 'outerHTML', 'document.write', 'eval', 'setInnerHTML', '<script', 'javascript:', 'onerror=', 'onclick=', 'onload=', 'v-html', 'ng-bind-html', 'dangerouslySetInnerHTML', 'inner_text', 'html_safe'],
            'command_injection': ['exec', 'system', 'subprocess', 'shell_exec', 'passthru'],
            'csrf': ['csrf', 'token', 'session', 'cookie'],
            'authentication': ['password', 'login', 'auth', 'authenticate'],
            'authorization': ['permission', 'role', 'access', 'privilege'],
            'sensitive_data': ['password', 'secret', 'key', 'token', 'credential'],
            'file_handling': ['file_get_contents', 'fopen', 'fwrite', 'file_put_contents'],
            'network': ['socket', 'http', 'request', 'response', 'fetch'],
            'crypto': ['encrypt', 'decrypt', 'hash', 'md5', 'sha1']
        }
        
        # OWASP TOP10 关键词权重
        self.OWASP_TOP10_KEYWORDS = {
            'A01': {
                'name': 'Broken Access Control',
                'keywords': ['auth', 'access', 'permission', 'role', 'admin', 'privilege', 'authorize', 'authz', 'authn', 'access_control', 'authorization']
            },
            'A02': {
                'name': 'Cryptographic Failures',
                'keywords': ['crypt', 'encrypt', 'hash', 'ssl', 'tls', 'certificate', 'key', 'decrypt', 'cipher', 'signature', 'cert', 'pem', 'keytool']
            },
            'A03': {
                'name': 'Injection',
                'keywords': ['sql', 'jdbc', 'mybatis', 'hibernate', 'query', 'execute', 'raw', 'input', 'validate', 'sanitize', 'sql_injection', 'nosql', 'orm', 'mapper', 'ibatis', 'select', 'insert', 'update', 'delete', 'xss', 'script', 'html', 'escape', 'template', 'render', 'request.body', 'request.param', 'getInput', 'innerHTML', 'outerHTML', 'document.write']
            },
            'A04': {
                'name': 'Insecure Design',
                'keywords': ['business', 'logic', 'workflow', 'process', 'race_condition', 'concurrency', 'state_machine']
            },
            'A05': {
                'name': 'Security Misconfiguration',
                'keywords': ['config', 'settings', 'environment', 'default', 'misconfiguration', 'hardening', 'baseline']
            },
            'A06': {
                'name': 'Vulnerable Components',
                'keywords': ['dependency', 'library', 'version', 'cve', 'vulnerability', 'exploit', 'patch', 'outdated']
            },
            'A07': {
                'name': 'Authentication Failures',
                'keywords': ['login', 'password', 'token', 'session', 'jwt', 'oauth', 'saml', 'openid', 'ldap', 'radius', 'kerberos', '2fa', 'mfa', 'html', 'escape', 'sanitize']
            },
            'A08': {
                'name': 'Software Integrity Failures',
                'keywords': ['signature', 'verify', 'checksum', 'hash', 'integrity', 'tamper', 'anti_tamper']
            },
            'A09': {
                'name': 'Security Logging Failures',
                'keywords': ['log', 'audit', 'monitor', 'alert', 'logging', 'forensic', 'incident', 'trace']
            },
            'A10': {
                'name': 'SSRF',
                'keywords': ['request', 'url', 'fetch', 'redirect', 'forward', 'ssrf', 'url_redirect', 'open_redirect']
            }
        }

        # Token流分析关键词定义（语言无关）
        TOKEN_FLOW_PATTERNS = {
            'source': {
                'keywords': [
                    'request', 'input', 'param', 'query', 'body', 'header', 'cookie',
                    'getParameter', 'getQuery', 'getBody', 'request.GET', 'request.POST',
                    'request.body', 'args', 'kwargs', 'argv', 'stdin',
                    'user_input', 'userdata', 'form', 'upload'
                ],
                'severity': 0.7
            },
            'sink': {
                'keywords': [
                    'exec', 'eval', 'execute', 'query', 'sql', 'command', 'system',
                    'shell', 'bash', 'os.system', 'os.popen', 'subprocess',
                    'cursor.execute', 'statement.execute', 'Connection.execute',
                    'innerHTML', 'outerHTML', 'document.write', 'eval', 'setInnerHTML',
                    'Runtime.exec', 'ProcessBuilder', 'ProcessImpl',
                    'os_command', 'system_exec', 'shell_exec', 'passthru'
                ],
                'severity': 0.9
            },
            'transform': {
                'keywords': [
                    'concat', 'format', 'sprintf', 'stringify', 'join',
                    'merge', 'combine', 'append', 'interpolate'
                ],
                'severity': 0.3
            },
            'sanitizer': {
                'keywords': [
                    'escape', 'sanitize', 'validate', 'filter', 'clean',
                    'htmlspecialchars', 'strip_tags', 'mysqli_real_escape_string',
                    'ParameterizedQuery', 'PreparedStatement', 'bindParam',
                    'param', 'placeholder', 'validateInput', 'checkInput'
                ],
                'severity': -0.5
            }
        }

        DANGEROUS_FLOW_PATTERNS = [
            ('source', 'transform', 'sink'),
            ('source', 'sink'),
            ('source', 'transform', 'transform', 'sink'),
        ]
        
        # 权重系数
        self.owasp_weight = 0.3
        self.importance_weight = 0.3  # 文件重要性权重
        self.problem_probability_weight = 0.7  # 出现问题的可能性权重
        self.content_weight = 0.2  # 内容分析权重
        
        # AI相关初始化
        self.ai_client = None
        self.model_manager = None
        self.enabled = False
        self.ai_initialized = False
        self.prompt_templates = PromptTemplates()
        self.cache_manager = CacheManager()  # 缓存管理器
    
    async def _ensure_ai_initialized(self):
        """确保AI客户端已初始化"""
        if self.ai_initialized:
            return
        
        try:
            from src.core.config import get_config
            config = get_config()
            
            # 异步获取模型管理器
            from src.ai.client import get_model_manager
            self.model_manager = await get_model_manager(config)
            
            # 获取AI客户端
            from src.ai.client import AIProvider
            provider = AIProvider.DEEPSEEK  # 使用deepseek-reasoner模型
            self.ai_client = self.model_manager.get_client(provider)
            
            if not self.ai_client:
                # 尝试获取默认客户端
                self.ai_client = self.model_manager.get_default_client()
                
            self.enabled = self.ai_client is not None
            self.ai_initialized = True
            if self.enabled:
                print("[DEBUG] AI文件优先级评估器初始化成功")
            else:
                print("[DEBUG] AI文件优先级评估器初始化失败：无法获取AI客户端")
        except Exception as e:
            print(f"[DEBUG] AI初始化失败: {e}")
            self.enabled = False
            self.ai_initialized = True
    
    async def _async_initialize_ai(self):
        """异步初始化AI客户端"""
        try:
            from src.core.config import get_config
            config = get_config()
            
            # 初始化模型管理器
            self.model_manager = get_model_manager()
            await self.model_manager.initialize(config)
            
            # 获取AI客户端
            provider = AIProvider.DEEPSEEK  # 使用deepseek-reasoner模型
            self.ai_client = self.model_manager.get_client(provider)
            
            if not self.ai_client:
                # 尝试获取默认客户端
                self.ai_client = self.model_manager.get_default_client()
                
        except Exception as e:
            print(f"[DEBUG] AI客户端初始化失败: {e}")
    
    async def _generate_with_retry(self, prompt: str, max_retries: int = 2, timeout: float = 10.0) -> str:
        """带重试的AI生成

        Args:
            prompt: 提示词
            max_retries: 最大重试次数
            timeout: 超时时间（秒）

        Returns:
            生成的响应
        """
        import asyncio

        for i in range(max_retries):
            try:
                if not self.ai_client:
                    raise Exception("AI客户端未初始化")

                request = AIRequest(
                    prompt=prompt,
                    model="deepseek-reasoner",
                    temperature=0.0,
                    max_tokens=256
                )

                response = await asyncio.wait_for(
                    self.ai_client.generate(request),
                    timeout=timeout
                )

                if hasattr(response, 'content'):
                    return response.content
                else:
                    return str(response)

            except asyncio.TimeoutError:
                if i == max_retries - 1:
                    print("[DEBUG] AI生成超时")
                    raise
                continue
            except Exception as e:
                if i == max_retries - 1:
                    print(f"[DEBUG] AI生成最终失败: {e}")
                    raise
                continue
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """解析JSON响应
        
        Args:
            response: 响应字符串
            
        Returns:
            解析后的JSON对象
        """
        try:
            # 清理响应字符串
            cleaned_response = response.strip()
            
            # 首先尝试直接解析
            try:
                return json.loads(cleaned_response)
            except json.JSONDecodeError:
                pass
            
            # 提取JSON部分（处理markdown代码块）
            import re
            # 尝试匹配 ```json ... ``` 格式
            json_match = re.search(r'```json\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
            
            # 尝试匹配 ``` ... ``` 格式
            json_match = re.search(r'```\s*([\s\S]*?)```', cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
            
            # 尝试匹配 { ... } 格式
            json_match = re.search(r'\{[\s\S]*\}', cleaned_response)
            if json_match:
                json_str = json_match.group(0)
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
            
            # 尝试更宽松的JSON提取和修复
            # 1. 提取可能的JSON部分
            possible_json = cleaned_response
            # 找到第一个 { 和最后一个 }
            first_brace = possible_json.find('{')
            last_brace = possible_json.rfind('}')
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                json_str = possible_json[first_brace:last_brace+1]
                # 尝试修复常见的JSON问题
                # 1. 修复未转义的引号
                json_str = re.sub(r'(?<!\\)\'', '"', json_str)
                # 2. 修复属性名缺少引号
                json_str = re.sub(r'(\w+)\s*:', '"\1":', json_str)
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
            
            # 如果没有找到JSON，返回原始响应
            return {'raw_response': response}
        except Exception as e:
            print(f"[DEBUG] JSON解析失败: {e}")
            return {'raw_response': response, 'error': str(e)}
    
    async def calculate_priority_ai(self, file_path: str, fast_mode: bool = True) -> Dict[str, Any]:
        """使用AI计算文件优先级

        Args:
            file_path: 文件路径
            fast_mode: 是否使用快速模式（默认True，快速分析）

        Returns:
            包含AI优先级评估结果的字典
        """
        try:
            await self._ensure_ai_initialized()

            if not self.enabled or not self.ai_client:
                return {
                    'priority_score': 0.5,
                    'priority_level': 'medium',
                    'analysis_summary': 'AI客户端未初始化，使用默认优先级',
                    'key_risk_factors': [],
                    'security_sensitivity': 'medium',
                    'code_complexity': 'medium',
                    'error': 'AI客户端未初始化'
                }

            cache_key = f"priority_ai_{file_path}_{fast_mode}"
            cached_result = self.cache_manager.get(cache_key)
            if cached_result:
                print(f"[DEBUG] 使用缓存的AI优先级评估结果: {file_path}")
                return cached_result

            path = Path(file_path)

            if fast_mode:
                file_preview = self._get_file_preview(path)
                project_root = path.parent
                while project_root.parent != project_root:
                    if (project_root / 'src').exists() or (project_root / 'package.json').exists() or (project_root / 'requirements.txt').exists():
                        break
                    project_root = project_root.parent
                project_structure = self._get_project_structure_summary(project_root)

                prompt = f"""快速评估文件安全优先级：

文件路径: {file_path}
文件预览（前10行）:
{file_preview if file_preview else '(无法读取)'}

项目结构: {project_structure}

返回JSON格式：
{{"priority_score":0-1数字,"priority_level":"high"|"medium"|"low","analysis_summary":"简短分析"}}"""

                timeout = 2.0
            else:
                prompt = f"评估文件路径 '{file_path}' 的安全优先级。\n\n返回：{{\"priority_score\":0-1数字,\"priority_level\":\"high\"|\"medium\"|\"low\",\"analysis_summary\":\"分析\"}}"
                timeout = 10.0

            response = await self._generate_with_retry(prompt, timeout=timeout)

            result = self._parse_json_response(response)

            priority_score = result.get('priority_score', 0.5)
            priority_level = result.get('priority_level', 'medium')
            analysis_summary = result.get('analysis_summary', 'AI评估')

            final_result = {
                'file_path': file_path,
                'priority_score': priority_score,
                'priority_level': priority_level,
                'analysis_summary': analysis_summary,
                'key_risk_factors': [],
                'security_sensitivity': 'medium',
                'code_complexity': 'medium',
                'impact_scope': 'local',
                'fast_mode': fast_mode,
                'raw_result': result
            }

            self.cache_manager.set(cache_key, final_result)

            return final_result

        except Exception as e:
            print(f"[DEBUG] AI优先级评估失败: {e}")
            return {
                'file_path': file_path,
                'priority_score': 0.5,
                'priority_level': 'medium',
                'analysis_summary': 'AI评估失败，使用默认值',
                'key_risk_factors': [],
                'security_sensitivity': 'medium',
                'code_complexity': 'medium',
                'impact_scope': 'local',
                'error': str(e)
            }
    
    async def calculate_priority(self, file_path: str) -> Dict[str, Any]:
        """计算文件优先级（混合方法）

        Args:
            file_path: 文件路径

        Returns:
            包含优先级分数和详细分析的字典
        """
        path = Path(file_path)

        # 1. 计算传统规则的优先级
        importance_score = self._calculate_importance(path)
        problem_probability = self._calculate_problem_probability(path)
        content_score = self._calculate_content_score(path)
        owasp_score = self._calculate_owasp_score(path)
        weights = self._get_dynamic_weights(path, content_score)

        traditional_score = (
            importance_score * weights['importance'] +
            problem_probability * weights['problem_probability'] +
            content_score * weights['content']
        )
        traditional_score = self._apply_nonlinear_adjustment(traditional_score, content_score)

        # 2. 尝试使用AI评估
        ai_score = 0.5
        ai_analysis = {}
        try:
            ai_result = await self.calculate_priority_ai(file_path)
            ai_score = ai_result.get('priority_score', 0.5)
            ai_analysis = ai_result
        except Exception as e:
            print(f"[DEBUG] AI评估失败，使用传统规则: {e}")

        # 3. 混合计算（AI权重为0.5，传统规则权重为0.3，OWASP权重为0.2）
        final_score = traditional_score * 0.3 + ai_score * 0.5 + owasp_score * 0.2

        # 4. 确保分数在0-1范围内
        final_score = max(0.0, min(1.0, final_score))

        return {
            'file_path': file_path,
            'priority_score': round(final_score, 3),
            'importance_score': round(importance_score, 3),
            'problem_probability': round(problem_probability, 3),
            'content_score': round(content_score, 3),
            'owasp_score': round(owasp_score, 3),
            'ai_score': round(ai_score, 3),
            'traditional_score': round(traditional_score, 3),
            'analysis': {
                'directory_score': round(self._calculate_directory_score(path), 3),
                'file_name_score': round(self._calculate_file_name_score(path), 3),
                'file_type_score': round(self._calculate_file_type_score(path), 3),
                'owasp_score': round(owasp_score, 3),
                'content_score': round(content_score, 3),
                'security_patterns': self._detect_security_patterns(path),
                'file_size': self._get_file_size(path),
                'file_complexity': self._calculate_file_complexity(path),
                'dynamic_weights': weights,
                'ai_analysis': ai_analysis
            }
        }
    
    def _get_dynamic_weights(self, path: Path, content_score: float) -> Dict[str, float]:
        """获取动态权重调整
        
        Args:
            path: 文件路径
            content_score: 内容分析分数
            
        Returns:
            动态权重字典
        """
        # 基础权重
        base_weights = {
            'importance': self.importance_weight,
            'problem_probability': self.problem_probability_weight,
            'content': self.content_weight
        }
        
        # 根据文件类型调整权重
        file_type = path.suffix.lower()
        if file_type in ['.env', '.key', '.pem', '.crt', '.env.local', '.env.development', '.env.production', '.env.test']:
            # 敏感配置文件，增加内容权重
            return {
                'importance': 0.2,
                'problem_probability': 0.3,
                'content': 0.5
            }
        elif file_type in ['.py', '.js', '.ts', '.php', '.java']:
            # 代码文件，保持平衡
            return base_weights
        elif file_type in ['.sh', '.bat', '.ps1']:
            # 脚本文件，增加问题概率权重
            return {
                'importance': 0.2,
                'problem_probability': 0.6,
                'content': 0.2
            }
        
        # 根据内容分数调整权重
        if content_score > 0.8:
            # 高风险内容，增加内容权重
            return {
                'importance': 0.2,
                'problem_probability': 0.3,
                'content': 0.5
            }
        elif content_score < 0.3:
            # 低风险内容，减少内容权重
            return {
                'importance': 0.4,
                'problem_probability': 0.5,
                'content': 0.1
            }
        
        return base_weights
    
    def _apply_nonlinear_adjustment(self, priority_score: float, content_score: float) -> float:
        """应用非线性调整
        
        Args:
            priority_score: 基础优先级分数
            content_score: 内容分析分数
            
        Returns:
            调整后的优先级分数
        """
        # 对高风险文件给予更高的权重
        if priority_score > 0.7:
            # 高优先级文件，进一步提高分数
            priority_score = min(1.0, priority_score * 1.1)
        elif priority_score > 0.5:
            # 中高优先级文件，轻微提高分数
            priority_score = min(1.0, priority_score * 1.05)
        
        # 如果内容分析显示高风险，额外提高分数
        if content_score > 0.8:
            priority_score = min(1.0, priority_score * 1.15)
        
        return priority_score
    
    def _calculate_content_score(self, path: Path) -> float:
        """计算文件内容分析分数
        
        Args:
            path: 文件路径
            
        Returns:
            内容分析分数（0-1）
        """
        try:
            # 检测安全模式
            security_patterns = self._detect_security_patterns(path)
            pattern_score = min(1.0, len(security_patterns) * 0.1)  # 每个模式贡献0.1分
            
            # 计算文件复杂度
            complexity_score = self._calculate_file_complexity(path)
            
            # 计算文件大小分数
            size_score = self._calculate_size_score(path)
            
            # 综合分数
            return (pattern_score * 0.5 + complexity_score * 0.3 + size_score * 0.2)
        except Exception:
            return 0.5  # 默认分数
    
    def _detect_security_patterns(self, path: Path) -> list:
        """检测文件中的安全问题模式
        
        Args:
            path: 文件路径
            
        Returns:
            检测到的安全模式列表
        """
        detected_patterns = []
        
        try:
            if path.is_file() and path.stat().st_size < 1000000:  # 限制文件大小，避免处理过大的文件
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                    
                    for pattern_name, patterns in self.security_patterns.items():
                        for pattern in patterns:
                            if pattern.lower() in content:
                                detected_patterns.append(pattern_name)
                                break
        except Exception:
            pass
        
        return detected_patterns
    
    def _calculate_file_complexity(self, path: Path) -> float:
        """计算文件复杂度
        
        Args:
            path: 文件路径
            
        Returns:
            复杂度分数（0-1）
        """
        try:
            if path.is_file() and path.stat().st_size < 1000000:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                    code_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
                    
                    # 基于代码行数计算复杂度
                    line_count = len(code_lines)
                    if line_count > 1000:
                        return 1.0
                    elif line_count > 500:
                        return 0.8
                    elif line_count > 200:
                        return 0.6
                    elif line_count > 100:
                        return 0.4
                    else:
                        return 0.2
        except Exception:
            pass
        
        return 0.5
    
    def _calculate_size_score(self, path: Path) -> float:
        """计算文件大小分数
        
        Args:
            path: 文件路径
            
        Returns:
            大小分数（0-1）
        """
        try:
            if path.is_file():
                size = path.stat().st_size
                if size > 1000000:
                    return 1.0  # 大文件风险更高
                elif size > 100000:
                    return 0.8
                elif size > 10000:
                    return 0.6
                elif size > 1000:
                    return 0.4
                else:
                    return 0.2
        except Exception:
            pass
        
        return 0.5
    
    def _get_file_size(self, path: Path) -> int:
        """获取文件大小
        
        Args:
            path: 文件路径
            
        Returns:
            文件大小（字节）
        """
        try:
            if path.is_file():
                return path.stat().st_size
        except Exception:
            pass
        
        return 0
    
    def _calculate_importance(self, path: Path) -> float:
        """计算文件重要性
        
        Args:
            path: 文件路径
            
        Returns:
            重要性分数（0-1）
        """
        # 目录重要性
        directory_score = self._calculate_directory_score(path)
        
        # 文件名重要性
        file_name_score = self._calculate_file_name_score(path)
        
        # 综合重要性（平均）
        return (directory_score + file_name_score) / 2
    
    def _calculate_problem_probability(self, path: Path) -> float:
        """计算出现问题的概率
        
        Args:
            path: 文件路径
            
        Returns:
            问题概率分数（0-1）
        """
        # 文件类型问题概率
        file_type_score = self._calculate_file_type_score(path)
        
        # 文件名问题概率（基于关键词）
        file_name_problem_score = self._calculate_file_name_score(path)
        
        # 综合问题概率（文件类型权重更高）
        return file_type_score * 0.6 + file_name_problem_score * 0.4
    
    def _calculate_directory_score(self, path: Path) -> float:
        """计算目录重要性分数
        
        Args:
            path: 文件路径
            
        Returns:
            目录重要性分数（0-1）
        """
        max_score = 0.0
        
        # 检查所有父目录
        for parent in path.parents:
            dir_name = parent.name.lower()
            if dir_name in self.directory_weights:
                if self.directory_weights[dir_name] > max_score:
                    max_score = self.directory_weights[dir_name]
        
        return max_score
    
    def _calculate_file_name_score(self, path: Path) -> float:
        """计算文件名重要性分数
        
        Args:
            path: 文件路径
            
        Returns:
            文件名重要性分数（0-1）
        """
        file_name = path.stem.lower()
        max_score = 0.5  # 默认分数
        
        # 检查文件名中的关键词
        for keyword, score in self.file_name_keywords.items():
            if keyword in file_name:
                if score > max_score:
                    max_score = score
        
        return max_score
    
    def _calculate_file_type_score(self, path: Path) -> float:
        """计算文件类型问题概率分数

        Args:
            path: 文件路径

        Returns:
            文件类型问题概率分数（0-1）
        """
        suffix = path.suffix.lower()
        return self.file_type_weights.get(suffix, 0.4)  # 默认分数
    
    def _calculate_owasp_score(self, path: Path) -> float:
        """计算 OWASP TOP10 关键词匹配分数

        Args:
            path: 文件路径

        Returns:
            OWASP 关键词匹配分数（0-1）
        """
        path_str = str(path).lower()
        file_name = path.stem.lower()
        
        matched_categories = set()
        total_matches = 0
        
        for category, info in self.OWASP_TOP10_KEYWORDS.items():
            keywords = info['keywords']
            category_matches = 0
            
            for keyword in keywords:
                if keyword in path_str or keyword in file_name:
                    category_matches += 1
                    total_matches += 1
            
            if category_matches > 0:
                matched_categories.add(category)
        
        if not matched_categories:
            return 0.0
        
        category_count = len(matched_categories)
        category_bonus = min(0.3, category_count * 0.05)
        
        base_score = min(0.7, total_matches * 0.1)
        
        final_score = base_score + category_bonus

        return min(1.0, final_score)

    def _get_file_preview(self, path: Path, max_lines: int = 10, max_chars: int = 500) -> str:
        """获取文件预览（只读取前几行）

        Args:
            path: 文件路径
            max_lines: 最大行数
            max_chars: 最大字符数

        Returns:
            文件预览文本
        """
        try:
            if not path.is_file():
                return ""

            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        break
                    lines.append(line.rstrip('\n\r'))

                preview = '\n'.join(lines)
                if len(preview) > max_chars:
                    preview = preview[:max_chars] + "..."

                return preview
        except Exception:
            return ""

    def _get_project_structure_summary(self, project_root: Path) -> str:
        """获取项目结构摘要

        Args:
            project_root: 项目根目录

        Returns:
            项目结构摘要字符串
        """
        key_dirs = ['src', 'config', 'api', 'auth', 'service', 'controller', 'models', 'routes', 'middleware', 'utils', 'core', 'lib']
        summary_parts = []

        try:
            if not project_root.is_dir():
                return "项目根目录无效"

            for item in sorted(project_root.iterdir()):
                if item.is_dir():
                    dir_name = item.name.lower()
                    if dir_name in key_dirs:
                        file_count = len(list(item.rglob('*'))) if item.is_dir() else 0
                        summary_parts.append(f"{item.name}/ ({file_count} files)")

            if not summary_parts:
                all_dirs = [item.name for item in sorted(project_root.iterdir()) if item.is_dir()]
                summary_parts = all_dirs[:10]

            return " | ".join(summary_parts) if summary_parts else "空项目"
        except Exception:
            return "无法获取项目结构"

    def _pre_filter_by_rules(self, paths: list) -> list:
        """使用规则快速过滤文件，返回 TOP 30% 最重要的文件

        Args:
            paths: 文件路径列表

        Returns:
            过滤后的文件路径列表（TOP 30%）
        """
        if not paths:
            return []

        scored_files = []

        for file_path in paths:
            path = Path(file_path)

            importance_score = self._calculate_importance(path)
            problem_probability = self._calculate_problem_probability(path)
            content_score = self._calculate_content_score(path)
            owasp_score = self._calculate_owasp_score(path)

            weights = self._get_dynamic_weights(path, content_score)

            combined_score = (
                importance_score * weights['importance'] +
                problem_probability * weights['problem_probability'] +
                content_score * weights['content']
            )
            combined_score = self._apply_nonlinear_adjustment(combined_score, content_score)

            final_score = combined_score * 0.4 + owasp_score * 0.35 + problem_probability * 0.25

            scored_files.append((file_path, final_score))

        scored_files.sort(key=lambda x: x[1], reverse=True)

        top_count = max(1, int(len(scored_files) * 0.3))

        return [file_path for file_path, _ in scored_files[:top_count]]

    async def calculate_priority_batch(self, paths: List[str], use_ai: bool = True,
                                       include_token_analysis: bool = True) -> List[Dict[str, Any]]:
        """批量计算文件优先级（优化版 - 两阶段筛选）

        Args:
            paths: 文件路径列表
            use_ai: 是否使用AI分析
            include_token_analysis: 是否包含Token流分析

        Returns:
            按优先级降序排列的结果列表
        """
        if not paths:
            return []

        initial_results = []
        for path_str in paths:
            path = Path(path_str)
            if not path.exists():
                continue

            importance_score = self._calculate_importance(path)
            problem_probability = self._calculate_problem_probability(path)
            content_score = self._calculate_content_score(path)
            owasp_score = self._calculate_owasp_score(path)

            token_score = 0.0
            if include_token_analysis:
                token_result = self.calculate_token_risk_score(path)
                token_score = token_result.get('risk_score', 0.0)

            rule_score = (
                importance_score * 0.2 +
                problem_probability * 0.3 +
                content_score * 0.2 +
                owasp_score * 0.15 +
                token_score * 0.15
            )

            initial_results.append({
                'path': path_str,
                'rule_score': rule_score,
                'importance_score': importance_score,
                'problem_probability': problem_probability,
                'content_score': content_score,
                'owasp_score': owasp_score,
                'token_score': token_score
            })

        initial_results.sort(key=lambda x: x['rule_score'], reverse=True)
        top_count = max(1, int(len(initial_results) * 0.35))
        top_results = initial_results[:top_count]

        final_results = []

        if use_ai:
            tasks = []
            for result in top_results:
                task = self.calculate_priority(result['path'])
                tasks.append(task)

            if tasks:
                completed = await asyncio.gather(*tasks, return_exceptions=True)
                for i, res in enumerate(completed):
                    if isinstance(res, Exception):
                        final_results.append({
                            'file_path': top_results[i]['path'],
                            'priority_score': top_results[i]['rule_score'],
                            'stage': 'ai_failed'
                        })
                    else:
                        res['stage'] = 'full_ai'
                        final_results.append(res)
        else:
            for result in top_results:
                result['file_path'] = result['path']
                result['priority_score'] = result['rule_score']
                result['stage'] = 'rule_only'
                final_results.append(result)

        all_paths = {r['file_path'] for r in final_results}
        for result in initial_results[top_count:]:
            if result['path'] not in all_paths:
                result['file_path'] = result['path']
                result['priority_score'] = result['rule_score']
                result['stage'] = 'rule_only'
                final_results.append(result)

        final_results.sort(key=lambda x: x.get('priority_score', 0), reverse=True)

        return final_results

    def _sort_files_by_priority(self, files: list) -> list:
        """按优先级分数降序排序文件

        Args:
            files: 文件优先级字典列表

        Returns:
            按优先级降序排列的列表
        """
        return sorted(files, key=lambda x: x.get('priority_score', 0.5), reverse=True)

    def _extract_tokens(self, path: Path) -> List[Dict[str, Any]]:
        """提取文件的Token序列

        Args:
            path: 文件路径

        Returns:
            Token列表，每个token包含: {'text': str, 'line': int, 'category': str}
        """
        tokens = []
        try:
            if path.is_file() and path.stat().st_size < 1000000:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_no, line in enumerate(f, 1):
                        line_lower = line.lower()
                        for category, pattern in TOKEN_FLOW_PATTERNS.items():
                            for keyword in pattern['keywords']:
                                if keyword.lower() in line_lower:
                                    tokens.append({
                                        'text': line.strip(),
                                        'line': line_no,
                                        'category': category,
                                        'keyword': keyword,
                                        'severity': pattern['severity']
                                    })
        except Exception:
            pass
        return tokens

    def _analyze_token_flow(self, tokens: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析Token流，检测危险数据流模式

        Args:
            tokens: Token序列

        Returns:
            分析结果，包含: {'has_dangerous_flow': bool, 'risk_score': float, 'flow_paths': list}
        """
        if not tokens:
            return {'has_dangerous_flow': False, 'risk_score': 0.0, 'flow_paths': []}

        flow_paths = []
        risk_score = 0.0

        sorted_tokens = sorted(tokens, key=lambda x: x['line'])

        for pattern in DANGEROUS_FLOW_PATTERNS:
            pattern_len = len(pattern)
            for i in range(len(sorted_tokens) - pattern_len + 1):
                window = [t['category'] for t in sorted_tokens[i:i+pattern_len]]
                if window == list(pattern):
                    sink_idx = i + pattern_len - 1
                    has_sanitizer = any(
                        t['category'] == 'sanitizer'
                        for t in sorted_tokens[i:sink_idx]
                    )
                    if not has_sanitizer:
                        flow_paths.append({
                            'pattern': pattern,
                            'start_line': sorted_tokens[i]['line'],
                            'end_line': sorted_tokens[sink_idx]['line'],
                            'tokens': sorted_tokens[i:i+pattern_len]
                        })
                        risk_score += 0.8

        for token in sorted_tokens:
            if token['category'] == 'source':
                for sink_token in sorted_tokens:
                    if sink_token['category'] == 'sink' and sink_token['line'] > token['line']:
                        between = [t for t in sorted_tokens
                                   if token['line'] < t['line'] < sink_token['line']]
                        has_sanitizer = any(t['category'] == 'sanitizer' for t in between)
                        if not has_sanitizer:
                            risk_score += 0.95
                            flow_paths.append({
                                'pattern': ('source', 'sink'),
                                'start_line': token['line'],
                                'end_line': sink_token['line'],
                                'direct': True
                            })

        return {
            'has_dangerous_flow': len(flow_paths) > 0,
            'risk_score': min(1.0, risk_score),
            'flow_paths': flow_paths
        }

    def calculate_token_risk_score(self, path: Path) -> Dict[str, Any]:
        """计算基于Token流的文件风险分数

        Args:
            path: 文件路径

        Returns:
            包含风险分数和分析结果的字典
        """
        tokens = self._extract_tokens(path)
        flow_analysis = self._analyze_token_flow(tokens)

        return {
            'file_path': str(path),
            'token_count': len(tokens),
            'risk_score': flow_analysis['risk_score'],
            'has_dangerous_flow': flow_analysis['has_dangerous_flow'],
            'flow_paths': flow_analysis['flow_paths'],
            'tokens': tokens[:20]
        }

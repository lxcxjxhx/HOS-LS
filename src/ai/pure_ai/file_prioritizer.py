from pathlib import Path
from typing import Dict, Any

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
            'database': 0.8,
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
            'internal': 0.8
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
            '.xml': 0.5,
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
            'xss': ['innerHTML', 'outerHTML', 'document.write', 'eval', 'setInnerHTML'],
            'command_injection': ['exec', 'system', 'subprocess', 'shell_exec', 'passthru'],
            'csrf': ['csrf', 'token', 'session', 'cookie'],
            'authentication': ['password', 'login', 'auth', 'authenticate'],
            'authorization': ['permission', 'role', 'access', 'privilege'],
            'sensitive_data': ['password', 'secret', 'key', 'token', 'credential'],
            'file_handling': ['file_get_contents', 'fopen', 'fwrite', 'file_put_contents'],
            'network': ['socket', 'http', 'request', 'response', 'fetch'],
            'crypto': ['encrypt', 'decrypt', 'hash', 'md5', 'sha1']
        }
        
        # 权重系数
        self.importance_weight = 0.3  # 文件重要性权重
        self.problem_probability_weight = 0.7  # 出现问题的可能性权重
        self.content_weight = 0.2  # 内容分析权重
    
    def calculate_priority(self, file_path: str) -> Dict[str, Any]:
        """计算文件优先级
        
        Args:
            file_path: 文件路径
            
        Returns:
            包含优先级分数和详细分析的字典
        """
        path = Path(file_path)
        
        # 1. 计算文件重要性
        importance_score = self._calculate_importance(path)
        
        # 2. 计算出现问题的概率
        problem_probability = self._calculate_problem_probability(path)
        
        # 3. 计算内容分析分数
        content_score = self._calculate_content_score(path)
        
        # 4. 获取动态权重调整
        weights = self._get_dynamic_weights(path, content_score)
        
        # 5. 计算最终优先级（动态加权）
        priority_score = (
            importance_score * weights['importance'] +
            problem_probability * weights['problem_probability'] +
            content_score * weights['content']
        )
        
        # 6. 应用非线性调整，对高风险文件给予更高权重
        priority_score = self._apply_nonlinear_adjustment(priority_score, content_score)
        
        return {
            'file_path': file_path,
            'priority_score': round(priority_score, 3),
            'importance_score': round(importance_score, 3),
            'problem_probability': round(problem_probability, 3),
            'content_score': round(content_score, 3),
            'analysis': {
                'directory_score': round(self._calculate_directory_score(path), 3),
                'file_name_score': round(self._calculate_file_name_score(path), 3),
                'file_type_score': round(self._calculate_file_type_score(path), 3),
                'content_score': round(content_score, 3),
                'security_patterns': self._detect_security_patterns(path),
                'file_size': self._get_file_size(path),
                'file_complexity': self._calculate_file_complexity(path),
                'dynamic_weights': weights
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

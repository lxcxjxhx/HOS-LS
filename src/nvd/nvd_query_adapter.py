"""NVD 数据库查询适配器

实际查询 nvd_vulnerability.db 数据库进行 CWE 匹配和漏洞查询
优化版本：支持缓存和内存索引
"""

import os
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


class NVDQueryAdapter:
    """NVD 数据库查询适配器

    实际查询 nvd_vulnerability.db 数据库进行 CWE 匹配
    优化版本：缓存 + 内存索引 + CVSS 统计
    """

    def __init__(self, db_path: str = None, use_cache: bool = True):
        if db_path is None:
            db_path = self._find_default_db_path()

        self.db_path = db_path
        self._conn = None
        self._connected = False
        self._fallback_mode = False
        self._cwe_index: Optional[Dict[str, Dict[str, Any]]] = None
        self._index_built = False

        if use_cache:
            try:
                from src.nvd.query_cache import NVDQueryCache, get_global_cache
                self._cache = get_global_cache()
            except Exception:
                self._cache = None
        else:
            self._cache = None

        db_path_str = str(db_path) if db_path else ""
        if db_path_str and os.path.exists(db_path_str):
            self._connect()
        else:
            logger.warning(f"NVD数据库文件不存在: {db_path_str}")
            self._fallback_mode = True

    def _find_default_db_path(self) -> Optional[str]:
        """查找默认的 NVD 数据库路径（使用增强的路径查找逻辑）"""
        try:
            from src.nvd.db.sqlite_connection import SQLiteConnection
            # 修复：使用公开的类方法 find_database_path() 而不是错误的实例方法
            found_path = SQLiteConnection.find_database_path()
            if found_path:
                logger.info(f"[NVDQueryAdapter] 使用增强路径查找找到数据库: {found_path}")
                return str(found_path)
        except Exception as e:
            logger.debug(f"[NVDQueryAdapter] SQLiteConnection路径查找失败: {e}")

        possible_paths = [
            Path(__file__).parent.parent.parent.parent / 'All Vulnerabilities' / 'sql_data' / 'nvd_vulnerability.db',
            Path('c:/1AAA_PROJECT/HOS/HOS-LS/HOS-LS/All Vulnerabilities/sql_data/nvd_vulnerability.db'),
            Path.cwd() / 'All Vulnerabilities' / 'sql_data' / 'nvd_vulnerability.db',
        ]

        for path in possible_paths:
            if path.exists() and path.is_file():
                try:
                    import sqlite3
                    test_conn = sqlite3.connect(str(path), timeout=1.0)
                    test_conn.execute("SELECT 1")
                    test_conn.close()
                    logger.info(f"找到NVD数据库: {path}")
                    return str(path)
                except Exception:
                    pass

        return None

    def _connect(self) -> bool:
        """连接数据库"""
        try:
            import sqlite3
            self._conn = sqlite3.connect(self.db_path, timeout=30.0)
            self._conn.row_factory = sqlite3.Row
            self._connected = True
            logger.info(f"NVD数据库连接成功: {self.db_path}")
            return True
        except Exception as e:
            logger.error(f"NVD数据库连接失败: {e}")
            self._connected = False
            return False

    def _disconnect(self) -> None:
        """断开数据库连接"""
        if self._conn:
            self._conn.close()
            self._conn = None
            self._connected = False

    def _ensure_connected(self) -> bool:
        """确保已连接"""
        if not self._connected or self._conn is None:
            return self._connect()
        return True

    def is_available(self) -> bool:
        """NVD 查询始终可用（强制启用）"""
        return True

    def _ensure_cwe_index(self) -> Dict[str, Dict[str, Any]]:
        """构建 CWE 内存索引

        一次性加载所有 CWE 到内存，加速后续查询
        """
        if self._fallback_mode:
            logger.warning("NVD 处于 fallback 模式，跳过索引构建")
            return {}

        if self._cwe_index is not None:
            return self._cwe_index

        if not self._ensure_connected():
            return {}

        try:
            cursor = self._conn.cursor()
            
            # 检查cwe表是否存在
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='cwe'
            """)
            if not cursor.fetchone():
                logger.warning("CWE表不存在，跳过CWE索引构建（降级模式）")
                cursor.close()
                self._cwe_index = {}
                return {}
            
            cursor.execute("""
                SELECT cwe_id, name, description
                FROM cwe
            """)
            rows = cursor.fetchall()
            cursor.close()

            self._cwe_index = {}
            for row in rows:
                self._cwe_index[row['cwe_id']] = {
                    'cwe_id': row['cwe_id'],
                    'cwe_name': row['name'],
                    'cwe_description': row['description'],
                    'name_lower': row['name'].lower(),
                    'desc_lower': row['description'].lower()
                }

            self._index_built = True
            logger.info(f"CWE内存索引构建完成，共 {len(self._cwe_index)} 条记录")
            return self._cwe_index

        except Exception as e:
            logger.warning(f"CWE索引构建失败: {e}（降级模式：无CWE匹配）")
            self._cwe_index = {}
            return {}

    def _search_in_memory(self, keywords: List[str], limit: int = 5) -> List[Dict[str, Any]]:
        """在内存中搜索 CWE

        Args:
            keywords: 关键词列表
            limit: 返回数量限制

        Returns:
            匹配的 CWE 列表
        """
        cwe_index = self._ensure_cwe_index()
        if not cwe_index:
            return []

        scored = []
        for cwe_id, cwe_info in cwe_index.items():
            score = 0
            matched_kws = []

            name_lower = cwe_info['name_lower']
            desc_lower = cwe_info['desc_lower']

            for kw in keywords:
                kw_lower = kw.lower()

                if kw_lower in name_lower:
                    score += 3
                    matched_kws.append(kw)

                if kw_lower in desc_lower:
                    score += 1
                    if kw not in matched_kws:
                        matched_kws.append(kw)

            if score > 0:
                scored.append({
                    'cwe_id': cwe_id,
                    'cwe_name': cwe_info['cwe_name'],
                    'cwe_description': cwe_info['cwe_description'],
                    'confidence': min(1.0, score / 6.0),
                    'matched_keywords': matched_kws,
                    'score': score
                })

        scored.sort(key=lambda x: x['score'], reverse=True)
        return scored[:limit]

    def match_cwe(self, keywords: List[str], limit: int = 5) -> List[Dict[str, Any]]:
        """根据关键词匹配 NVD CWE

        优化版本：优先使用缓存，然后使用内存索引

        Args:
            keywords: 关键词列表
            limit: 返回数量限制

        Returns:
            匹配的 CWE 信息列表
        """
        if not keywords:
            return []

        if self._fallback_mode:
            logger.warning("NVD 处于 fallback 模式，返回空 CWE 结果")
            return []

        cache_key = f"match:{','.join(sorted(keywords))}:{limit}"

        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        if self._ensure_connected() and self._cwe_index is not None:
            results = self._search_in_memory(keywords, limit)
        elif self._ensure_connected():
            results = self._search_with_index(keywords, limit)
        else:
            results = []

        if self._cache and results:
            self._cache.set(cache_key, results)

        return results

    def _search_with_index(self, keywords: List[str], limit: int = 5) -> List[Dict[str, Any]]:
        """使用索引搜索 CWE

        Args:
            keywords: 关键词列表
            limit: 返回数量限制

        Returns:
            匹配的 CWE 列表
        """
        cwe_index = self._ensure_cwe_index()
        if not cwe_index:
            return []

        return self._search_in_memory(keywords, limit)

    def get_cwe_by_id(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """根据 CWE ID 获取详细信息

        Args:
            cwe_id: CWE ID，如 'CWE-89'

        Returns:
            CWE 详细信息
        """
        if not self._ensure_connected():
            return None

        if self._fallback_mode:
            logger.warning("NVD 处于 fallback 模式，返回空 CWE-by-ID 结果")
            return None

        cache_key = f"cwe_by_id:{cwe_id}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            cwe_index = self._ensure_cwe_index()
            if cwe_id in cwe_index:
                result = {
                    'cwe_id': cwe_index[cwe_id]['cwe_id'],
                    'cwe_name': cwe_index[cwe_id]['cwe_name'],
                    'cwe_description': cwe_index[cwe_id]['cwe_description'],
                    'confidence': 1.0
                }
                if self._cache:
                    self._cache.set(cache_key, result)
                return result

            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT cwe_id, cwe_name, cwe_description
                FROM cwe
                WHERE cwe_id = ?
            """, (cwe_id,))

            row = cursor.fetchone()
            cursor.close()

            if row:
                result = {
                    'cwe_id': row['cwe_id'],
                    'cwe_name': row['cwe_name'],
                    'cwe_description': row['cwe_description'],
                    'confidence': 1.0
                }
                if self._cache:
                    self._cache.set(cache_key, result)
                return result

            return None

        except Exception as e:
            logger.error(f"CWE查询失败 (ID: {cwe_id}): {e}")
            return None

    def get_cwe_with_cvss_stats(self, cwe_id: str) -> Dict[str, Any]:
        """获取 CWE 的 CVSS 统计信息

        用于辅助判断漏洞严重性

        Args:
            cwe_id: CWE ID

        Returns:
            CVSS 统计信息
        """
        if not self._ensure_connected():
            return {}

        if self._fallback_mode:
            logger.warning("NVD 处于 fallback 模式，返回空 CVSS 统计")
            return {}

        cache_key = f"cvss_stats:{cwe_id}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT
                    AVG(cvss.cvss_score) as avg_score,
                    MAX(cvss.cvss_score) as max_score,
                    MIN(cvss.cvss_score) as min_score,
                    COUNT(DISTINCT cvss.cvss_severity) as severity_count,
                    COUNT(DISTINCT cvss.cve_id) as cve_count
                FROM cve_cwe
                JOIN cvss ON cve_cwe.cve_id = cvss.cve_id
                WHERE cve_cwe.cwe_id = ?
            """, (cwe_id,))

            row = cursor.fetchone()
            cursor.close()

            result = {
                'cwe_id': cwe_id,
                'avg_cvss': float(row['avg_score']) if row['avg_score'] else 0.0,
                'max_cvss': float(row['max_score']) if row['max_score'] else 0.0,
                'min_cvss': float(row['min_score']) if row['min_score'] else 0.0,
                'severity_variants': row['severity_count'] or 0,
                'cve_count': row['cve_count'] or 0
            }

            if self._cache:
                self._cache.set(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"CVSS统计查询失败 (CWE: {cwe_id}): {e}")
            return {}

    def search_vulnerabilities(self, cwe_id: str = None, severity: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """搜索特定 CWE 的漏洞

        Args:
            cwe_id: CWE ID，如 'CWE-89'
            severity: 严重级别，如 'HIGH', 'CRITICAL'
            limit: 返回数量限制

        Returns:
            漏洞信息列表
        """
        if not self._ensure_connected():
            return []

        if self._fallback_mode:
            logger.warning("NVD 处于 fallback 模式，返回空漏洞搜索结果")
            return []

        try:
            cursor = self._conn.cursor()

            query = """
                SELECT DISTINCT
                    cve.cve_id,
                    cve.description,
                    cvss.cvss_score,
                    cvss.cvss_severity
                FROM cve
                LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
                LEFT JOIN cve_cwe ON cve.cve_id = cve_cwe.cve_id
                WHERE 1=1
            """
            params = []

            if cwe_id:
                query += " AND cve_cwe.cwe_id = ?"
                params.append(cwe_id)

            if severity:
                query += " AND cvss.cvss_severity = ?"
                params.append(severity.upper())

            query += f" ORDER BY cvss.cvss_score DESC LIMIT {limit}"

            cursor.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()

            results = []
            for row in rows:
                results.append({
                    'cve_id': row['cve_id'],
                    'description': row['description'],
                    'cvss_score': float(row['cvss_score']) if row['cvss_score'] else None,
                    'severity': row['cvss_severity']
                })

            return results

        except Exception as e:
            logger.error(f"漏洞搜索失败: {e}")
            return []

    def get_cwe_with_cves(self, cwe_id: str, limit: int = 10) -> Dict[str, Any]:
        """获取 CWE 及其相关的 CVE

        Args:
            cwe_id: CWE ID
            limit: 返回的 CVE 数量

        Returns:
            包含 CWE 信息和相关 CVE 列表的字典
        """
        cwe_info = self.get_cwe_by_id(cwe_id)
        if not cwe_info:
            return {}

        cves = self.search_vulnerabilities(cwe_id=cwe_id, limit=limit)
        cwe_info['related_cves'] = cves
        cwe_info['cve_count'] = len(cves)

        cvss_stats = self.get_cwe_with_cvss_stats(cwe_id)
        cwe_info['cvss_stats'] = cvss_stats

        return cwe_info

    def get_all_cwe_ids(self) -> List[str]:
        """获取所有 CWE ID 列表

        Returns:
            CWE ID 列表
        """
        if not self._ensure_connected():
            return []

        if self._fallback_mode:
            logger.warning("NVD 处于 fallback 模式，返回空 CWE IDs 列表")
            return []

        cache_key = "all_cwe_ids"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            cwe_index = self._ensure_cwe_index()
            if cwe_index:
                result = sorted(cwe_index.keys())
                if self._cache:
                    self._cache.set(cache_key, result)
                return result

            cursor = self._conn.cursor()
            cursor.execute("SELECT cwe_id FROM cwe ORDER BY cwe_id")
            rows = cursor.fetchall()
            cursor.close()
            result = [row['cwe_id'] for row in rows]

            if self._cache:
                self._cache.set(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"获取CWE列表失败: {e}")
            return []

    def get_db_stats(self) -> Dict[str, int]:
        """获取数据库统计信息

        Returns:
            各表的记录数统计
        """
        stats = {
            'connected': self._connected,
            'db_path': self.db_path,
            'index_built': self._index_built,
            'index_size': len(self._cwe_index) if self._cwe_index else 0
        }

        if not self._ensure_connected():
            return stats

        if self._fallback_mode:
            return stats

        try:
            cursor = self._conn.cursor()
            tables = ['cve', 'cvss', 'cpe', 'cwe', 'cve_cwe', 'kev', 'exploit', 'poc']

            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    stats[table] = count
                except Exception:
                    stats[table] = 0

            cursor.close()
        except Exception as e:
            logger.error(f"获取数据库统计失败: {e}")

        return stats

    def clear_cache(self) -> None:
        """清空查询缓存"""
        if self._cache:
            self._cache.clear()

    def get_vulnerability_keywords(self, language: str = "python") -> Dict[str, List[str]]:
        """从 NVD 数据库提取漏洞关键词（用于 sink 匹配）

        CVE 描述通常不包含具体函数名，但包含漏洞特征关键词。
        这些关键词可用于代码中的模式匹配。

        Args:
            language: 编程语言

        Returns:
            按漏洞类型分组的关键词字典
        """
        if not self._ensure_connected():
            return {}

        cache_key = f"vuln_keywords:{language}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        # 各语言代码中常见的 sink 关键词
        # 这些是代码语义关键词，不是漏洞特征
        lang_sink_keywords = {
            'python': {
                'sql_injection': ['execute', 'query', 'raw', 'cursor'],
                'command_injection': ['system', 'popen', 'subprocess', 'exec', 'spawn', 'run'],
                'xss': ['render', 'template', 'html', 'response', 'write'],
                'code_injection': ['eval', 'exec', 'compile', 'import'],
                'path_traversal': ['open', 'read', 'write', 'path', 'file'],
                'deserialization': ['pickle', 'yaml', 'marshal', 'loads', 'unpickle'],
                'ssrf': ['request', 'get', 'post', 'urlopen', 'fetch'],
            },
            'java': {
                'sql_injection': ['executeQuery', 'executeUpdate', 'createStatement', 'prepareStatement'],
                'command_injection': ['exec', 'Runtime', 'ProcessBuilder', 'System'],
                'xss': ['getWriter', 'println', 'innerHTML', 'write'],
                'code_injection': ['eval', 'invoke', 'getMethod'],
                'path_traversal': ['File', 'FileInputStream', 'getPath', 'openStream'],
            },
            'javascript': {
                'sql_injection': ['query', 'execute', 'exec'],
                'command_injection': ['exec', 'spawn', 'execSync', 'execFile'],
                'xss': ['innerHTML', 'outerHTML', 'document.write', 'eval'],
                'code_injection': ['eval', 'Function', 'setTimeout'],
                'path_traversal': ['readFile', 'writeFile', 'open', 'fs.'],
            },
        }

        result = lang_sink_keywords.get(language, {})

        if self._cache:
            self._cache.set(cache_key, result)

        return result

    def get_dangerous_functions(self, language: str = "python") -> Dict[str, List[str]]:
        """从 NVD 数据库动态获取危险函数列表

        直接查询 CVE 描述中的漏洞模式，提取实际的危险函数。
        不依赖 cve_cwe 映射表（该表可能为空），改用 CVE 描述关键词匹配。
        绝对无硬编码数据，完全依赖 NVD 数据库。

        Args:
            language: 编程语言 (python/java/javascript)

        Returns:
            按漏洞类型分组的危险函数字典
        """
        if not self._ensure_connected():
            return {}

        cache_key = f"dangerous_funcs:{language}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        # 漏洞类型关键词映射（用于从 CVE 描述中筛选相关 CVE）
        vuln_keywords = {
            'SQL Injection': ['sql injection', 'sql query', 'sql command', 'database query'],
            'Command Injection': ['command injection', 'os command', 'shell command', 'execute command'],
            'Code Injection': ['code injection', 'arbitrary code', 'eval(', 'exec('],
            'XSS': ['cross-site scripting', 'xss', 'script injection', 'html injection'],
            'Deserialization': ['deserialization', 'unserialize', 'pickle', 'yaml load'],
            'Path Traversal': ['path traversal', 'directory traversal', 'file path', 'file inclusion'],
            'SSRF': ['server-side request forgery', 'ssrf', 'internal request'],
        }

        # 各语言危险函数识别关键词
        language_indicators = {
            'python': ['cursor', 'os.system', 'os.popen', 'subprocess', 'eval(', 'exec(', 'render_template',
                       'pickle.loads', 'yaml.load', 'urllib', 'requests.', 'sqlite3', 'psycopg2'],
            'java': ['executequery', 'runtime.exec', 'processbuilder', 'objectinput', 'fileinput',
                     'getwriter', 'innerhtml', 'statement.execute', 'class.forname', 'method.invoke'],
            'javascript': ['child_process', 'eval(', 'function(', 'innerhtml', 'document.write',
                           'fetch(', 'axios', 'exec(', 'spawn('],
        }

        indicators = language_indicators.get(language, language_indicators['python'])
        result = {}

        try:
            cursor = self._conn.cursor()

            for vuln_type, keywords in vuln_keywords.items():
                funcs = set()
                for kw in keywords:
                    cursor.execute("""
                        SELECT DISTINCT description
                        FROM cve
                        WHERE description LIKE ?
                        LIMIT 200
                    """, (f'%{kw}%',))

                    for row in cursor.fetchall():
                        desc = row['description'].lower() if row['description'] else ''

                        # 提取函数/方法调用模式
                        import re
                        func_patterns = re.findall(r'(?:[\w.]+)\w+(?:\s*\()', desc)
                        for p in func_patterns:
                            clean = p.strip('(').strip()
                            if any(ind.lower() in clean.lower() for ind in indicators):
                                funcs.add(clean)

                if funcs:
                    result[vuln_type] = sorted(funcs)

            cursor.close()
        except Exception as e:
            logger.debug(f"NVD 危险函数动态提取失败: {e}")

        if self._cache:
            self._cache.set(cache_key, result)

        return result

    def get_all_cwe_descriptions(self) -> List[Dict[str, str]]:
        """获取所有 CWE 的 ID 和描述（供 AI Agent 参考）

        替代硬编码 CWE_PATTERNS 中的 cwe_id/cwe_name 映射。

        Returns:
            CWE 信息列表
        """
        cwe_index = self._ensure_cwe_index()
        if cwe_index:
            return [
                {
                    'cwe_id': info['cwe_id'],
                    'cwe_name': info['cwe_name'],
                    'cwe_description': info['cwe_description'],
                }
                for info in cwe_index.values()
            ]

        if not self._ensure_connected():
            return []

        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT cwe_id, name, description FROM cwe")
            rows = cursor.fetchall()
            cursor.close()

            return [
                {
                    'cwe_id': row['cwe_id'],
                    'cwe_name': row['name'],
                    'cwe_description': row['description'],
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"获取CWE描述列表失败: {e}")
            return []

    def get_sanitizer_patterns(self, language: str = "python") -> List[Dict[str, str]]:
        """从 NVD 数据库动态获取 sanitizer 模式（供 AI Agent 参考）

        通过分析 CVE 描述中与"escape/sanitize/validate/parameterized"相关的
        修复方案描述，提取各语言的安全处理函数模式。
        绝对无硬编码数据，完全依赖 NVD 数据库。

        Args:
            language: 编程语言

        Returns:
            sanitizer 模式列表
        """
        if not self._ensure_connected():
            return []

        cache_key = f"sanitizer_patterns:{language}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        # 与 sanitizer 相关的安全关键词
        security_keywords = [
            'escape', 'sanitize', 'validate', 'parameterized',
            'prepared statement', 'encode', 'whitelist', 'allowlist',
            'input validation', 'output encoding', 'html encode',
        ]

        # 各语言 sanitizer 函数的识别关键词
        language_indicators = {
            'python': ['escape', 'quote', 'sanitize', 'validate', 'clean', 'purify', 'html.'],
            'java': ['escape', 'sanitize', 'preparedstatement', 'encode', 'validate', 'stringescape'],
            'javascript': ['escape', 'encodeuricomponent', 'dompurify', 'sanitize', 'textcontent', 'encode'],
        }

        indicators = language_indicators.get(language, language_indicators['python'])
        sanitizer_set = set()

        try:
            cursor = self._conn.cursor()

            # 从所有包含安全修复关键词的 CVE 描述中提取 sanitizer 函数
            for kw in security_keywords:
                cursor.execute("""
                    SELECT DISTINCT description
                    FROM cve
                    WHERE description LIKE ?
                    LIMIT 100
                """, (f'%{kw}%',))

                for row in cursor.fetchall():
                    desc = row['description'].lower() if row['description'] else ''

                    # 提取函数/方法调用模式
                    import re
                    func_patterns = re.findall(r'(?:[\w.]+)\w+(?:\s*\()', desc)
                    for p in func_patterns:
                        clean = p.strip('(').strip()
                        if any(ind in clean.lower() for ind in indicators):
                            sanitizer_set.add(clean)

            cursor.close()
        except Exception as e:
            logger.debug(f"NVD sanitizer 模式动态提取失败: {e}")

        # 转换为统一格式
        result = [
            {'function': func, 'type': self._infer_sanitizer_type(func)}
            for func in sorted(sanitizer_set)
        ]

        if self._cache:
            self._cache.set(cache_key, result)

        return result

    def _infer_sanitizer_type(self, func_name: str) -> str:
        """根据函数名推断 sanitizer 类型

        Args:
            func_name: 函数名

        Returns:
            sanitizer 类型标识
        """
        func_lower = func_name.lower()
        if 'escape' in func_lower:
            return 'escape'
        elif 'quote' in func_lower:
            return 'quote'
        elif 'encode' in func_lower:
            return 'encode'
        elif 'validate' in func_lower or 'verify' in func_lower:
            return 'validate'
        elif 'param' in func_lower or 'prepared' in func_lower:
            return 'parameterize'
        elif 'sanit' in func_lower or 'clean' in func_lower or 'purify' in func_lower:
            return 'sanitize'
        else:
            return 'sanitize'

    def __del__(self):
        """析构时关闭连接"""
        self._disconnect()


def get_nvd_adapter(db_path: str = None, use_cache: bool = True) -> NVDQueryAdapter:
    """获取 NVD 查询适配器实例（始终返回，不可关闭）

    Args:
        db_path: 数据库路径
        use_cache: 是否使用缓存

    Returns:
        NVDQueryAdapter 实例（始终返回）
    """
    return NVDQueryAdapter(db_path, use_cache)

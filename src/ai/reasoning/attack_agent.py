"""攻击链生成 Agent

基于污点分析结果生成攻击链，具有攻击者视角的推理能力。
"""

from typing import Dict, List, Any, Optional
import re

from src.attack.chain_analyzer import AttackChainAnalyzer


class AttackAgent:
    """攻击链生成 Agent

    基于污点分析结果生成攻击链，具有攻击者视角的推理能力。
    """

    ENTRY_POINT_PATTERNS = {
        'python': [
            r'input\(',
            r'request\.',
            r'request\.args',
            r'request\.form',
            r'request\.json',
            r'request\.values',
            r'os\.environ',
            r'os\.popen',
            r'subprocess\.',
            r'eval\(',
            r'exec\(',
        ],
        'javascript': [
            r'req\.body',
            r'req\.query',
            r'req\.params',
            r'req\.headers',
            r'document\.',
            r'window\.',
            r'eval\(',
            r'Function\(',
            r'innerHTML',
            r'outerHTML',
        ],
    }

    SINK_PATTERNS = {
        'sql_injection': [
            r'execute\(',
            r'executemany\(',
            r'cursor\.execute\(',
            r'cursor\.executemany\(',
            r'\.query\(',
            r'SQL\(',
        ],
        'command_injection': [
            r'os\.system\(',
            r'os\.popen\(',
            r'subprocess\.',
            r'exec\(',
            r'eval\(',
            r'popen\(',
        ],
        'xss': [
            r'innerHTML',
            r'outerHTML',
            r'document\.write',
            r'\.html\(',
            r'v-html',
        ],
        'code_injection': [
            r'eval\(',
            r'exec\(',
            r'compile\(',
            r'__import__\(',
        ],
    }

    PAYLOAD_TEMPLATES = {
        'sql_injection': [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
        ],
        'command_injection': [
            '; ls -la',
            '| cat /etc/passwd',
            '&& whoami',
            '$(whoami)',
            '`id`',
        ],
        'xss': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
        ],
        'code_injection': [
            '__import__("os").system("whoami")',
            'eval("__import__("os").popen("whoami").read()")',
        ],
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化攻击链生成 Agent

        Args:
            config: 配置参数
        """
        self.config = config or {}
        self.chain_analyzer = AttackChainAnalyzer()

    def think_like_attacker(self, code: str, language: str = 'python') -> List[Dict[str, Any]]:
        """从攻击者视角推理攻击路径

        Args:
            code: 目标代码
            language: 编程语言

        Returns:
            攻击路径列表
        """
        attack_paths = []

        entry_points = self.find_entry_points(code, language)
        potential_sinks = self.find_potential_sinks(code, language)

        for entry in entry_points:
            for sink_type, sinks in potential_sinks.items():
                for sink in sinks:
                    if self._can_connect(entry, sink, code):
                        path = self._build_attack_path(entry, sink, code, language)
                        if path:
                            attack_paths.append(path)

        return attack_paths

    def find_entry_points(self, code: str, language: str = 'python') -> List[Dict[str, Any]]:
        """查找可能的攻击入口点

        Args:
            code: 目标代码
            language: 编程语言

        Returns:
            入口点列表
        """
        entry_points = []
        patterns = self.ENTRY_POINT_PATTERNS.get(language, self.ENTRY_POINT_PATTERNS['python'])

        for i, line in enumerate(code.split('\n'), 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    entry_points.append({
                        'line': i,
                        'code': line.strip(),
                        'type': self._classify_entry_point(pattern),
                        'variable': self._extract_variable(line, pattern)
                    })
                    break

        return entry_points

    def find_potential_sinks(self, code: str, language: str = 'python') -> dict[str, list[dict[str, Any]]]:
        """查找可能的危险 sink 点

        Args:
            code: 目标代码
            language: 编程语言

        Returns:
            按漏洞类型分组的 sink 点
        """
        sinks_by_type: Dict[str, List[Dict[str, Any]]] = {}

        for vuln_type, patterns in self.SINK_PATTERNS.items():
            sinks = []
            for i, line in enumerate(code.split('\n'), 1):
                for pattern in patterns:
                    if re.search(pattern, line):
                        sinks.append({
                            'line': i,
                            'code': line.strip(),
                            'function': self._extract_function(line)
                        })
                        break
            if sinks:
                sinks_by_type[vuln_type] = sinks

        return sinks_by_type

    def generate_payload(self, vulnerability_type: str) -> List[str]:
        """生成针对特定漏洞类型的攻击 payload

        Args:
            vulnerability_type: 漏洞类型

        Returns:
            payload 列表
        """
        return self.PAYLOAD_TEMPLATES.get(vulnerability_type, [])

    def validate_exploit(self, code: str, entry_point: Dict, sink: Dict, payload: str) -> Dict[str, Any]:
        """验证 exploit 是否可行

        Args:
            code: 目标代码
            entry_point: 入口点信息
            sink: sink 点信息
            payload: 攻击 payload

        Returns:
            验证结果
        """
        result = {
            'possible': False,
            'confidence': 0.0,
            'reason': '',
            'attack_path': []
        }

        lines = code.split('\n')
        if entry_point['line'] > len(lines) or sink['line'] > len(lines):
            result['reason'] = 'Line number out of range'
            return result

        entry_line = lines[entry_point['line'] - 1]
        sink_line = lines[sink['line'] - 1]

        entry_var = entry_point.get('variable', '')
        sink_func = sink.get('function', '')

        if entry_var and sink_func:
            if entry_var in sink_line or self._variable_reaches(entry_var, sink_line):
                result['possible'] = True
                result['confidence'] = 0.8
                result['attack_path'] = [
                    f"Line {entry_point['line']}: {entry_line.strip()}",
                    f"  ↓ {entry_var} is user-controllable",
                    f"Line {sink['line']}: {sink_line.strip()}",
                    f"  ↓ {sink_func} executes without sanitization",
                    f"Exploit: {payload}"
                ]
                result['reason'] = f'{entry_var} flows to {sink_func}'
            else:
                result['reason'] = f'{entry_var} does not reach {sink_func}'
        else:
            result['reason'] = 'Could not determine data flow'

        return result

    def _classify_entry_point(self, pattern: str) -> str:
        """分类入口点类型"""
        if 'input' in pattern:
            return 'user_input'
        elif 'request' in pattern:
            return 'http_request'
        elif 'environ' in pattern:
            return 'environment'
        else:
            return 'unknown'

    def _extract_variable(self, line: str, pattern: str) -> Optional[str]:
        """从代码行中提取变量名"""
        if 'input(' in line:
            match = re.search(r'(\w+)\s*=\s*input\(', line)
            if match:
                return match.group(1)

        if 'request.' in line:
            match = re.search(r'request\.(args|form|json|values|params)', line)
            if match:
                return f'request.{match.group(1)}'

        if re.search(r'os\.environ', line):
            match = re.search(r'os\.environ\[([\'"])(.+?)\1\]', line)
            if match:
                return f"os.environ['{match.group(2)}']"

        return None

    def _extract_function(self, line: str) -> str:
        """从代码行中提取函数名"""
        funcs = ['execute', 'executemany', 'system', 'popen', 'eval', 'exec', 'query']
        for func in funcs:
            if func in line:
                return func
        return 'unknown'

    def _can_connect(self, entry: Dict, sink: Dict, code: str) -> bool:
        """判断入口点和 sink 点之间是否存在数据流"""
        entry_var = entry.get('variable')
        if not entry_var:
            return False

        lines = code.split('\n')
        sink_line_idx = sink['line'] - 1

        if sink_line_idx < len(lines):
            sink_line = lines[sink_line_idx]
            return entry_var in sink_line or self._variable_reaches(entry_var, sink_line)

        return False

    def _variable_reaches(self, var: str, target_line: str) -> bool:
        """判断变量是否可能到达目标行"""
        return var in target_line

    def _build_attack_path(self, entry: Dict, sink: Dict, code: str, language: str) -> Optional[Dict[str, Any]]:
        """构建攻击路径"""
        entry_var = entry.get('variable')
        sink_func = sink.get('function')
        vuln_type = self._infer_vulnerability_type(sink_func)

        if not entry_var or not sink_func:
            return None

        payload = self.generate_payload(vuln_type)[0] if vuln_type else ''

        return {
            'type': 'attack_path',
            'entry': {
                'line': entry['line'],
                'code': entry['code'],
                'variable': entry_var,
                'type': entry['type']
            },
            'sink': {
                'line': sink['line'],
                'code': sink['code'],
                'function': sink_func
            },
            'vulnerability_type': vuln_type,
            'payload': payload,
            'impact': self._evaluate_impact(vuln_type),
            'confidence': 0.8,
            'source_agent': 'Attack-Agent',
            'attack_chain': f"{entry_var} → {sink_func} → {vuln_type}"
        }

    def _infer_vulnerability_type(self, function: str) -> str:
        """推断漏洞类型"""
        mapping = {
            'execute': 'sql_injection',
            'executemany': 'sql_injection',
            'system': 'command_injection',
            'popen': 'command_injection',
            'eval': 'code_injection',
            'exec': 'code_injection',
            'query': 'sql_injection',
        }
        return mapping.get(function, 'unknown')

    def generate_attack_chains(self, taint_paths: List[Dict[str, Any]], evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成攻击链

        Args:
            taint_paths: 污点路径列表
            evidence: 证据列表

        Returns:
            攻击链列表
        """
        attack_chains = []

        for taint_path in taint_paths:
            chain = self._generate_chain(taint_path, evidence)
            if chain:
                attack_chains.append(chain)

        return attack_chains

    def _generate_chain(self, taint_path: Dict[str, Any], evidence: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """生成单个攻击链

        Args:
            taint_path: 污点路径
            evidence: 证据列表

        Returns:
            攻击链
        """
        source = taint_path.get('source', 'unknown')
        sink = taint_path.get('function', 'unknown')
        location = taint_path.get('location', 'unknown')
        vulnerability_type = taint_path.get('metadata', {}).get('vulnerability_type', 'Unknown')

        path = self._build_attack_path_from_taint(taint_path)
        impact = self._evaluate_impact(vulnerability_type)

        chain = {
            "type": "attack_chain",
            "path": path,
            "impact": impact,
            "vulnerability_type": vulnerability_type,
            "location": location,
            "evidence": taint_path.get('evidence', []),
            "source_agent": "Attack-Agent",
            "confidence": taint_path.get('confidence', 0.8),
            "metadata": {
                "source": source,
                "sink": sink,
                "severity": taint_path.get('metadata', {}).get('severity', 'medium')
            }
        }

        return chain

    def _build_attack_path_from_taint(self, taint_path: Dict[str, Any]) -> List[str]:
        """从污点路径构建攻击路径"""
        path_info = taint_path.get('path', [])

        if isinstance(path_info, list):
            return path_info
        elif isinstance(path_info, str):
            return path_info.split(' → ')
        else:
            source = taint_path.get('source', 'input')
            sink = taint_path.get('function', 'dangerous_function')
            return [source, sink]

    def _evaluate_impact(self, vulnerability_type: str) -> str:
        """评估漏洞影响

        Args:
            vulnerability_type: 漏洞类型

        Returns:
            影响级别
        """
        impact_map = {
            "Code Injection": "RCE",
            "Command Injection": "RCE",
            "SQL Injection": "Data Breach",
            "XSS": "Client-Side Attack",
            "Path Traversal": "File Access",
            "Authentication Bypass": "Privilege Escalation",
            "Authorization Bypass": "Privilege Escalation",
            "Information Disclosure": "Data Leak",
            "Denial of Service": "DoS",
            "Buffer Overflow": "RCE",
            "sql_injection": "Data Breach",
            "command_injection": "RCE",
            "code_injection": "RCE",
            "xss": "Client-Side Attack",
        }

        return impact_map.get(vulnerability_type, "Unknown")

    def get_standardized_output(self, attack_chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """获取标准化的输出格式

        Args:
            attack_chains: 攻击链列表

        Returns:
            标准化的输出列表
        """
        return attack_chains

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
沙箱分析模块

功能：
1. 代码沙箱执行监控
2. 网络行为监控（外联检测）
3. 文件操作追踪（读写敏感文件）
4. 系统调用拦截
5. 异常行为检测
6. 并行文件分析
7. 智能文件发现
"""

import ast
import re
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict

from .file_discovery_engine import file_discovery_engine
from .sandbox_executor_pool import sandbox_executor_pool

logger = logging.getLogger(__name__)


class SandboxAnalyzer:
    """沙箱分析器"""
    
    def __init__(self):
        # 网络外联检测模式
        self.network_patterns = [
            r'requests\.(get|post|put|delete|patch)\s*\(',
            r'urllib\.request\.urlopen\s*\(',
            r'http\.client\.HTTPConnection',
            r'socket\.socket\s*\(.*\)\.connect',
            r'ftplib\.FTP',
            r'smtplib\.SMTP',
            r'paramiko\.SSHClient',
            r'asyncio\.open_connection',
            r'aiohttp\.ClientSession',
            r'httpx\.Client',
        ]
        
        # 文件操作检测模式
        self.file_operations = [
            r'open\s*\([^)]*[\'"][^\'"]*[\'"]',
            r'os\.open\s*\(',
            r'os\.read\s*\(',
            r'os\.write\s*\(',
            r'shutil\.(copy|move|remove|rmtree)',
            r'os\.(remove|unlink|rmdir|rename)',
            r'pathlib\.Path\.[^)]*write',
            r'pathlib\.Path\.[^)]*read',
            r'yaml\.(safe_)?load\s*\(',
            r'pickle\.load\s*\(',
            r'joblib\.load\s*\(',
        ]
        
        # 敏感文件路径
        self.sensitive_paths = [
            r'/etc/passwd',
            r'/etc/shadow',
            r'~/.ssh/',
            r'~/.bashrc',
            r'~/.bash_profile',
            r'~/.netrc',
            r'~/.pgpass',
            r'~/.my.cnf',
            r'\.env',
            r'credentials',
            r'secrets?\.(json|yaml|yml|txt)',
            r'\.pem$',
            r'\.key$',
            r'\.p12$',
            r'\.pfx$',
        ]
        
        # 系统调用检测
        self.system_calls = [
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'subprocess\.(call|run|Popen|check_output)\s*\(',
            r'commands\.getoutput\s*\(',
            r'pty\.spawn\s*\(',
            r'pexpect\.spawn\s*\(',
        ]
        
        # 危险操作组合（攻击链）
        self.dangerous_chains = [
            ('network', 'file_read'),  # 读取文件后外发
            ('file_write', 'network'),  # 写入文件后外发
            ('system_call', 'network'),  # 执行命令后外发
            ('eval', 'network'),  # 代码执行后外发
        ]
    
    def detect_network_exfiltration(self, content: str) -> List[Dict[str, Any]]:
        """检测网络外联行为"""
        results = []
        
        for pattern in self.network_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                result = {
                    'type': 'network_exfiltration',
                    'pattern': pattern,
                    'match': match.group(0),
                    'position': match.start(),
                    'severity': 'HIGH',
                    'confidence': 0.85,
                    'description': '检测到网络外联行为',
                    'risk': '数据外泄、C2 通信',
                    'mitigation': '验证目标地址，实施白名单，记录所有外联'
                }
                
                # 检查是否包含敏感数据
                if self._contains_sensitive_data(content, match.start()):
                    result['severity'] = 'CRITICAL'
                    result['confidence'] = 0.95
                    result['description'] = '检测到敏感数据外联'
                
                results.append(result)
        
        return results
    
    def detect_file_operations(self, content: str) -> List[Dict[str, Any]]:
        """检测文件操作"""
        results = []
        
        for pattern in self.file_operations:
            matches = re.finditer(pattern, content)
            for match in matches:
                result = {
                    'type': 'file_operation',
                    'pattern': pattern,
                    'match': match.group(0),
                    'position': match.start(),
                    'severity': 'MEDIUM',
                    'confidence': 0.80,
                    'description': '检测到文件操作',
                    'risk': '敏感文件访问、数据泄露',
                    'mitigation': '限制文件访问权限，实施路径白名单'
                }
                
                # 检查是否访问敏感路径
                if self._is_sensitive_path(content, match.start()):
                    result['severity'] = 'HIGH'
                    result['confidence'] = 0.90
                    result['description'] = '检测到敏感文件访问'
                
                results.append(result)
        
        return results
    
    def detect_system_calls(self, content: str) -> List[Dict[str, Any]]:
        """检测系统调用"""
        results = []
        
        for pattern in self.system_calls:
            matches = re.finditer(pattern, content)
            for match in matches:
                result = {
                    'type': 'system_call',
                    'pattern': pattern,
                    'match': match.group(0),
                    'position': match.start(),
                    'severity': 'HIGH',
                    'confidence': 0.90,
                    'description': '检测到系统调用',
                    'risk': '命令注入、系统控制',
                    'mitigation': '禁止系统调用，使用安全 API 替代'
                }
                
                # 检查是否包含用户输入
                if self._contains_user_input(content, match.start()):
                    result['severity'] = 'CRITICAL'
                    result['confidence'] = 0.95
                    result['description'] = '检测到用户输入系统调用'
                
                results.append(result)
        
        return results
    
    def detect_attack_chains(self, content: str) -> List[Dict[str, Any]]:
        """检测攻击链（危险操作组合）"""
        results = []
        
        # 检测网络操作
        network_ops = []
        for pattern in self.network_patterns:
            for match in re.finditer(pattern, content):
                network_ops.append(('network', match.start()))
        
        # 检测文件读取
        file_reads = []
        file_read_patterns = [r'open\s*\(', r'os\.read\s*\(', r'pathlib\.Path\.[^)]*read']
        for pattern in file_read_patterns:
            for match in re.finditer(pattern, content):
                file_reads.append(('file_read', match.start()))
        
        # 检测文件写入
        file_writes = []
        file_write_patterns = [r'open\s*\([^)]*["\']w', r'os\.write\s*\(', r'pathlib\.Path\.[^)]*write']
        for pattern in file_write_patterns:
            for match in re.finditer(pattern, content):
                file_writes.append(('file_write', match.start()))
        
        # 检测系统调用
        sys_calls = []
        for pattern in self.system_calls:
            for match in re.finditer(pattern, content):
                sys_calls.append(('system_call', match.start()))
        
        # 检测危险组合
        for chain_type, ops1, ops2 in [
            ('file_to_network', file_reads, network_ops),
            ('write_to_network', file_writes, network_ops),
            ('exec_to_network', sys_calls, network_ops),
        ]:
            for op1, pos1 in ops1:
                for op2, pos2 in ops2:
                    # 检查操作顺序（先 op1 后 op2）
                    if pos1 < pos2:
                        result = {
                            'type': 'attack_chain',
                            'chain_type': chain_type,
                            'operations': [op1, op2],
                            'positions': [pos1, pos2],
                            'severity': 'CRITICAL',
                            'confidence': 0.85,
                            'description': f'检测到攻击链：{op1} -> {op2}',
                            'risk': '数据外泄、横向移动',
                            'mitigation': '分离操作权限，实施行为监控'
                        }
                        results.append(result)
        
        return results
    
    def _contains_sensitive_data(self, content: str, position: int) -> bool:
        """检查是否包含敏感数据"""
        # 查找附近的敏感变量名
        context_start = max(0, position - 200)
        context = content[context_start:position + 100]
        
        sensitive_keywords = [
            'password', 'secret', 'token', 'api_key', 'apikey',
            'credential', 'private_key', 'auth', 'access_token'
        ]
        
        for keyword in sensitive_keywords:
            if keyword in context.lower():
                return True
        
        return False
    
    def _is_sensitive_path(self, content: str, position: int) -> bool:
        """检查是否是敏感路径"""
        # 提取路径
        context_start = max(0, position - 100)
        context = content[context_start:position + 200]
        
        for pattern in self.sensitive_paths:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _contains_user_input(self, content: str, position: int) -> bool:
        """检查是否包含用户输入"""
        context_start = max(0, position - 200)
        context = content[context_start:position + 100]
        
        user_input_patterns = [
            r'input\s*\(',
            r'request\.(args|form|data|json)',
            r'sys\.argv',
            r'os\.environ',
        ]
        
        for pattern in user_input_patterns:
            if re.search(pattern, context):
                return True
        
        return False
    
    def analyze(self, content: str) -> Dict[str, Any]:
        """执行完整沙箱分析"""
        results = {
            'network_exfiltration': self.detect_network_exfiltration(content),
            'file_operations': self.detect_file_operations(content),
            'system_calls': self.detect_system_calls(content),
            'attack_chains': self.detect_attack_chains(content),
            'summary': {
                'total_issues': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
            }
        }
        
        # 统计
        all_issues = (
            results['network_exfiltration'] +
            results['file_operations'] +
            results['system_calls'] +
            results['attack_chains']
        )
        
        results['summary']['total_issues'] = len(all_issues)
        results['summary']['critical'] = sum(1 for i in all_issues if i.get('severity') == 'CRITICAL')
        results['summary']['high'] = sum(1 for i in all_issues if i.get('severity') == 'HIGH')
        results['summary']['medium'] = sum(1 for i in all_issues if i.get('severity') == 'MEDIUM')
        
        return results
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """分析单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            analysis_result = self.analyze(content)
            return {
                'file': file_path,
                'success': True,
                'analysis': analysis_result
            }
        except Exception as e:
            logger.error(f"分析文件 {file_path} 时出错: {str(e)}")
            return {
                'file': file_path,
                'success': False,
                'error': str(e)
            }
    
    def analyze_files(self, files: List[str], parallel: bool = True) -> List[Dict[str, Any]]:
        """分析文件列表"""
        sandbox_executor_pool.initialize()
        return sandbox_executor_pool.execute(files, self.analyze_file, parallel)
    
    def analyze_directory(self, directory: str, extensions: Optional[List[str]] = None, 
                         include_patterns: Optional[List[str]] = None, 
                         exclude_patterns: Optional[List[str]] = None, 
                         parallel: bool = True) -> Dict[str, Any]:
        """分析目录中的所有文件"""
        # 发现文件
        files = file_discovery_engine.discover_files(
            directory, extensions, include_patterns, exclude_patterns
        )
        
        # 分析文件
        results = self.analyze_files(files, parallel)
        
        # 统计结果
        summary = {
            'total_files': len(files),
            'analyzed_files': len([r for r in results if r.get('success')]),
            'failed_files': len([r for r in results if not r.get('success')]),
            'total_issues': 0,
            'critical': 0,
            'high': 0,
            'medium': 0
        }
        
        for result in results:
            if result.get('success') and 'analysis' in result:
                analysis = result['analysis']
                summary['total_issues'] += analysis['summary']['total_issues']
                summary['critical'] += analysis['summary']['critical']
                summary['high'] += analysis['summary']['high']
                summary['medium'] += analysis['summary']['medium']
        
        return {
            'directory': directory,
            'summary': summary,
            'results': results
        }


class BehaviorMonitor:
    """行为监控器（用于运行时监控）"""
    
    def __init__(self):
        self.sandbox = SandboxAnalyzer()
        self.behavior_log = []
    
    def log_action(self, action_type: str, details: Dict[str, Any]):
        """记录行为"""
        self.behavior_log.append({
            'timestamp': self._get_timestamp(),
            'action_type': action_type,
            'details': details
        })
    
    def _get_timestamp(self) -> str:
        """获取时间戳"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_behavior_report(self) -> Dict[str, Any]:
        """生成行为报告"""
        return {
            'total_actions': len(self.behavior_log),
            'actions_by_type': self._count_by_type(),
            'suspicious_activities': self._detect_suspicious(),
            'log': self.behavior_log
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """按类型统计"""
        counts = defaultdict(int)
        for action in self.behavior_log:
            counts[action['action_type']] += 1
        return dict(counts)
    
    def _detect_suspicious(self) -> List[Dict[str, Any]]:
        """检测可疑活动"""
        suspicious = []
        
        # 检测频繁的网络请求
        network_count = sum(1 for a in self.behavior_log if a['action_type'] == 'network')
        if network_count > 10:
            suspicious.append({
                'type': 'excessive_network',
                'count': network_count,
                'severity': 'HIGH'
            })
        
        # 检测敏感文件访问
        file_access = [a for a in self.behavior_log if a['action_type'] == 'file']
        for access in file_access:
            if 'sensitive' in access['details'].get('path', '').lower():
                suspicious.append({
                    'type': 'sensitive_file_access',
                    'details': access,
                    'severity': 'CRITICAL'
                })
        
        return suspicious

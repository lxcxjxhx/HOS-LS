"""数据集导入工具

负责从各种来源导入安全漏洞数据，包括CVE、漏洞模式和POC。
"""

import json
import os
import requests
from typing import Dict, List, Optional

from src.core.config import Config, get_config


class DatasetImporter:
    """数据集导入器

    从各种来源导入安全漏洞数据。
    """
    
    def __init__(self, config: Optional[Config] = None):
        """初始化数据集导入器
        
        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self.api_timeout = 30  # API请求超时时间
    
    def import_from_nvd(self, year: int) -> List[Dict]:
        """从NVD导入CVE数据
        
        Args:
            year: 年份
        
        Returns:
            CVE列表
        """
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={year}-01-01T00:00:00.000&pubEndDate={year}-12-31T23:59:59.000"
            headers = {
                "Accept": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=self.api_timeout)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            # 解析NVD响应
            for item in data.get("vulnerabilities", []):
                cve_item = item.get("cve", {})
                cve_id = cve_item.get("id")
                descriptions = cve_item.get("descriptions", [])
                description = ""
                
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                references = []
                for ref in cve_item.get("references", []):
                    references.extend(ref.get("url", []))
                
                # 获取CVSS评分
                cvss_metrics = cve_item.get("metrics", {})
                cvss_v3 = cvss_metrics.get("cvssMetricV31", []) or cvss_metrics.get("cvssMetricV30", [])
                cvss_score = None
                
                if cvss_v3:
                    cvss_score = cvss_v3[0].get("cvssData", {}).get("baseScore")
                
                cves.append({
                    "id": cve_id,
                    "description": description,
                    "references": references,
                    "cvss_score": cvss_score,
                    "published_date": cve_item.get("published", ""),
                    "last_modified_date": cve_item.get("lastModified", "")
                })
            
            return cves
        except Exception as e:
            print(f"从NVD导入CVE失败: {str(e)}")
            return []
    
    def import_from_exploitdb(self, limit: int = 100) -> List[Dict]:
        """从Exploit-DB导入漏洞数据
        
        Args:
            limit: 限制数量
        
        Returns:
            漏洞列表
        """
        try:
            url = f"https://exploit-db.com/api/v1/search?limit={limit}"
            headers = {
                "Accept": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=self.api_timeout)
            response.raise_for_status()
            
            data = response.json()
            exploits = []
            
            # 解析Exploit-DB响应
            for item in data.get("data", []):
                exploits.append({
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "type": item.get("type"),
                    "platform": item.get("platform"),
                    "author": item.get("author"),
                    "date": item.get("date"),
                    "url": item.get("url"),
                    "cve": item.get("cve")
                })
            
            return exploits
        except Exception as e:
            print(f"从Exploit-DB导入漏洞失败: {str(e)}")
            return []
    
    def import_from_custom_json(self, file_path: str) -> List[Dict]:
        """从自定义JSON文件导入数据
        
        Args:
            file_path: JSON文件路径
        
        Returns:
            数据列表
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 检查数据格式
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                # 尝试从常见的键中提取数据
                for key in ["cves", "vulnerabilities", "exploits", "pocs", "patterns"]:
                    if key in data and isinstance(data[key], list):
                        return data[key]
            
            return []
        except Exception as e:
            print(f"从JSON文件导入数据失败: {str(e)}")
            return []
    
    def import_vulnerability_patterns(self) -> List[Dict]:
        """导入漏洞模式数据
        
        Returns:
            漏洞模式列表
        """
        # 内置的漏洞模式
        patterns = [
            {
                "type": "SQL Injection",
                "description": "SQL注入漏洞",
                "patterns": [
                    r"execute\(['\"].*\{.*\}.*['\"]",
                    r"query\(['\"].*\{.*\}.*['\"]",
                    r"sql.*=.*['\"].*\+.*['\"]",
                    r"SELECT.*FROM.*WHERE.*=['\"].*\+.*['\"]"
                ],
                "severity": "high",
                "cwe": "CWE-89"
            },
            {
                "type": "Command Injection",
                "description": "命令注入漏洞",
                "patterns": [
                    r"exec\(['\"].*\{.*\}.*['\"]",
                    r"system\(['\"].*\{.*\}.*['\"]",
                    r"subprocess\.run\(['\"].*\{.*\}.*['\"]",
                    r"os\.system\(['\"].*\+.*['\"]"
                ],
                "severity": "high",
                "cwe": "CWE-77"
            },
            {
                "type": "XSS",
                "description": "跨站脚本漏洞",
                "patterns": [
                    r"innerHTML\s*=.*\{.*\}",
                    r"document\.write\(['\"].*\{.*\}.*['\"]",
                    r"eval\(['\"].*\{.*\}.*['\"]",
                    r"setAttribute\(['\"](on\w+)['\"],.*\{.*\}"
                ],
                "severity": "medium",
                "cwe": "CWE-79"
            },
            {
                "type": "SSRF",
                "description": "服务器端请求伪造漏洞",
                "patterns": [
                    r"requests\.get\(['\"].*\{.*\}.*['\"]",
                    r"urllib\.request\.urlopen\(['\"].*\{.*\}.*['\"]",
                    r"fetch\(['\"].*\{.*\}.*['\"]",
                    r"HttpClient\.get\(['\"].*\{.*\}.*['\"]"
                ],
                "severity": "high",
                "cwe": "CWE-918"
            },
            {
                "type": "Path Traversal",
                "description": "路径遍历漏洞",
                "patterns": [
                    r"open\(['\"].*\{.*\}.*['\"]",
                    r"readFile\(['\"].*\{.*\}.*['\"]",
                    r"fs\.readFileSync\(['\"].*\{.*\}.*['\"]",
                    r"path\.join\(['\"].*\{.*\}.*['\"]"
                ],
                "severity": "high",
                "cwe": "CWE-22"
            }
        ]
        
        return patterns
    
    def import_poc_templates(self) -> List[Dict]:
        """导入POC模板数据
        
        Returns:
            POC模板列表
        """
        # 内置的POC模板
        pocs = [
            {
                "vulnerability_type": "SQL Injection",
                "name": "SQL注入测试",
                "description": "测试SQL注入漏洞",
                "methods": [
                    {
                        "method": "curl",
                        "template": "curl -X GET '{url}?{parameter}={payload}'"
                    },
                    {
                        "method": "python",
                        "template": """import requests\n\nurl = '{url}'\nparams = {{'{parameter}': '{payload}'}}\nresponse = requests.get(url, params=params)\nprint(response.text)\n"""
                    }
                ],
                "payloads": [
                    "' OR 1=1 --",
                    "' UNION SELECT user, password FROM users --",
                    "' AND 1=0 UNION SELECT version(), database() --"
                ]
            },
            {
                "vulnerability_type": "XSS",
                "name": "XSS测试",
                "description": "测试跨站脚本漏洞",
                "methods": [
                    {
                        "method": "curl",
                        "template": "curl -X GET '{url}?{parameter}={payload}'"
                    },
                    {
                        "method": "python",
                        "template": """import requests\n\nurl = '{url}'\nparams = {{'{parameter}': '{payload}'}}\nresponse = requests.get(url, params=params)\nprint(response.text)\n"""
                    }
                ],
                "payloads": [
                    "<script>alert('XSS')</script>",
                    "<img src='x' onerror='alert(1)'>",
                    "<svg onload='alert(1)'>"
                ]
            },
            {
                "vulnerability_type": "SSRF",
                "name": "SSRF测试",
                "description": "测试服务器端请求伪造漏洞",
                "methods": [
                    {
                        "method": "curl",
                        "template": "curl -X GET '{url}?{parameter}={payload}'"
                    },
                    {
                        "method": "python",
                        "template": """import requests\n\nurl = '{url}'\nparams = {{'{parameter}': '{payload}'}}\nresponse = requests.get(url, params=params)\nprint(response.text)\n"""
                    }
                ],
                "payloads": [
                    "http://localhost:8080",
                    "http://127.0.0.1:3306",
                    "file:///etc/passwd"
                ]
            },
            {
                "vulnerability_type": "Path Traversal",
                "name": "路径遍历测试",
                "description": "测试路径遍历漏洞",
                "methods": [
                    {
                        "method": "curl",
                        "template": "curl -X GET '{url}?{parameter}={payload}'"
                    },
                    {
                        "method": "python",
                        "template": """import requests\n\nurl = '{url}'\nparams = {{'{parameter}': '{payload}'}}\nresponse = requests.get(url, params=params)\nprint(response.text)\n"""
                    }
                ],
                "payloads": [
                    "../../../../etc/passwd",
                    "../..\\/..\\/..\\/windows\\win.ini",
                    "....//....//....//etc/passwd"
                ]
            }
        ]
        
        return pocs

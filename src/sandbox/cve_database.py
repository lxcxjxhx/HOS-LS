"""
CVE数据库加载器

提供CVE/POC数据库加载、搜索和匹配功能。
用于AI POC生成的预推理和降噪。
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class CVEInfo:
    """CVE信息"""
    cve_id: str
    description: str
    html_url: str
    tech_stack: List[str]
    severity: str = "unknown"
    cvss_score: float = 0.0


class CVEDatabase:
    """CVE数据库加载器

    加载CVE/POC数据并提供搜索功能。
    数据来源:
    - SQLite数据库: All Vulnerabilities/sql_data/vd_vulnerability.db
    - JSON文件: All Vulnerabilities/temp_zip/PoC-in-GitHub-master/
    """

    VULNERABILITY_KEYWORDS = {
        "SQL Injection": ["sql", "database", "injection", "sqli", "mysql", "postgresql", "oracle"],
        "XSS": ["xss", "cross-site", "script", "javascript", "html", "dom"],
        "RCE": ["remote code", "execution", "rce", "command", "shell", "exec"],
        "SSRF": ["ssrf", "server-side", "request", "fetch", "url", "redirect"],
        "XXE": ["xxe", "xml", "external", "entity", "DOCTYPE"],
        "Path Traversal": ["path", "traversal", "directory", "lfi", "rfp"],
        "Deserialization": ["deserialize", "serialization", "pickle", "java", "object"],
        "CSRF": ["csrf", "cross-site", "request", "forgery", "token"],
        "IDOR": ["idor", "insecure", "direct", "object", "reference", "authorization"],
        "API Security": ["api", "rest", "graphql", "endpoint", "authentication"],
    }

    def __init__(self, db_path: Optional[str] = None, json_dir: Optional[str] = None):
        """初始化CVE数据库

        Args:
            db_path: SQLite数据库路径
            json_dir: JSON CVE目录路径
        """
        self.base_path = Path(__file__).parent.parent.parent
        self.db_path = Path(db_path) if db_path else self.base_path / "All Vulnerabilities" / "sql_data" / "vd_vulnerability.db"
        self.json_dir = Path(json_dir) if json_dir else self.base_path / "All Vulnerabilities" / "temp_zip" / "PoC-in-GitHub-master"
        self.cve_index: Dict[str, Dict] = {}
        self.tech_to_cves: Dict[str, List[str]] = {}
        self._loaded = False

    def load(self, verbose: bool = True) -> int:
        """加载CVE数据

        Args:
            verbose: 是否打印加载信息

        Returns:
            加载的CVE数量
        """
        if self._loaded:
            return len(self.cve_index)

        count = 0

        if self.json_dir.exists():
            count += self._load_from_json()
            if verbose:
                print(f"[CVE Database] Loaded {count} CVEs from JSON")
        else:
            if verbose:
                print(f"[CVE Database] JSON directory not found: {self.json_dir}")

        if self.db_path.exists():
            db_count = self._load_from_db()
            count += db_count
            if verbose:
                print(f"[CVE Database] Loaded {db_count} CVEs from SQLite")
        else:
            if verbose:
                print(f"[CVE Database] SQLite database not found: {self.db_path}")

        self._build_tech_index()
        self._loaded = True

        if verbose:
            print(f"[CVE Database] Total CVEs indexed: {len(self.cve_index)}")

        return count

    def _load_from_json(self) -> int:
        """从JSON目录加载CVE

        Returns:
            加载的CVE数量
        """
        count = 0

        if not self.json_dir.exists():
            return 0

        for cve_file in self.json_dir.glob("**/*.json"):
            try:
                with open(cve_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for item in data:
                        cve_info = self._parse_json_item(item)
                        if cve_info:
                            self.cve_index[cve_info.cve_id] = {
                                "cve_id": cve_info.cve_id,
                                "description": cve_info.description,
                                "html_url": cve_info.html_url,
                                "tech_stack": cve_info.tech_stack,
                                "severity": cve_info.severity,
                                "cvss_score": cve_info.cvss_score,
                            }
                            count += 1
                elif isinstance(data, dict):
                    cve_info = self._parse_json_item(data)
                    if cve_info:
                        self.cve_index[cve_info.cve_id] = {
                            "cve_id": cve_info.cve_id,
                            "description": cve_info.description,
                            "html_url": cve_info.html_url,
                            "tech_stack": cve_info.tech_stack,
                            "severity": cve_info.severity,
                            "cvss_score": cve_info.cvss_score,
                        }
                        count += 1

            except Exception as e:
                continue

        return count

    def _parse_json_item(self, item: Dict) -> Optional[CVEInfo]:
        """解析JSON条目

        Args:
            item: JSON数据

        Returns:
            CVEInfo对象或None
        """
        cve_id = item.get("name", "") or item.get("cve_id", "") or item.get("id", "")
        if not cve_id.startswith("CVE-"):
            return None

        description = item.get("description", "") or item.get("body", "") or ""
        html_url = item.get("html_url", "") or item.get("url", "") or item.get("link", "") or ""

        tech_stack = self._extract_tech_stack(description)

        severity = item.get("severity", "unknown")
        cvss_score = float(item.get("cvss_score", 0.0) or 0.0)

        return CVEInfo(
            cve_id=cve_id,
            description=description,
            html_url=html_url,
            tech_stack=tech_stack,
            severity=severity,
            cvss_score=cvss_score,
        )

    def _extract_tech_stack(self, description: str) -> List[str]:
        """从描述中提取技术栈

        Args:
            description: CVE描述

        Returns:
            技术栈列表
        """
        tech_stack = []
        desc_lower = description.lower()

        for vuln_type, keywords in self.VULNERABILITY_KEYWORDS.items():
            for keyword in keywords:
                if keyword in desc_lower:
                    if vuln_type not in tech_stack:
                        tech_stack.append(vuln_type)
                    break

        return tech_stack

    def _load_from_db(self) -> int:
        """从SQLite数据库加载CVE

        Returns:
            加载的CVE数量
        """
        count = 0

        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [t[0] for t in cursor.fetchall()]

            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 1")
                    columns = [desc[0] for desc in cursor.description]

                    if "cve_id" in columns or "cve" in columns:
                        id_col = "cve_id" if "cve_id" in columns else "cve"
                        desc_col = next((c for c in columns if "desc" in c.lower()), None)
                        url_col = next((c for c in columns if "url" in c.lower() or "link" in c.lower()), None)

                        query = f"SELECT {id_col}"
                        if desc_col:
                            query += f", {desc_col}"
                        if url_col:
                            query += f", {url_col}"
                        query += f" FROM {table}"

                        cursor.execute(query)
                        rows = cursor.fetchall()

                        for row in rows:
                            cve_id = str(row[0])
                            if cve_id.startswith("CVE-"):
                                description = str(row[1]) if desc_col else ""
                                html_url = str(row[2]) if url_col else ""

                                self.cve_index[cve_id] = {
                                    "cve_id": cve_id,
                                    "description": description,
                                    "html_url": html_url,
                                    "tech_stack": self._extract_tech_stack(description),
                                    "severity": "unknown",
                                    "cvss_score": 0.0,
                                }
                                count += 1

                except Exception:
                    continue

            conn.close()

        except Exception as e:
            print(f"[CVE Database] SQLite load error: {e}")

        return count

    def _build_tech_index(self):
        """构建技术栈到CVE的索引"""
        self.tech_to_cves = {}

        for cve_id, info in self.cve_index.items():
            for tech in info.get("tech_stack", []):
                if tech not in self.tech_to_cves:
                    self.tech_to_cves[tech] = []
                self.tech_to_cves[tech].append(cve_id)

    def search_by_keyword(self, keyword: str) -> List[Dict]:
        """按关键词搜索CVE

        Args:
            keyword: 搜索关键词

        Returns:
            匹配的CVE列表
        """
        keyword_lower = keyword.lower()
        results = []

        for cve_id, info in self.cve_index.items():
            desc = info.get("description", "").lower()
            if keyword_lower in desc:
                results.append(info)

        return results

    def search_by_tech_stack(self, tech_stack: List[str]) -> List[Dict]:
        """按技术栈搜索CVE

        Args:
            tech_stack: 技术栈列表

        Returns:
            匹配的CVE列表
        """
        results = []
        seen = set()

        for tech in tech_stack:
            matching_cves = self.tech_to_cves.get(tech, [])
            for cve_id in matching_cves:
                if cve_id not in seen:
                    seen.add(cve_id)
                    results.append(self.cve_index[cve_id])

        return results

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """获取指定CVE信息

        Args:
            cve_id: CVE编号

        Returns:
            CVE信息字典
        """
        return self.cve_index.get(cve_id)

    def get_poc_url(self, cve_id: str) -> Optional[str]:
        """获取CVE关联的POC URL

        Args:
            cve_id: CVE编号

        Returns:
            POC URL
        """
        cve = self.cve_index.get(cve_id)
        return cve.get("html_url") if cve else None

    def get_all_cves(self) -> List[Dict]:
        """获取所有CVE

        Returns:
            所有CVE列表
        """
        return list(self.cve_index.values())

    def get_vulnerability_types(self) -> List[str]:
        """获取所有漏洞类型

        Returns:
            漏洞类型列表
        """
        return list(self.VULNERABILITY_KEYWORDS.keys())

    def is_loaded(self) -> bool:
        """检查是否已加载

        Returns:
            是否已加载
        """
        return self._loaded

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息字典
        """
        return {
            "total_cves": len(self.cve_index),
            "tech_stack_count": len(self.tech_to_cves),
            "loaded": self._loaded,
            "db_path": str(self.db_path),
            "json_dir": str(self.json_dir),
        }

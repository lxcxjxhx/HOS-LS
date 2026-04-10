"""数据集管理系统

负责安全漏洞数据集的管理，包括存储、导入、导出、更新和查询功能。
"""

import json
import os
import time
from typing import Dict, List, Optional, Tuple

from src.core.config import Config, get_config
from src.integration.cve_crawler import CVECrawler
from src.integration.nvd_importer import NVDImporter


class DatasetManager:
    """数据集管理器

    管理安全漏洞数据集，包括CVE、漏洞模式、POC等数据。
    """
    
    def __init__(self, config: Optional[Config] = None):
        """初始化数据集管理器
        
        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self.dataset_dir = os.path.join(self.config.data.storage_path, "dataset")
        self.cve_dataset_path = os.path.join(self.dataset_dir, "cve_dataset.json")
        self.vulnerability_patterns_path = os.path.join(self.dataset_dir, "vulnerability_patterns.json")
        self.poc_dataset_path = os.path.join(self.dataset_dir, "poc_dataset.json")
        
        # 确保数据集目录存在
        os.makedirs(self.dataset_dir, exist_ok=True)
        
        # 初始化数据集
        self._initialize_datasets()
        
        # 初始化CVE爬虫和NVD导入器
        self.cve_crawler = CVECrawler()
        self.nvd_importer = NVDImporter()
    
    def _initialize_datasets(self):
        """初始化数据集文件"""
        # 初始化CVE数据集
        if not os.path.exists(self.cve_dataset_path):
            with open(self.cve_dataset_path, 'w', encoding='utf-8') as f:
                json.dump({"cves": [], "last_updated": None}, f, ensure_ascii=False, indent=2)
        
        # 初始化漏洞模式数据集
        if not os.path.exists(self.vulnerability_patterns_path):
            with open(self.vulnerability_patterns_path, 'w', encoding='utf-8') as f:
                json.dump({"patterns": [], "last_updated": None}, f, ensure_ascii=False, indent=2)
        
        # 初始化POC数据集
        if not os.path.exists(self.poc_dataset_path):
            with open(self.poc_dataset_path, 'w', encoding='utf-8') as f:
                json.dump({"pocs": [], "last_updated": None}, f, ensure_ascii=False, indent=2)
    
    def get_cve_dataset(self) -> Dict:
        """获取CVE数据集
        
        Returns:
            CVE数据集
        """
        with open(self.cve_dataset_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def get_vulnerability_patterns(self) -> Dict:
        """获取漏洞模式数据集
        
        Returns:
            漏洞模式数据集
        """
        with open(self.vulnerability_patterns_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def get_poc_dataset(self) -> Dict:
        """获取POC数据集
        
        Returns:
            POC数据集
        """
        with open(self.poc_dataset_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def update_cve_dataset(self, cves: List[Dict]) -> bool:
        """更新CVE数据集
        
        Args:
            cves: CVE列表
        
        Returns:
            是否更新成功
        """
        try:
            dataset = {
                "cves": cves,
                "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(self.cve_dataset_path, 'w', encoding='utf-8') as f:
                json.dump(dataset, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception as e:
            print(f"更新CVE数据集失败: {str(e)}")
            return False
    
    def update_vulnerability_patterns(self, patterns: List[Dict]) -> bool:
        """更新漏洞模式数据集
        
        Args:
            patterns: 漏洞模式列表
        
        Returns:
            是否更新成功
        """
        try:
            dataset = {
                "patterns": patterns,
                "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(self.vulnerability_patterns_path, 'w', encoding='utf-8') as f:
                json.dump(dataset, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception as e:
            print(f"更新漏洞模式数据集失败: {str(e)}")
            return False
    
    def update_poc_dataset(self, pocs: List[Dict]) -> bool:
        """更新POC数据集
        
        Args:
            pocs: POC列表
        
        Returns:
            是否更新成功
        """
        try:
            dataset = {
                "pocs": pocs,
                "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(self.poc_dataset_path, 'w', encoding='utf-8') as f:
                json.dump(dataset, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception as e:
            print(f"更新POC数据集失败: {str(e)}")
            return False
    
    def import_cve_from_nvd(self, year: int) -> Tuple[bool, int]:
        """从NVD导入CVE数据
        
        Args:
            year: 年份
        
        Returns:
            (是否导入成功, 导入数量)
        """
        try:
            # 使用NVD导入器导入CVE数据
            cves = self.nvd_importer.import_cves(year)
            
            if cves:
                # 获取现有CVE数据
                existing_dataset = self.get_cve_dataset()
                existing_cves = existing_dataset.get("cves", [])
                
                # 去重
                existing_cve_ids = {cve.get("id") for cve in existing_cves}
                new_cves = [cve for cve in cves if cve.get("id") not in existing_cve_ids]
                
                # 合并数据
                combined_cves = existing_cves + new_cves
                
                # 更新数据集
                success = self.update_cve_dataset(combined_cves)
                return success, len(new_cves)
            
            return False, 0
        except Exception as e:
            print(f"从NVD导入CVE失败: {str(e)}")
            return False, 0
    
    def crawl_latest_cves(self, days: int = 7) -> Tuple[bool, int]:
        """爬取最新的CVE数据
        
        Args:
            days: 最近几天
        
        Returns:
            (是否爬取成功, 爬取数量)
        """
        try:
            # 使用CVE爬虫爬取最新CVE
            cves = self.cve_crawler.crawl_latest_cves(days)
            
            if cves:
                # 获取现有CVE数据
                existing_dataset = self.get_cve_dataset()
                existing_cves = existing_dataset.get("cves", [])
                
                # 去重
                existing_cve_ids = {cve.get("id") for cve in existing_cves}
                new_cves = [cve for cve in cves if cve.get("id") not in existing_cve_ids]
                
                # 合并数据
                combined_cves = existing_cves + new_cves
                
                # 更新数据集
                success = self.update_cve_dataset(combined_cves)
                return success, len(new_cves)
            
            return False, 0
        except Exception as e:
            print(f"爬取CVE失败: {str(e)}")
            return False, 0
    
    def search_cve(self, query: str) -> List[Dict]:
        """搜索CVE
        
        Args:
            query: 搜索关键词
        
        Returns:
            匹配的CVE列表
        """
        dataset = self.get_cve_dataset()
        cves = dataset.get("cves", [])
        
        # 简单的关键词匹配
        results = []
        for cve in cves:
            if (query.lower() in cve.get("id", "").lower() or
                query.lower() in cve.get("description", "").lower() or
                any(query.lower() in ref.lower() for ref in cve.get("references", []))):
                results.append(cve)
        
        return results
    
    def search_vulnerability_patterns(self, vulnerability_type: str) -> List[Dict]:
        """搜索漏洞模式
        
        Args:
            vulnerability_type: 漏洞类型
        
        Returns:
            匹配的漏洞模式列表
        """
        dataset = self.get_vulnerability_patterns()
        patterns = dataset.get("patterns", [])
        
        return [pattern for pattern in patterns if pattern.get("type") == vulnerability_type]
    
    def search_poc(self, vulnerability_type: str) -> List[Dict]:
        """搜索POC
        
        Args:
            vulnerability_type: 漏洞类型
        
        Returns:
            匹配的POC列表
        """
        dataset = self.get_poc_dataset()
        pocs = dataset.get("pocs", [])
        
        return [poc for poc in pocs if poc.get("vulnerability_type") == vulnerability_type]
    
    def export_dataset(self, output_dir: str, dataset_type: str) -> bool:
        """导出数据集
        
        Args:
            output_dir: 输出目录
            dataset_type: 数据集类型 (cve, patterns, poc)
        
        Returns:
            是否导出成功
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            if dataset_type == "cve":
                dataset = self.get_cve_dataset()
                output_path = os.path.join(output_dir, "cve_dataset.json")
            elif dataset_type == "patterns":
                dataset = self.get_vulnerability_patterns()
                output_path = os.path.join(output_dir, "vulnerability_patterns.json")
            elif dataset_type == "poc":
                dataset = self.get_poc_dataset()
                output_path = os.path.join(output_dir, "poc_dataset.json")
            else:
                return False
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(dataset, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception as e:
            print(f"导出数据集失败: {str(e)}")
            return False
    
    def import_dataset(self, input_path: str, dataset_type: str) -> bool:
        """导入数据集
        
        Args:
            input_path: 输入文件路径
            dataset_type: 数据集类型 (cve, patterns, poc)
        
        Returns:
            是否导入成功
        """
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                dataset = json.load(f)
            
            if dataset_type == "cve":
                return self.update_cve_dataset(dataset.get("cves", []))
            elif dataset_type == "patterns":
                return self.update_vulnerability_patterns(dataset.get("patterns", []))
            elif dataset_type == "poc":
                return self.update_poc_dataset(dataset.get("pocs", []))
            else:
                return False
        except Exception as e:
            print(f"导入数据集失败: {str(e)}")
            return False
    
    def get_dataset_statistics(self) -> Dict:
        """获取数据集统计信息
        
        Returns:
            数据集统计信息
        """
        cve_dataset = self.get_cve_dataset()
        patterns_dataset = self.get_vulnerability_patterns()
        poc_dataset = self.get_poc_dataset()
        
        return {
            "cve": {
                "count": len(cve_dataset.get("cves", [])),
                "last_updated": cve_dataset.get("last_updated")
            },
            "vulnerability_patterns": {
                "count": len(patterns_dataset.get("patterns", [])),
                "last_updated": patterns_dataset.get("last_updated")
            },
            "poc": {
                "count": len(poc_dataset.get("pocs", [])),
                "last_updated": poc_dataset.get("last_updated")
            }
        }

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict, List
from tqdm import tqdm
from .base import BaseETL

class CWEETL(BaseETL):
    """CWE数据ETL处理器"""

    ETL_NAME = "cwe"

    CWE_NAMESPACES = {
        'ns': 'http://cwe.mitre.org/cwe-6'
    }

    def __init__(self, connection=None):
        super().__init__(connection)
        self._print_header()

    def _print_header(self) -> None:
        """打印美化标题"""
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     CWE 数据入库                         ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  数据源: CWE XML (弱点枚举)                             ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def process(self, data_path: str) -> bool:
        """处理CWE数据"""
        data_path_obj = Path(data_path)

        if data_path_obj.is_file():
            xml_files = [data_path_obj]
        else:
            xml_files = list(data_path_obj.glob("*.xml"))
            if not xml_files:
                xml_files = list(data_path_obj.glob("cwec/*.xml"))

        if not xml_files:
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║  ✗ 未找到CWE XML文件: {data_path:<36} ║")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            return False

        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║  📂 发现 {len(xml_files)} 个CWE文件                              ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")

        for xml_file in xml_files:
            print(f"\n║  📄 处理: {xml_file.name}")
            print("╠══════════════════════════════════════════════════════════════╣")
            self._process_xml_file(xml_file)

        self._print_summary()
        return True

    def _print_summary(self) -> None:
        """打印美化汇总"""
        total = self.records_processed
        inserted = self.records_inserted
        skipped = self.records_skipped
        success_rate = (inserted / total * 100) if total > 0 else 0

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                     CWE 数据入库完成                     ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  总处理: {total:>6} 条                                              ║")
        print(f"║  插入:   {inserted:>6} 条  ({success_rate:.1f}%)                               ║")
        print(f"║  跳过:   {skipped:>6} 条                                              ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    def _process_xml_file(self, xml_file: Path) -> None:
        """处理单个XML文件"""
        tree = ET.parse(xml_file)
        root = tree.getroot()

        weaknesses = root.findall('.//ns:Weakness', self.CWE_NAMESPACES)

        print(f"║  📊 发现 {len(weaknesses)} 个CWE条目                               ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        for weakness in tqdm(weaknesses, desc="  处理进度", unit="CWE", ncols=70):
            self.records_processed += 1
            cwe_data = self._extract_cwe_data(weakness)

            if cwe_data and self._insert_cwe(cwe_data):
                self.records_inserted += 1

                cve_cwes = self._extract_cve_cwe_relations(weakness, cwe_data['cwe_id'])
                for rel in cve_cwes:
                    if self._insert_cve_cwe_relation(rel):
                        self.records_inserted += 1
            else:
                self.records_skipped += 1

    def _extract_cwe_data(self, weakness: ET.Element) -> Optional[Dict]:
        """提取CWE数据"""
        try:
            cwe_id = weakness.get('ID')
            if not cwe_id:
                return None

            name_elem = weakness.find('ns:Name', self.CWE_NAMESPACES)
            name = name_elem.text if name_elem is not None else ''

            abstraction_elem = weakness.find('ns:Abstraction', self.CWE_NAMESPACES)
            abstraction = abstraction_elem.text if abstraction_elem is not None else ''

            status_elem = weakness.find('ns:Status', self.CWE_NAMESPACES)
            status = status_elem.text if status_elem is not None else ''

            desc_elem = weakness.find('ns:Description', self.CWE_NAMESPACES)
            description = desc_elem.text if desc_elem is not None else ''

            return {
                'cwe_id': f'CWE-{cwe_id}',
                'name': name,
                'weakness_abstraction': abstraction,
                'status': status,
                'description': description
            }
        except Exception as e:
            print(f"提取CWE数据失败: {e}")
            return None

    def _extract_cve_cwe_relations(self, weakness: ET.Element, cwe_id: str) -> List[Dict]:
        """提取CVE-CWE关联"""
        relations = []

        related_vulnerabilities = weakness.find('ns:RelatedVulnerabilities', self.CWE_NAMESPACES)
        if related_vulnerabilities is None:
            return relations

        for rel_vuln in related_vulnerabilities.findall('ns:RelatedVulnerability', self.CWE_NAMESPACES):
            cve_id = rel_vuln.get('CVEID')
            if cve_id:
                is_primary = rel_vuln.get('Nature', '') == 'Primary'
                relations.append({
                    'cve_id': cve_id,
                    'cwe_id': cwe_id,
                    'is_primary': is_primary
                })

        return relations

    def _insert_cwe(self, cwe_data: Dict) -> bool:
        """插入CWE"""
        query = """
            INSERT INTO cwe (cwe_id, name, weakness_abstraction, status, description)
            VALUES (%(cwe_id)s, %(name)s, %(weakness_abstraction)s, %(status)s, %(description)s)
            ON CONFLICT (cwe_id) DO UPDATE SET
                name = EXCLUDED.name,
                weakness_abstraction = EXCLUDED.weakness_abstraction,
                status = EXCLUDED.status,
                description = EXCLUDED.description
        """
        try:
            self.conn.execute(query, cwe_data)
            return True
        except Exception as e:
            self.records_skipped += 1
            return False

    def _insert_cve_cwe_relation(self, rel_data: Dict) -> bool:
        """插入CVE-CWE关联"""
        query = """
            INSERT INTO cve_cwe (cve_id, cwe_id, is_primary)
            VALUES (%(cve_id)s, %(cwe_id)s, %(is_primary)s)
            ON CONFLICT (cve_id, cwe_id) DO UPDATE SET
                is_primary = EXCLUDED.is_primary
        """
        try:
            self.conn.execute(query, rel_data)
            return True
        except Exception as e:
            self.records_skipped += 1
            return False

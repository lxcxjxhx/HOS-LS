"""NVD适配器单元测试"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path


class TestNVDVulnerability:
    """测试NVD漏洞数据类"""

    def test_nvd_vulnerability_creation(self):
        """测试NVDVulnerability创建"""
        from src.scanner.nvd_adapter import NVDVulnerability

        vuln = NVDVulnerability(
            cve_id="CVE-2021-44228",
            description="Log4j RCE vulnerability",
            cvss_score=10.0,
            severity="CRITICAL",
            kev_exploited=True,
            exploit_count=5,
            poc_stars=100,
            affected_versions=["2.0.0", "2.1.0"],
            fix_version="2.17.0"
        )

        assert vuln.cve_id == "CVE-2021-44228"
        assert vuln.cvss_score == 10.0
        assert vuln.severity == "CRITICAL"
        assert vuln.kev_exploited is True
        assert vuln.exploit_count == 5
        assert vuln.poc_stars == 100
        assert vuln.affected_versions == ["2.0.0", "2.1.0"]
        assert vuln.fix_version == "2.17.0"

    def test_nvd_vulnerability_defaults(self):
        """测试NVDVulnerability默认值"""
        from src.scanner.nvd_adapter import NVDVulnerability

        vuln = NVDVulnerability(
            cve_id="CVE-2021-44228",
            description="Log4j RCE",
            cvss_score=10.0,
            severity="CRITICAL",
            kev_exploited=False,
            exploit_count=0,
            poc_stars=0,
            affected_versions=[]
        )

        assert vuln.fix_version is None
        assert vuln.references is None
        assert vuln.cwe_ids is None
        assert vuln.published_date is None


class TestNVDAdapter:
    """测试NVD适配器"""

    @patch('src.scanner.nvd_adapter.SQLiteConnection')
    def test_adapter_initialization(self, mock_conn_class):
        """测试适配器初始化"""
        from src.scanner.nvd_adapter import NVDAdapter

        mock_conn = MagicMock()
        mock_conn.table_exists.return_value = True
        mock_conn.is_connected.return_value = True
        mock_conn.get_vulnerability_stats.return_value = {'cve': 1000, 'cvss': 1000}
        mock_conn_class.get_instance.return_value = mock_conn

        adapter = NVDAdapter()

        assert adapter.is_available() is True
        assert adapter.get_db_type() == 'sqlite'

    @patch('src.scanner.nvd_adapter.SQLiteConnection')
    def test_adapter_unavailable_when_no_tables(self, mock_conn_class):
        """测试表不存在时适配器不可用"""
        from src.scanner.nvd_adapter import NVDAdapter

        mock_conn = MagicMock()
        mock_conn.table_exists.return_value = False
        mock_conn_class.get_instance.return_value = mock_conn

        adapter = NVDAdapter()

        assert adapter.is_available() is False

    def test_adapter_returns_empty_when_unavailable(self):
        """测试不可用时返回空列表"""
        from src.scanner.nvd_adapter import NVDAdapter

        adapter = NVDAdapter()
        adapter._initialized = False
        adapter._query_engine = None

        result = adapter.scan_library("apache", "log4j", "2.14.0", min_score=5.0)

        assert result == []


class TestNVDAdapterSingleton:
    """测试NVD适配器单例"""

    def test_get_nvd_adapter_returns_same_instance(self):
        """测试获取同一实例"""
        from src.scanner.nvd_adapter import get_nvd_adapter, reset_nvd_adapter

        reset_nvd_adapter()
        adapter1 = get_nvd_adapter()
        adapter2 = get_nvd_adapter()

        assert adapter1 is adapter2

    def test_reset_nvd_adapter(self):
        """测试重置适配器"""
        from src.scanner.nvd_adapter import get_nvd_adapter, reset_nvd_adapter

        reset_nvd_adapter()
        adapter1 = get_nvd_adapter()
        reset_nvd_adapter()
        adapter2 = get_nvd_adapter()

        assert adapter1 is not adapter2

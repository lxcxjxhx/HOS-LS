"""库匹配器NVD集成单元测试"""

import pytest
from unittest.mock import Mock, patch, MagicMock


class TestLibraryMatcherNVD:
    """测试库匹配器NVD集成"""

    def test_detect_python_libraries(self):
        """测试Python库检测"""
        from src.scanner.library_matcher import LibraryMatcher, LibraryInfo

        matcher = LibraryMatcher()
        code = """
import requests
import django
from flask import Flask
import numpy as np
"""
        libraries = matcher.detect_libraries(code, 'python')

        library_names = [lib.name for lib in libraries]
        assert 'requests' in library_names
        assert 'django' in library_names
        assert 'flask' in library_names
        assert 'numpy' in library_names

    def test_detect_javascript_libraries(self):
        """测试JavaScript库检测"""
        from src.scanner.library_matcher import LibraryMatcher

        matcher = LibraryMatcher()
        code = """
const axios = require('axios');
import React from 'react';
import Vue from 'vue';
"""
        libraries = matcher.detect_libraries(code, 'javascript')

        library_names = [lib.name for lib in libraries]
        assert 'axios' in library_names
        assert 'react' in library_names
        assert 'vue' in library_names

    def test_detect_java_libraries(self):
        """测试Java库检测"""
        from src.scanner.library_matcher import LibraryMatcher

        matcher = LibraryMatcher()
        code = """
import org.springframework.boot;
import com.google.gson;
import apache.log4j;
"""
        libraries = matcher.detect_libraries(code, 'java')

        library_names = [lib.name for lib in libraries]
        assert 'springframework' in library_names or 'spring' in str(library_names).lower()
        assert 'gson' in library_names
        assert 'log4j' in library_names

    def test_severity_mapping(self):
        """测试严重级别映射"""
        from src.scanner.library_matcher import LibraryMatcher

        matcher = LibraryMatcher()

        assert matcher._map_severity('CRITICAL') == 'CRITICAL'
        assert matcher._map_severity('HIGH') == 'HIGH'
        assert matcher._map_severity('MEDIUM') == 'MEDIUM'
        assert matcher._map_severity('LOW') == 'LOW'
        assert matcher._map_severity('INVALID') == 'MEDIUM'
        assert matcher._map_severity('') == 'MEDIUM'
        assert matcher._map_severity(None) == 'MEDIUM'


class TestLibraryMatcherFallback:
    """测试库匹配器回退机制"""

    def test_fallback_when_nvd_unavailable(self):
        """测试NVD不可用时的回退"""
        from src.scanner.library_matcher import LibraryMatcher

        matcher = LibraryMatcher()
        matcher._nvd_available = False

        libraries = [
            LibraryMatcher.__dataclass__.name.__get__(LibraryMatcher.__dataclass__(), None) if False else LibraryInfo(name='requests', version='2.25.0')
        ]

        matcher._vulnerability_db = {
            'requests': [
                LibraryMatcher.__dataclass__(
                    cve_id='CVE-2021-23337',
                    library_name='requests',
                    affected_versions=['<2.26.0'],
                    severity='MEDIUM',
                    description='Requests vulnerability'
                )
            ]
        }

        from src.scanner.library_matcher import LibraryInfo as LI
        test_libs = [LI(name='requests', version='2.25.0')]

        vulnerabilities = matcher._match_via_json(test_libs)

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].cve_id == 'CVE-2021-23337'


class TestLibraryInfo:
    """测试库信息类"""

    def test_library_info_creation(self):
        """测试LibraryInfo创建"""
        from src.scanner.library_matcher import LibraryInfo

        lib = LibraryInfo(
            name='requests',
            version='2.25.0',
            source='requirements.txt',
            metadata={' ecosystem': 'pip'}
        )

        assert lib.name == 'requests'
        assert lib.version == '2.25.0'
        assert lib.source == 'requirements.txt'
        assert lib.metadata == {' ecosystem': 'pip'}

    def test_library_info_defaults(self):
        """测试LibraryInfo默认值"""
        from src.scanner.library_matcher import LibraryInfo

        lib = LibraryInfo(name='requests')

        assert lib.version is None
        assert lib.source == ''
        assert lib.metadata == {}


class TestLibraryVulnerability:
    """测试库漏洞类"""

    def test_library_vulnerability_creation(self):
        """测试LibraryVulnerability创建"""
        from src.scanner.library_matcher import LibraryVulnerability

        vuln = LibraryVulnerability(
            cve_id='CVE-2021-44228',
            library_name='log4j',
            affected_versions=['2.0.0', '2.14.1'],
            severity='CRITICAL',
            description='Log4j RCE',
            fix_version='2.17.0',
            metadata={'cvss_score': 10.0}
        )

        assert vuln.cve_id == 'CVE-2021-44228'
        assert vuln.library_name == 'log4j'
        assert vuln.affected_versions == ['2.0.0', '2.14.1']
        assert vuln.severity == 'CRITICAL'
        assert vuln.description == 'Log4j RCE'
        assert vuln.fix_version == '2.17.0'
        assert vuln.metadata == {'cvss_score': 10.0}

    def test_library_vulnerability_defaults(self):
        """测试LibraryVulnerability默认值"""
        from src.scanner.library_matcher import LibraryVulnerability

        vuln = LibraryVulnerability(
            cve_id='CVE-2021-44228',
            library_name='log4j',
            affected_versions=[],
            severity='MEDIUM',
            description='Test'
        )

        assert vuln.fix_version is None
        assert vuln.metadata == {}

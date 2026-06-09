"""行号验证集成测试"""

import pytest
import os
from pathlib import Path
from src.ai.pure_ai.line_number_mapper import LineNumberMapper, LineNumberValidator


class TestLineNumberValidationIntegration:
    """行号验证集成测试"""

    PROJECT_PATH = Path("c:/1AAA_PROJECT/HOS/HOS-LS/real-project/bizspring-open-main")
    REPORT_PATH = Path("c:/1AAA_PROJECT/HOS/HOS-LS/HOS-LS/report.html")

    def test_all_matched_vulnerabilities_preserved(self):
        """测试所有匹配的漏洞都被保留（关键集成测试）"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper)

        test_content = """package com.example;

public class Test {
    private String value;

    public void setValue(String v) {
        this.value = v;
    }
}"""

        file_path = "Test.java"
        mapper.record_file_snapshot(file_path, test_content)
        validator.record_file_snapshot(file_path, test_content)

        test_cases = [
            ("Test.java:2", "package com.example;"),
            ("Test.java:10", "public class Test {"),
            ("Test.java:5", "private String value;"),
        ]

        for location, expected_code in test_cases:
            result = validator.verify_and_correct(location, expected_code, tolerance=5)
            assert result["is_valid"] is True, f"漏洞应被保留: {location}"
            assert result["verified_line"] is not None

    def test_real_project_line_numbers(self):
        """测试真实项目中的行号"""
        project_path = Path("c:/1AAA_PROJECT/HOS/HOS-LS/real-project/bizspring-open-main")

        if not project_path.exists():
            pytest.skip("Project path not found")

        jackson_config = project_path / "bizspring-base/bizspring-base-core/src/main/java/cn/bizspring/cloud/common/core/config/JacksonConfig.java"

        if not jackson_config.exists():
            pytest.skip("JacksonConfig.java not found")

        content = jackson_config.read_text(encoding="utf-8")

        if "builder.locale(Locale.CHINA)" not in content:
            pytest.skip("builder.locale not found in file")

        mapper = LineNumberMapper()
        mapper.record_file_snapshot(str(jackson_config), content)

        matched_line, match_status, candidates = mapper.find_matching_line(
            "builder.locale(Locale.CHINA);", content, ai_reported_line=28
        )

        assert matched_line > 0, "Should find builder.locale in the file"
        assert match_status in ["EXACT", "ADJUSTED"]


def test_integration_with_real_files():
    """使用真实文件进行集成测试"""
    project_path = Path("c:/1AAA_PROJECT/HOS/HOS-LS/real-project/bizspring-open-main")

    if not project_path.exists():
        pytest.skip("Project path not found")

    config_files = list(project_path.glob("**/config/*.java"))[:3]

    if not config_files:
        pytest.skip("No config files found")

    mapper = LineNumberMapper()

    for config_file in config_files:
        content = config_file.read_text(encoding="utf-8")
        mapper.record_file_snapshot(str(config_file), content)

        assert len(content) > 0


def test_real_project_validation():
    """测试真实项目的验证逻辑"""
    project_path = Path("c:/1AAA_PROJECT/HOS/HOS-LS/real-project/bizspring-open-main")

    if not project_path.exists():
        pytest.skip("Project path not found")

    jackson_config = project_path / "bizspring-base/bizspring-base-core/src/main/java/cn/bizspring/cloud/common/core/config/JacksonConfig.java"

    if not jackson_config.exists():
        pytest.skip("JacksonConfig.java not found")

    content = jackson_config.read_text(encoding="utf-8")

    mapper = LineNumberMapper()
    validator = LineNumberValidator(mapper, tolerance=5)

    validator.record_file_snapshot(str(jackson_config), content)

    result = validator.verify_and_correct(
        str(jackson_config) + ":28",
        "builder.locale(Locale.CHINA);",
        tolerance=5
    )

    assert result["is_valid"] is True
    assert result["verified_line"] is not None
    assert result["verified_line"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

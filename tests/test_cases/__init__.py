"""测试用例模块

定义测试用例的数据结构。
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TestCase:
    """测试用例"""

    id: str
    name: str
    description: str
    category: str
    language: str
    code: str
    expected_findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "language": self.language,
            "code": self.code,
            "expected_findings": self.expected_findings,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TestCase":
        """从字典创建"""
        return cls(**data)


class TestCaseLoader:
    """测试用例加载器"""

    def __init__(self, test_cases_dir: Path) -> None:
        self.test_cases_dir = test_cases_dir
        self._test_cases: Dict[str, TestCase] = {}

    def load_all(self) -> Dict[str, TestCase]:
        """加载所有测试用例"""
        if self._test_cases:
            return self._test_cases

        # 按类别加载
        for category_dir in self.test_cases_dir.iterdir():
            if not category_dir.is_dir():
                continue

            category = category_dir.name
            for test_file in category_dir.glob("*.py"):
                test_case = self._load_test_case(test_file, category)
                if test_case:
                    self._test_cases[test_case.id] = test_case

        return self._test_cases

    def _load_test_case(self, test_file: Path, category: str) -> Optional[TestCase]:
        """加载单个测试用例"""
        try:
            code = test_file.read_text(encoding="utf-8")

            # 从文件名生成 ID
            test_id = f"{category}_{test_file.stem}"

            return TestCase(
                id=test_id,
                name=test_file.stem.replace("_", " ").title(),
                description=f"Test case for {category}",
                category=category,
                language=test_file.suffix[1:],
                code=code,
            )
        except Exception:
            return None

    def get_by_category(self, category: str) -> List[TestCase]:
        """按类别获取测试用例"""
        test_cases = self.load_all()
        return [tc for tc in test_cases.values() if tc.category == category]

    def get_by_language(self, language: str) -> List[TestCase]:
        """按语言获取测试用例"""
        test_cases = self.load_all()
        return [tc for tc in test_cases.values() if tc.language == language]

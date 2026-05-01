"""LineNumber映射器模块

提供AI报告行号与实际代码行号的映射验证功能。

核心策略：校正优先，排除次之
- 任何通过代码片段匹配到的漏洞都会被保留
- tolerance 仅用于决定是否显示警告，不用于排除
"""

import re
from typing import Optional, Tuple, List, Dict, Any


class LineNumberMapper:
    """LineNumber映射器

    通过代码片段匹配验证和校正AI报告的行号。
    """

    def __init__(self):
        self._snapshots: Dict[str, str] = {}

    def record_file_snapshot(self, file_path: str, file_content: str = None) -> None:
        """记录文件快照

        Args:
            file_path: 文件路径
            file_content: 文件内容（如果为None则从文件读取）
        """
        if file_content is None:
            try:
                from pathlib import Path
                file_content = Path(file_path).read_text(encoding='utf-8')
            except Exception:
                file_content = ""
        self._snapshots[file_path] = file_content

    def get_file_content(self, file_path: str) -> str:
        """获取文件内容

        Args:
            file_path: 文件路径

        Returns:
            文件内容
        """
        return self._snapshots.get(file_path, "")

    def parse_location(self, location: str) -> Tuple[Optional[str], Optional[int]]:
        """解析location字符串获取文件路径和行号

        Args:
            location: 形如 "path/to/file.java:26" 或 "path/to/file.java:1-24" 的字符串

        Returns:
            (文件路径, 行号或起始行号)
        """
        if not location:
            return None, None

        patterns = [
            r'^([A-Za-z]:.+?):(\d+)$',
            r'^(.+?):(\d+)$',
            r'^(.+?):(\d+)-(\d+)$',
        ]

        for pattern in patterns:
            match = re.match(pattern, location, re.IGNORECASE)
            if match:
                file_path = match.group(1)
                if len(match.groups()) >= 2 and match.group(2):
                    try:
                        line_num = int(match.group(2))
                        return file_path, line_num
                    except ValueError:
                        pass
                return file_path, None

        return location, None

    def is_invalid_location(self, location: str) -> bool:
        """检查location是否包含无效的行号标记

        Args:
            location: location字符串

        Returns:
            是否为无效location
        """
        if not location:
            return True

        invalid_patterns = [
            r':line$',
            r':Line$',
            r':LINE$',
            r':行号未知$',
            r':行号$',
            r':未知$',
            r':unknown$',
            r':Unknown$',
        ]

        for pattern in invalid_patterns:
            if re.search(pattern, location, re.IGNORECASE):
                return True

        return False

    def find_matching_line(
        self,
        code_snippet: str,
        file_content: str,
        ai_reported_line: int = None,
        search_range: int = 50
    ) -> Tuple[int, str, List[int]]:
        """在文件内容中查找与代码片段匹配的行

        Args:
            code_snippet: 要匹配的代码片段
            file_content: 文件全部内容
            ai_reported_line: AI报告的行号（用于判断是EXACT还是ADJUSTED）
            search_range: 上下搜索范围（行数）

        Returns:
            (匹配行号, 匹配状态, 候选行号列表)
            匹配状态: "EXACT", "ADJUSTED", "NOT_FOUND"
            - EXACT: 在AI报告的行号处精确匹配
            - ADJUSTED: 在其他位置匹配到（行号有偏差但已校正）
            - NOT_FOUND: 找不到匹配
        """
        if not code_snippet or not file_content:
            return -1, "NOT_FOUND", []

        lines = file_content.split('\n')
        snippet_stripped = code_snippet.strip()

        if not snippet_stripped:
            return -1, "NOT_FOUND", []

        all_candidates = []

        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if line_stripped and snippet_stripped == line_stripped:
                all_candidates.append(i + 1)

        if not all_candidates:
            return -1, "NOT_FOUND", []

        if ai_reported_line and ai_reported_line in all_candidates:
            return ai_reported_line, "EXACT", all_candidates
        else:
            return all_candidates[0], "ADJUSTED", all_candidates

    def calculate_line_deviation(
        self,
        ai_reported_line: int,
        actual_line: int
    ) -> int:
        """计算AI报告行号与实际行号的偏差

        Args:
            ai_reported_line: AI报告的行号
            actual_line: 实际匹配到的行号

        Returns:
            偏差行数（绝对值）
        """
        if ai_reported_line <= 0 or actual_line <= 0:
            return -1
        return abs(ai_reported_line - actual_line)

    def is_within_tolerance(
        self,
        deviation: int,
        tolerance: int
    ) -> bool:
        """检查偏差是否在容忍范围内

        Args:
            deviation: 偏差行数
            tolerance: 容忍度

        Returns:
            是否在容忍范围内
        """
        if tolerance <= 0:
            return deviation == 0
        return deviation <= tolerance

    def _is_valid_vulnerability_line(self, line_content: str, line_number: int, total_lines: int = None) -> tuple[bool, str]:
        """检查行内容是否为有效的漏洞位置

        强制规则：
        1. 不能是空行
        2. 不能是单行注释
        3. 不能是多行注释开始
        4. 如果行号 < 10，不能是 package/import
        5. 类级别注解通常不在前10行

        Args:
            line_content: 行内容
            line_number: 行号
            total_lines: 总行数

        Returns:
            (是否有效, 原因)
        """
        if not line_content or not line_content.strip():
            return False, "空行不能作为漏洞位置"

        stripped = line_content.strip()

        if stripped.startswith("//"):
            return False, "单行注释不能作为漏洞位置"

        if "/*" in stripped and "*/" not in stripped and not stripped.endswith("*/"):
            return False, "多行注释开始不能作为漏洞位置"

        if line_number < 10:
            if stripped.startswith("package ") or stripped.startswith("import "):
                return False, f"行{line_number}是package/import声明，不能作为漏洞位置"

            class_annotations = ["@Data", "@RefreshScope", "@Configuration", "@Service", "@Component",
                                 "@Controller", "@RestController", "@Repository", "@Bean"]
            for ann in class_annotations:
                if stripped.startswith(ann):
                    return False, f"行{line_number}是类级别注解@{ann}，通常不在前10行"

        return True, "VALID"

    def _is_comment_or_import(self, line_content: str) -> bool:
        """检查行内容是否为注释或import/package声明

        Args:
            line_content: 行内容

        Returns:
            是否为注释或import/package
        """
        if not line_content or not line_content.strip():
            return True

        stripped = line_content.strip()

        if stripped.startswith("//"):
            return True

        if stripped.startswith("/*") or stripped.startswith("*"):
            return True

        if stripped.startswith("package ") or stripped.startswith("import "):
            return True

        return False

    def validate_vulnerability_location(self, line_number: int, line_content: str,
                                        vulnerability_type: str = "") -> tuple[bool, str]:
        """验证漏洞位置是否与漏洞类型匹配

        Args:
            line_number: 行号
            line_content: 行内容
            vulnerability_type: 漏洞类型

        Returns:
            (是否匹配, 原因)
        """
        is_valid, reason = self._is_valid_vulnerability_line(line_content, line_number)
        if not is_valid:
            return False, reason

        if not vulnerability_type:
            return True, "VALID"

        type_lower = vulnerability_type.lower()

        if "annotation" in type_lower:
            if not any(ann in line_content for ann in ["@", "Annotation"]):
                return False, "该行不包含注解，与漏洞类型不匹配"
            return True, "VALID"

        if "configuration" in type_lower or "config" in type_lower:
            if not any(kw in line_content.lower() for kw in ["config", "properties", "@", "configuration"]):
                return False, "该行不包含配置相关代码，与漏洞类型不匹配"
            return True, "VALID"

        if "refreshscope" in type_lower or "refresh" in type_lower:
            if "@RefreshScope" not in line_content and "refresh" not in line_content.lower():
                return False, "该行不包含@RefreshScope或refresh相关代码"
            return True, "VALID"

        if "data" in type_lower and "lombok" in type_lower:
            if "@Data" not in line_content and "lombok" not in line_content.lower():
                return False, "该行不包含@Data或lombok相关代码"
            return True, "VALID"

        return True, "VALID"


class LineNumberValidator:
    """LineNumber验证器

    核心原则：校正优先，排除次之
    - 任何通过代码片段匹配到的漏洞都会被保留
    - tolerance 仅用于决定是否显示警告和标记状态
    """

    DEFAULT_TOLERANCE = 10

    def __init__(self, mapper: LineNumberMapper, tolerance: int = None):
        """初始化验证器

        Args:
            mapper: LineNumberMapper实例
            tolerance: 行号偏差容忍度（默认5），仅用于显示警告，不用于排除
        """
        self.mapper = mapper
        self._snapshots: Dict[str, str] = {}
        self._tolerance = tolerance if tolerance is not None else self.DEFAULT_TOLERANCE

    @property
    def tolerance(self) -> int:
        return self._tolerance

    def record_file_snapshot(self, file_path: str, file_content: str = None) -> None:
        """记录文件快照

        Args:
            file_path: 文件路径
            file_content: 文件内容（如果为None则从文件读取）
        """
        if file_content is None:
            try:
                from pathlib import Path
                file_content = Path(file_path).read_text(encoding='utf-8')
            except Exception:
                file_content = ""
        self._snapshots[file_path] = file_content

    def get_file_content(self, file_path: str) -> str:
        """获取文件内容

        Args:
            file_path: 文件路径

        Returns:
            文件内容
        """
        return self._snapshots.get(file_path, "")

    def verify_and_correct(
        self,
        location: str,
        code_snippet: str = None,
        tolerance: int = None
    ) -> Dict[str, Any]:
        """验证并校正行号（校正优先模式）

        核心逻辑：
        1. 如果代码片段在文件中找到匹配 → 校正行号并保留漏洞
        2. 只有代码片段完全找不到时 → 标记为UNVERIFIED，但仍保留
        3. tolerance 仅用于决定是否显示警告，不用于排除

        Args:
            location: AI报告的位置（格式：文件路径:行号）
            code_snippet: 代码片段（可选）
            tolerance: 行号偏差容忍度（覆盖默认值）

        Returns:
            验证结果字典，包含:
            - ai_reported_line: AI报告的行号
            - verified_line: 校正后的行号（必定有值）
            - line_match_status: 匹配状态（EXACT/ADJUSTED/UNVERIFIED/NO_SNIPPET）
            - code_snippet: 代码片段
            - deviation: 偏差行数
            - is_valid: 是否有效（找到匹配即为True，不用于排除）
            - warning_message: 警告信息（如有）
            - candidate_lines: 候选行号列表（用于UNVERIFIED）
        """
        effective_tolerance = tolerance if tolerance is not None else self._tolerance

        file_path, ai_line = self.mapper.parse_location(location)

        result = {
            'ai_reported_line': ai_line,
            'verified_line': ai_line,
            'line_match_status': 'NOT_FOUND',
            'code_snippet': code_snippet or '',
            'deviation': 0,
            'is_valid': True,
            'warning_message': None,
            'ai_hallucination_warning': False,
            'candidate_lines': []
        }

        if ai_line is None:
            result['line_match_status'] = 'INVALID_LOCATION'
            result['is_valid'] = False
            result['warning_message'] = '无效的位置格式，请人工复核'
            return result

        file_content = self.get_file_content(file_path)
        if not file_content:
            result['line_match_status'] = 'NO_SNAPSHOT'
            result['warning_message'] = '文件快照不存在，请人工复核'
            return result

        if code_snippet:
            matched_line, match_status, candidates = self.mapper.find_matching_line(
                code_snippet, file_content, ai_line
            )
            result['line_match_status'] = match_status
            result['code_snippet'] = code_snippet
            result['candidate_lines'] = candidates

            if matched_line > 0:
                result['verified_line'] = matched_line
                deviation = self.mapper.calculate_line_deviation(ai_line, matched_line)
                result['deviation'] = deviation

                if match_status == "EXACT":
                    result['is_valid'] = True
                    result['warning_message'] = None
                else:
                    if deviation > effective_tolerance:
                        result['line_match_status'] = 'UNVERIFIED'
                        result['is_valid'] = True
                        result['warning_message'] = f'🚨 行号偏差过大（偏差{deviation}行，超过容忍范围{effective_tolerance}行），已自动标记为需人工复核'
                    else:
                        result['is_valid'] = True
                        result['warning_message'] = f'行号已自动校正（偏差{deviation}行）'
            else:
                result['verified_line'] = ai_line
                result['deviation'] = 0
                result['is_valid'] = True
                result['ai_hallucination_warning'] = True
                result['warning_message'] = '🚨 AI幻觉警告：代码片段在文件中不存在，请人工复核'
        else:
            result['line_match_status'] = 'UNVERIFIED'
            result['verified_line'] = ai_line
            result['is_valid'] = False
            result['ai_hallucination_warning'] = True
            result['warning_message'] = '🚨 AI幻觉警告：未提供代码片段，无法验证行号准确性，已拒绝该发现'

        return result

"""LineNumber映射器模块

提供AI报告行号与实际代码行号的映射验证功能。

核心策略：校正优先，排除次之
- 任何通过代码片段匹配到的漏洞都会被保留
- tolerance 仅用于决定是否显示警告，不用于排除
"""

import re
import difflib
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
        search_range: int = 200
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

        if ai_reported_line and ai_reported_line in all_candidates:
            return ai_reported_line, "EXACT", all_candidates

        if all_candidates:
            return all_candidates[0], "ADJUSTED", all_candidates

        stripped_candidates = []
        snippet_normalized = self._normalize_whitespace(snippet_stripped)
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if line_stripped:
                line_normalized = self._normalize_whitespace(line_stripped)
                if snippet_normalized == line_normalized:
                    stripped_candidates.append(i + 1)

        if stripped_candidates:
            if ai_reported_line and ai_reported_line in stripped_candidates:
                return ai_reported_line, "EXACT", stripped_candidates
            return stripped_candidates[0], "ADJUSTED", stripped_candidates

        fuzzy_candidates = self._fuzzy_search(
            snippet_stripped, lines,
            ai_reported_line if ai_reported_line else len(lines) // 2,
            search_range
        )

        if fuzzy_candidates:
            best_match = fuzzy_candidates[0]
            if ai_reported_line and best_match[0] == ai_reported_line:
                return best_match[0], "EXACT", [c[0] for c in fuzzy_candidates]
            return best_match[0], "ADJUSTED", [c[0] for c in fuzzy_candidates]

        return -1, "NOT_FOUND", []

    def _normalize_whitespace(self, text: str) -> str:
        """规范化空白字符

        Args:
            text: 输入文本

        Returns:
            规范化后的文本
        """
        return ' '.join(text.split())

    def _extract_keywords(self, snippet: str) -> List[str]:
        """从代码片段中提取关键词/标识符

        Args:
            snippet: 代码片段

        Returns:
            提取的关键词列表
        """
        keywords = []
        patterns = [
            r'@\w+',
            r'def\s+(\w+)',
            r'class\s+(\w+)',
            r'interface\s+(\w+)',
            r'var\s+(\w+)',
            r'val\s+(\w+)',
            r'let\s+(\w+)',
            r'\b(\w+)\s*\(',
            r'\bif\s*\(',
            r'\bfor\s*\(',
            r'\bwhile\s*\(',
            r'\breturn\s+',
            r'\bthrow\s+',
            r'\bnew\s+(\w+)',
        ]

        snippet_lower = snippet.lower()

        for pattern in patterns:
            matches = re.findall(pattern, snippet, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str) and len(match) > 2:
                    keywords.append(match.lower())

        identifier_pattern = r'\b[a-z][a-z0-9_]{2,}\b'
        words = re.findall(identifier_pattern, snippet_lower)
        for word in words:
            if word not in ['null', 'true', 'false', 'this', 'super', 'self', 'let', 'var', 'val', 'def', 'class', 'return', 'throw', 'new', 'if', 'for', 'while', 'else', 'elif', 'switch', 'case', 'break', 'continue']:
                if word not in keywords:
                    keywords.append(word)

        return keywords[:10]

    def _edit_distance_similarity(self, s1: str, s2: str) -> float:
        """计算两个字符串的编辑距离相似度

        Args:
            s1: 第一个字符串
            s2: 第二个字符串

        Returns:
            相似度分数 (0-1)
        """
        if not s1 or not s2:
            return 0.0

        len1, len2 = len(s1), len(s2)
        max_len = max(len1, len2)

        if max_len == 0:
            return 1.0

        distances = [[0] * (len2 + 1) for _ in range(len1 + 1)]

        for i in range(len1 + 1):
            distances[i][0] = i
        for j in range(len2 + 1):
            distances[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i-1] == s2[j-1] else 1
                distances[i][j] = min(
                    distances[i-1][j] + 1,
                    distances[i][j-1] + 1,
                    distances[i-1][j-1] + cost
                )

        edit_distance = distances[len1][len2]
        return 1.0 - (edit_distance / max_len)

    def _fuzzy_search(
        self,
        snippet: str,
        lines: List[str],
        center_line: int,
        search_range: int
    ) -> List[Tuple[int, float]]:
        """在指定范围内进行模糊搜索

        Args:
            snippet: 要匹配的代码片段
            lines: 文件所有行
            center_line: 中心行号（AI报告的行号）
            search_range: 搜索范围

        Returns:
            [(匹配行号, 相似度), ...] 按相似度降序排列
        """
        results = []
        start = max(0, center_line - 1 - search_range)
        end = min(len(lines), center_line - 1 + search_range)

        snippet_lower = snippet.lower()

        for i in range(start, end):
            line = lines[i]
            line_stripped = line.strip()

            if not line_stripped:
                continue

            if line_stripped == snippet:
                results.append((i + 1, 1.0))
                continue

            line_normalized = self._normalize_whitespace(line_stripped)
            snippet_normalized = self._normalize_whitespace(snippet)

            if line_normalized == snippet_normalized:
                results.append((i + 1, 0.95))
                continue

            matcher = difflib.SequenceMatcher(None, snippet_lower, line_stripped.lower())
            similarity = matcher.ratio()

            if similarity >= 0.80:
                results.append((i + 1, similarity))

        if not results:
            edit_results = []
            edit_start = max(0, center_line - 1 - search_range * 2)
            edit_end = min(len(lines), center_line - 1 + search_range * 2)

            for i in range(edit_start, edit_end):
                line = lines[i]
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                edit_sim = self._edit_distance_similarity(snippet, line_stripped)
                if edit_sim >= 0.5:
                    edit_results.append((i + 1, edit_sim))

            if edit_results:
                edit_results.sort(key=lambda x: (-x[1], x[0]))
                results.extend(edit_results)
                print(f"[DEBUG] 使用编辑距离后备方案，找到 {len(edit_results)} 个候选")
            else:
                keywords = self._extract_keywords(snippet)
                if keywords:
                    print(f"[DEBUG] 模糊匹配未找到，使用关键词后备方案，提取到关键词: {keywords}")
                    for i in range(start, end):
                        line = lines[i]
                        line_lower = line.lower()
                        if any(kw in line_lower for kw in keywords):
                            results.append((i + 1, 0.5))

        results.sort(key=lambda x: (-x[1], x[0]))
        if results:
            print(f"[DEBUG] 匹配完成，找到 {len(results)} 个候选，最佳匹配: 行{results[0][0]}, 相似度: {results[0][1]:.2f}")
        else:
            print(f"[DEBUG] 匹配完成，未找到任何匹配")
        return results

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

    def _detect_multiline_comment_blocks(self, file_content: str) -> List[Tuple[int, int]]:
        """检测文件中的所有多行注释块范围

        Args:
            file_content: 文件全部内容

        Returns:
            [(start_line, end_line), ...] 列表，行号从1开始
        """
        blocks = []
        lines = file_content.split('\n')
        in_comment = False
        comment_start = 0

        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()

            if not in_comment:
                if '/*' in stripped:
                    if '*/' not in stripped or stripped.index('/*') < stripped.index('*/'):
                        in_comment = True
                        comment_start = line_num
                    if '*/' in stripped and stripped.index('*/') > stripped.index('/*'):
                        blocks.append((comment_start, line_num))
                        in_comment = False
            else:
                if '*/' in stripped:
                    blocks.append((comment_start, line_num))
                    in_comment = False

        if in_comment:
            blocks.append((comment_start, len(lines)))

        return blocks

    def _is_in_multiline_comment(self, line_number: int, comment_blocks: List[Tuple[int, int]]) -> bool:
        """检查指定行号是否在多行注释块内

        Args:
            line_number: 行号（从1开始）
            comment_blocks: 多行注释块列表 [(start, end), ...]

        Returns:
            是否在注释块内
        """
        for start, end in comment_blocks:
            if start <= line_number <= end:
                return True
        return False

    def _is_valid_vulnerability_line(self, line_content: str, line_number: int, total_lines: int = None, comment_blocks: List[Tuple[int, int]] = None) -> tuple[bool, str]:
        """检查行内容是否为有效的漏洞位置

        强制规则：
        1. 不能是空行
        2. 不能是单行注释
        3. 不能是多行注释开始
        4. 不能在多行注释块内
        5. 如果行号 < 10，不能是 package/import
        6. 类级别注解通常不在前10行

        Args:
            line_content: 行内容
            line_number: 行号
            total_lines: 总行数
            comment_blocks: 多行注释块列表（可选）

        Returns:
            (是否有效, 原因)
        """
        if not line_content or not line_content.strip():
            return False, "空行不能作为漏洞位置"

        stripped = line_content.strip()

        if stripped.startswith("//"):
            return False, "单行注释不能作为漏洞位置"

        if comment_blocks and self._is_in_multiline_comment(line_number, comment_blocks):
            return False, f"行{line_number}在多行注释块内，不能作为漏洞位置"

        if "/*" in stripped and "*/" not in stripped and not stripped.endswith("*/"):
            return False, "多行注释开始不能作为漏洞位置"

        if line_number < 10:
            if stripped.startswith("package ") or stripped.startswith("import "):
                return False, f"行{line_number}是package/import声明，不能作为漏洞位置"

            critical_annotations = ["@Data", "@RefreshScope"]
            for ann in critical_annotations:
                if stripped.startswith(ann):
                    return False, f"行{line_number}是类级别注解@{ann}，通常不在前10行"

            config_annotations = ["@Configuration", "@Service", "@Component",
                                 "@Controller", "@RestController", "@Repository", "@Bean"]
            for ann in config_annotations:
                if stripped.startswith(ann):
                    return False, f"行{line_number}是类级别注解@{ann}，需确认是否与漏洞相关"

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

    def _find_nearest_valid_code_line(
        self,
        file_content: str,
        target_line: int,
        search_range: int = 10,
        comment_blocks: List[Tuple[int, int]] = None
    ) -> Optional[int]:
        """在目标行号附近搜索最近的有效代码行

        当AI报告的行号在注释块内时，自动搜索附近最近的实际可执行代码行。

        Args:
            file_content: 文件全部内容
            target_line: 目标行号（AI报告的行号）
            search_range: 搜索范围（上下各多少行）
            comment_blocks: 多行注释块列表

        Returns:
            最近的有效代码行号，如果未找到则返回None
        """
        lines = file_content.split('\n')
        total_lines = len(lines)

        if target_line < 1 or target_line > total_lines:
            return None

        for offset in range(0, search_range + 1):
            candidates = []

            if target_line - offset >= 1:
                candidates.append(target_line - offset)
            if offset != 0 and target_line + offset <= total_lines:
                candidates.append(target_line + offset)

            for line_num in sorted(candidates):
                line_content = lines[line_num - 1]
                stripped = line_content.strip()

                if not stripped:
                    continue

                if stripped.startswith("//"):
                    continue

                if stripped.startswith("*") and not (stripped.startswith("*/") or stripped.startswith("/*")):
                    continue

                if comment_blocks and self._is_in_multiline_comment(line_num, comment_blocks):
                    continue

                if stripped.startswith("/*"):
                    continue

                if stripped.endswith("*/") and "/*" not in stripped:
                    continue

                is_valid, reason = self._is_valid_vulnerability_line(
                    line_content, line_num, total_lines, comment_blocks
                )
                if is_valid:
                    print(f"[DEBUG] 注释块内行号校正: {target_line} -> {line_num} (偏移{abs(line_num - target_line)}行)")
                    return line_num

        return None

    def validate_vulnerability_location(self, line_number: int, line_content: str,
                                        vulnerability_type: str = "", comment_blocks: List[Tuple[int, int]] = None) -> tuple[bool, str]:
        """验证漏洞位置是否与漏洞类型匹配

        Args:
            line_number: 行号
            line_content: 行内容
            vulnerability_type: 漏洞类型
            comment_blocks: 多行注释块列表

        Returns:
            (是否匹配, 原因)
        """
        is_valid, reason = self._is_valid_vulnerability_line(line_content, line_number, comment_blocks=comment_blocks)
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

    DEFAULT_TOLERANCE = 5

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
        tolerance: int = None,
        code_graph_engine = None,
        finding_description: str = None
    ) -> Dict[str, Any]:
        """验证并校正行号（校正优先模式）

        核心逻辑：
        0. 检测并校正注释块内的行号
        1. 如果代码片段在文件中找到匹配 → 校正行号并保留漏洞
        2. 如果 AI 返回行号为 0 或无效，尝试用 CodeGraph 引擎二次校正
        3. 只有代码片段完全找不到时 → 标记为UNVERIFIED，但仍保留
        4. tolerance 仅用于决定是否显示警告，不用于排除

        Args:
            location: AI报告的位置（格式：文件路径:行号）
            code_snippet: 代码片段（可选）
            tolerance: 行号偏差容忍度（覆盖默认值）
            code_graph_engine: 代码图引擎实例（可选，用于二次行号校正）
            finding_description: 漏洞描述（可选，用于 CodeGraph 搜索关键词）

        Returns:
            验证结果字典，包含:
            - ai_reported_line: AI报告的行号
            - verified_line: 校正后的行号（必定有值）
            - line_match_status: 匹配状态（EXACT/ADJUSTED/UNVERIFIED/NO_SNIPPET/GRAPHCORRECTED/COMMENT_CORRECTED）
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

        file_content = self.get_file_content(file_path)
        if not file_content:
            result['line_match_status'] = 'NO_SNAPSHOT'
            result['warning_message'] = '文件快照不存在，请人工复核'
            return result

        comment_blocks = self.mapper._detect_multiline_comment_blocks(file_content)

        if ai_line and ai_line > 0 and comment_blocks:
            line_content_at_ai = ""
            lines = file_content.split('\n')
            if ai_line <= len(lines):
                line_content_at_ai = lines[ai_line - 1]

            is_in_comment, reason = self.mapper._is_valid_vulnerability_line(
                line_content_at_ai, ai_line, len(lines), comment_blocks
            )
            if not is_in_comment and "多行注释块内" in reason:
                print(f"[DEBUG] 检测到AI报告的行号{ai_line}在多行注释块内，开始搜索附近有效代码行")
                corrected_line = self.mapper._find_nearest_valid_code_line(
                    file_content, ai_line, search_range=10, comment_blocks=comment_blocks
                )
                if corrected_line and corrected_line != ai_line:
                    print(f"[DEBUG] 注释块行号校正成功: {ai_line} -> {corrected_line}")
                    result['ai_reported_line'] = ai_line
                    result['verified_line'] = corrected_line
                    result['line_match_status'] = 'COMMENT_CORRECTED'
                    result['is_valid'] = True
                    result['deviation'] = abs(corrected_line - ai_line)
                    result['warning_message'] = f'行号{ai_line}在注释块内，已自动校正到最近的有效代码行{corrected_line}'
                    ai_line = corrected_line
                else:
                    print(f"[DEBUG] 注释块行号校正失败: 在行号{ai_line}附近10行内未找到有效代码行")

        if ai_line is None or ai_line <= 0:
            if code_graph_engine is not None:
                graph_corrected_line = self._graph_based_line_correction(
                    code_graph_engine, file_path, file_content, finding_description, code_snippet
                )
                if graph_corrected_line > 0:
                    result['ai_reported_line'] = ai_line if ai_line else 0
                    result['verified_line'] = graph_corrected_line
                    result['line_match_status'] = 'GRAPHCORRECTED'
                    result['is_valid'] = True
                    result['warning_message'] = f'行号已通过代码图引擎校正: {graph_corrected_line}'
                    result['deviation'] = 0
                    return result

            result['ai_reported_line'] = ai_line if ai_line else 0
            result['line_match_status'] = 'INVALID_LOCATION'
            result['is_valid'] = False
            result['warning_message'] = '无效的位置格式，请人工复核'
            return result

        if code_snippet:
            matched_line, match_status, candidates = self.mapper.find_matching_line(
                code_snippet, file_content, ai_line
            )
            result['line_match_status'] = match_status
            result['code_snippet'] = code_snippet
            result['candidate_lines'] = candidates

            if matched_line > 0:
                deviation = self.mapper.calculate_line_deviation(ai_line, matched_line)
                result['deviation'] = deviation

                if match_status == "EXACT":
                    result['verified_line'] = matched_line
                    result['is_valid'] = True
                    result['warning_message'] = None
                else:
                    if deviation > effective_tolerance:
                        result['verified_line'] = ai_line
                        result['line_match_status'] = 'UNVERIFIED'
                        result['is_valid'] = True
                        result['warning_message'] = f'🚨 行号偏差过大（偏差{deviation}行，超过容忍范围{effective_tolerance}行），已自动标记为需人工复核'
                    else:
                        result['verified_line'] = matched_line
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

    def _graph_based_line_correction(self, code_graph_engine, file_path: str, file_content: str, finding_description: str, code_snippet: str) -> int:
        """利用 CodeGraph 引擎进行二次行号校正

        当 AI 返回行号为 0 时，通过代码图引擎搜索文件中的符号，
        结合漏洞描述和代码片段匹配最可能的行号。

        Args:
            code_graph_engine: 代码图引擎实例
            file_path: 文件路径
            file_content: 文件内容
            finding_description: 漏洞描述
            code_snippet: 代码片段

        Returns:
            校正后的行号，如果无法校正则返回 0
        """
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                nodes = loop.run_until_complete(code_graph_engine.get_nodes_by_file(file_path))
            finally:
                loop.close()

            if not nodes:
                return 0

            search_keywords = []
            if finding_description:
                for word in re.findall(r'[\u4e00-\u9fa5a-zA-Z_][\u4e00-\u9fa5a-zA-Z0-9_]*', finding_description):
                    if len(word) >= 3:
                        search_keywords.append(word.lower())

            if code_snippet:
                snippet_keywords = re.findall(r'[a-zA-Z_]\w*', code_snippet)
                for kw in snippet_keywords:
                    if len(kw) >= 3 and kw.lower() not in search_keywords:
                        search_keywords.append(kw.lower())

            keyword_vuln_patterns = [
                'auth', 'permission', 'security', 'access', 'tenant', 'context',
                'filter', 'interceptor', 'validator', 'csrf', 'token', 'session',
                'validate', 'check', 'verify', 'unauthorized', 'bypass', 'inject',
            ]
            for kw in keyword_vuln_patterns:
                if any(kw in k for k in search_keywords) and kw not in search_keywords:
                    search_keywords.append(kw)

            best_node = None
            best_score = 0

            for node in nodes:
                score = 0
                node_name = (node.get('symbol_name') or '').lower()
                node_type = node.get('symbol_type') or ''
                node_source = (node.get('source_code') or '').lower()

                for kw in search_keywords:
                    if kw in node_name:
                        score += 3
                    if kw in node_source:
                        score += 1

                if node_type in ('method', 'function') and any(
                    p in node_name for p in keyword_vuln_patterns
                ):
                    score += 2

                if score > best_score:
                    best_score = score
                    best_node = node

            if best_node and best_score >= 2:
                corrected_line = best_node.get('start_line', 0)
                if corrected_line > 0:
                    return corrected_line

            return 0
        except Exception:
            return 0


print("[DEBUG] 行号匹配范围已扩大到 ±200 行，阈值降至 0.65")

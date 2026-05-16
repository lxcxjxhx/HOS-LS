import re
from typing import Dict, List, Optional, Tuple

SAFE_PATTERNS = {
    r'Wrappers\.query\(': 'MyBatis-Plus预编译语句，安全',
    r'Wrappers\.lambdaQuery\(': 'MyBatis-Plus预编译语句，安全',
    r'#\{': 'MyBatis参数绑定，安全'
}

UNSAFE_PATTERNS = {
    r'\$\{': 'MyBatis字符串拼接，不安全'
}


def match_framework_patterns(code_content: str) -> Dict[str, List[Tuple[str, str]]]:
    """
    匹配代码中的框架安全模式

    Args:
        code_content: 代码内容字符串

    Returns:
        包含 safe 和 unsafe 匹配结果的字典
    """
    result = {
        'safe': [],
        'unsafe': []
    }

    for pattern, description in SAFE_PATTERNS.items():
        matches = re.finditer(pattern, code_content)
        for match in matches:
            result['safe'].append((pattern, description))

    for pattern, description in UNSAFE_PATTERNS.items():
        matches = re.finditer(pattern, code_content)
        for match in matches:
            result['unsafe'].append((pattern, description))

    return result


def check_safe_pattern(code_content: str) -> bool:
    """
    检查代码是否包含安全框架模式

    Args:
        code_content: 代码内容字符串

    Returns:
        是否包含至少一个安全模式
    """
    result = match_framework_patterns(code_content)
    return len(result['safe']) > 0


def check_unsafe_pattern(code_content: str) -> bool:
    """
    检查代码是否包含不安全框架模式

    Args:
        code_content: 代码内容字符串

    Returns:
        是否包含至少一个不安全模式
    """
    result = match_framework_patterns(code_content)
    return len(result['unsafe']) > 0

"""Schema验证器模块

提供Schema验证、自动修复和重试机制。
"""

import json
import re
from typing import Dict, Any, Optional, Callable, List
from src.ai.pure_ai.schema import (
    FINAL_DECISION_SCHEMA,
    VULNERABILITY_SCHEMA,
    ADVERSARIAL_SCHEMA,
    RISK_ENUMERATION_SCHEMA
)

class SchemaValidationError(Exception):
    """Schema验证异常"""
    pass

class SchemaValidator:
    """Schema验证器

    提供结构验证、自动修复和重试功能。
    """

    def __init__(self):
        self.schemas = {
            "final_decision": FINAL_DECISION_SCHEMA,
            "vulnerability": VULNERABILITY_SCHEMA,
            "adversarial": ADVERSARIAL_SCHEMA,
            "risk_enumeration": RISK_ENUMERATION_SCHEMA
        }

    def validate(self, data: Any, schema_name: str) -> tuple[bool, Optional[str]]:
        """验证数据是否符合Schema

        Args:
            data: 待验证的数据
            schema_name: Schema名称

        Returns:
            (是否通过, 错误信息)
        """
        schema = self.schemas.get(schema_name)
        if not schema:
            return True, None

        if not isinstance(data, dict):
            return False, f"Expected dict, got {type(data).__name__}"

        errors = self._validate_object(data, schema, "")
        if errors:
            return False, "; ".join(errors)
        return True, None

    def _validate_object(self, data: Dict, schema: Dict, path: str) -> List[str]:
        """递归验证对象

        Args:
            data: 待验证的数据
            schema: Schema定义
            path: 当前路径（用于错误信息）

        Returns:
            错误列表
        """
        errors = []

        required = schema.get("required", [])
        for field in required:
            if field not in data:
                errors.append(f"Missing required field: {path}.{field}")

        properties = schema.get("properties", {})
        for field, field_schema in properties.items():
            if field in data:
                field_value = data[field]
                field_type = field_schema.get("type")

                if field_type == "object":
                    if not isinstance(field_value, dict):
                        errors.append(f"Expected dict for {path}.{field}, got {type(field_value).__name__}")
                    elif "properties" in field_schema:
                        errors.extend(self._validate_object(field_value, field_schema, f"{path}.{field}"))
                elif field_type == "array":
                    if not isinstance(field_value, list):
                        errors.append(f"Expected array for {path}.{field}, got {type(field_value).__name__}")
                    elif "items" in field_schema:
                        for i, item in enumerate(field_value):
                            if isinstance(item, dict) and "properties" in field_schema["items"]:
                                errors.extend(self._validate_object(item, field_schema["items"], f"{path}.{field}[{i}]"))

        return errors

    def validate_with_fallback(self, data: Any, schema_name: str) -> Dict[str, Any]:
        """验证数据，如果不符合Schema则尝试修复

        Args:
            data: 待验证的数据
            schema_name: Schema名称

        Returns:
            修复后的数据
        """
        is_valid, error = self.validate(data, schema_name)
        if is_valid:
            return data

        print(f"[WARN] Schema validation failed for {schema_name}: {error}")
        print(f"[DEBUG] Attempting to fix structure...")

        fixed_data = self._fix_structure(data, schema_name)
        return fixed_data

    def _fix_structure(self, data: Any, schema_name: str) -> Dict[str, Any]:
        """尝试修复数据结构

        Args:
            data: 待修复的数据
            schema_name: Schema名称

        Returns:
            修复后的数据
        """
        schema = self.schemas.get(schema_name)
        if not schema or not isinstance(data, dict):
            return data

        fixed = {}

        for field, field_schema in schema.get("properties", {}).items():
            if field in data:
                fixed[field] = data[field]
            elif field in schema.get("required", []):
                fixed[field] = self._get_default_value(field_schema)

        for key in data:
            if key not in fixed:
                fixed[key] = data[key]

        return fixed

    def _get_default_value(self, field_schema: Dict) -> Any:
        """获取字段的默认值

        Args:
            field_schema: 字段Schema

        Returns:
            默认值
        """
        field_type = field_schema.get("type")

        if field_type == "object":
            return {}
        elif field_type == "array":
            return []
        elif field_type == "string":
            if "enum" in field_schema:
                return field_schema["enum"][0] if field_schema["enum"] else ""
            return ""
        elif field_type == "number":
            if "minimum" in field_schema:
                return field_schema["minimum"]
            return 0
        elif field_type == "boolean":
            return False

        return None

    def parse_json_response(self, response_text: str, schema_name: str) -> Optional[Dict[str, Any]]:
        """解析JSON响应

        Args:
            response_text: AI响应文本
            schema_name: Schema名称

        Returns:
            解析后的数据或None
        """
        try:
            json_str = self._extract_json(response_text)
            if not json_str:
                print(f"[WARN] No JSON found in response for {schema_name}")
                return None

            data = json.loads(json_str)
            validated_data = self.validate_with_fallback(data, schema_name)
            return validated_data

        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON parse error for {schema_name}: {e}")
            return self._emergency_fix(response_text, schema_name)
        except Exception as e:
            print(f"[ERROR] Unexpected error parsing {schema_name}: {e}")
            return None

    def _extract_json(self, text: str) -> Optional[str]:
        """从文本中提取JSON

        Args:
            text: 文本

        Returns:
            JSON字符串或None
        """
        patterns = [
            r'\{[^{}]*\}',
            r'\{[\s\S]*"final_findings"[\s\S]*\}',
            r'\{[\s\S]*"vulnerabilities"[\s\S]*\}',
            r'\{[\s\S]*"adversarial_analysis"[\s\S]*\}'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                try:
                    json.loads(match)
                    return match
                except:
                    continue

        return None

    def _emergency_fix(self, response_text: str, schema_name: str) -> Optional[Dict[str, Any]]:
        """紧急修复

        当JSON解析完全失败时，尝试从文本中提取信息

        Args:
            response_text: 响应文本
            schema_name: Schema名称

        Returns:
            修复后的数据
        """
        print(f"[DEBUG] Attempting emergency fix for {schema_name}")

        if schema_name == "final_decision":
            vulnerabilities = self._extract_vulnerabilities_from_text(response_text)
            if vulnerabilities:
                return {
                    "final_findings": vulnerabilities,
                    "summary": {
                        "total_vulnerabilities": len(vulnerabilities),
                        "valid_vulnerabilities": len(vulnerabilities),
                        "uncertain_vulnerabilities": 0,
                        "invalid_vulnerabilities": 0,
                        "high_severity_count": sum(1 for v in vulnerabilities if v.get("severity") == "HIGH"),
                        "medium_severity_count": sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM"),
                        "low_severity_count": sum(1 for v in vulnerabilities if v.get("severity") == "LOW")
                    }
                }

        return {"final_findings": [], "summary": {"total_vulnerabilities": 0}}

    def _extract_vulnerabilities_from_text(self, text: str) -> List[Dict]:
        """从文本中提取漏洞信息

        Args:
            text: 文本

        Returns:
            漏洞列表
        """
        vulnerabilities = []

        severity_keywords = {
            "CRITICAL": ["critical", "严重", "高危"],
            "HIGH": ["high", "高风险", "高"],
            "MEDIUM": ["medium", "中风险", "中"],
            "LOW": ["low", "低风险", "低"]
        }

        vulnerability_keywords = [
            "sql injection", "sql注入",
            "xss", "cross-site", "跨站",
            "command injection", "命令注入",
            "path traversal", "路径遍历",
            "ssrf", "服务器端请求伪造",
            "csrf", "跨站请求伪造",
            "authentication", "认证",
            "authorization", "授权",
            "sensitive data", "敏感数据",
            "hardcoded", "硬编码"
        ]

        for severity, keywords in severity_keywords.items():
            for keyword in keywords:
                if keyword.lower() in text.lower():
                    vulnerabilities.append({
                        "vulnerability": f"Detected {severity} issue",
                        "location": "Unknown (extracted from text)",
                        "severity": severity,
                        "status": "UNCERTAIN",
                        "confidence": "MEDIUM",
                        "evidence": text[:500],
                        "recommendation": "Manual review required",
                        "requires_human_review": True
                    })
                    break

        return vulnerabilities[:5]

def retry_with_validation(max_retries: int = 3):
    """重试装饰器

    Args:
        max_retries: 最大重试次数

    Returns:
        装饰器函数
    """
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    result = await func(*args, **kwargs)
                    validator = SchemaValidator()
                    is_valid, error = validator.validate(result, "final_decision")
                    if is_valid:
                        return result
                    print(f"[WARN] Attempt {attempt + 1} validation failed: {error}")
                    last_error = error
                except Exception as e:
                    last_error = e
                    print(f"[WARN] Attempt {attempt + 1} failed: {e}")

            print(f"[ERROR] All {max_retries} attempts failed. Last error: {last_error}")
            raise SchemaValidationError(f"Failed after {max_retries} attempts: {last_error}")

        return wrapper
    return decorator

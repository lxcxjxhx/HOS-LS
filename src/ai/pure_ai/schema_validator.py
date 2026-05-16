"""Schema验证器模块

提供Schema验证、自动修复和重试机制。
"""

import json
import re
import hashlib
from typing import Dict, Any, Optional, Callable, List, Tuple
from src.ai.pure_ai.schema import (
    FINAL_DECISION_SCHEMA,
    VULNERABILITY_SCHEMA,
    ADVERSARIAL_SCHEMA,
    RISK_ENUMERATION_SCHEMA,
    SignalState,
    LineMatchStatus
)
from src.ai.pure_ai.line_number_mapper import LineNumberMapper
from src.analysis.framework_patterns import match_framework_patterns, check_safe_pattern
from src.analysis.spel_parser import SpELParser
from src.analysis.bean_scanner import BeanScanner
from src.analysis.module_analyzer import ModuleAnalyzer
import yaml
import os

FORBIDDEN_PATTERNS = [
    r'^Unknown$',
    r'^未知$',
    r'^Unknown\s+risk',
    r'^未知\s+风险',
    r'Unable to determine',
    r'无法确定',
]

STRUCTURED_TAGS = [
    "SUSPICIOUS_PATTERN",
    "WEAK_SECURITY_SIGNAL",
    "NEEDS_VERIFICATION",
    "ARCHITECTURAL_RISK"
]

class SchemaValidationError(Exception):
    """Schema验证异常"""
    pass

class ForbiddenOutputError(Exception):
    """禁止的输出异常"""
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

    def validate_strict_output_contract(self, data: Dict[str, Any], schema_name: str) -> tuple[bool, List[str]]:
        """严格验证输出契约

        检查是否有禁止的Unknown输出，确保evidence结构完整。

        Args:
            data: 待验证的数据
            schema_name: Schema名称

        Returns:
            (是否通过, 错误列表)
        """
        errors = []

        forbidden_violations = self._check_forbidden_patterns(data)
        if forbidden_violations:
            errors.extend(forbidden_violations)

        evidence_errors = self._check_evidence_structure(data, schema_name)
        if evidence_errors:
            errors.extend(evidence_errors)

        signal_errors = self._check_signal_tracking(data, schema_name)
        if signal_errors:
            errors.extend(signal_errors)

        return len(errors) == 0, errors

    def _check_forbidden_patterns(self, data: Dict[str, Any], path: str = "") -> List[str]:
        """检查禁止的输出模式

        Args:
            data: 待检查的数据
            path: 当前路径

        Returns:
            错误列表
        """
        errors = []

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, str):
                    for pattern in FORBIDDEN_PATTERNS:
                        if re.search(pattern, value, re.IGNORECASE):
                            if value.strip() in STRUCTURED_TAGS:
                                continue
                            if value.count('Unknown') == 1 and len(value.split()) <= 2:
                                errors.append(f"Forbidden pattern at {current_path}: '{value}' - use STRUCTURED_TAGS instead")
                elif isinstance(value, (dict, list)):
                    errors.extend(self._check_forbidden_patterns(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                if isinstance(item, (dict, list)):
                    errors.extend(self._check_forbidden_patterns(item, current_path))

        return errors

    def _check_evidence_structure(self, data: Dict[str, Any], schema_name: str) -> List[str]:
        """检查evidence结构

        Args:
            data: 待检查的数据
            schema_name: Schema名称

        Returns:
            错误列表
        """
        errors = []

        evidence_required_schemas = {
            "final_decision": ["final_findings"],
            "vulnerability": ["vulnerabilities"],
            "adversarial": ["adversarial_analysis"],
            "risk_enumeration": ["risks"],
            "attack_chain": ["attack_chains"]
        }

        if schema_name not in evidence_required_schemas:
            return errors

        required_fields = evidence_required_schemas.get(schema_name, [])

        for field in required_fields:
            if field in data and isinstance(data[field], list):
                for i, item in enumerate(data[field]):
                    if isinstance(item, dict) and "evidence" in item:
                        evidence = item["evidence"]
                        if not isinstance(evidence, list):
                            errors.append(f"Evidence at {field}[{i}] must be array, got {type(evidence).__name__}")
                        elif len(evidence) == 0 and item.get("signal_state") not in ["REFINED", "NEW"]:
                            pass

        return errors

    def _check_signal_tracking(self, data: Dict[str, Any], schema_name: str) -> List[str]:
        """检查信号追踪结构

        Args:
            data: 待检查的数据
            schema_name: Schema名称

        Returns:
            错误列表
        """
        errors = []

        signal_tracking_schemas = {
            "vulnerability": ["vulnerabilities"],
            "risk_enumeration": ["risks"],
            "attack_chain": ["attack_chains"]
        }

        if schema_name not in signal_tracking_schemas:
            return errors

        if "signal_tracking" in data:
            tracking = data["signal_tracking"]
            if not isinstance(tracking, dict):
                errors.append("signal_tracking must be dict")
            else:
                base_fields = ["signals_confirmed", "signals_rejected", "signals_new"]
                if schema_name == "attack_chain":
                    expected_fields = base_fields
                else:
                    expected_fields = base_fields + ["signals_refined"]
                for field in expected_fields:
                    if field not in tracking:
                        errors.append(f"Missing signal_tracking.{field}")

        return errors

    def sanitize_forbidden_output(self, value: str) -> str:
        """将禁止的输出转换为结构化标签

        Args:
            value: 原始值

        Returns:
            替换后的值
        """
        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                if "risk" in value.lower():
                    return "WEAK_SECURITY_SIGNAL"
                return "SUSPICIOUS_PATTERN"
        return value

    def fix_unknown_outputs(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """修复禁止的Unknown输出

        Args:
            data: 待修复的数据

        Returns:
            修复后的数据
        """
        if isinstance(data, dict):
            fixed = {}
            for key, value in data.items():
                if isinstance(value, str):
                    fixed[key] = self.sanitize_forbidden_output(value)
                elif isinstance(value, (dict, list)):
                    fixed[key] = self.fix_unknown_outputs(value)
                else:
                    fixed[key] = value
            return fixed
        elif isinstance(data, list):
            return [self.fix_unknown_outputs(item) if isinstance(item, (dict, list)) else
                    self.sanitize_forbidden_output(item) if isinstance(item, str) else item
                    for item in data]
        return data

    def fix_invalid_locations(self, data: Dict[str, Any], schema_name: str = None) -> Dict[str, Any]:
        """修复无效的位置信息

        将包含 :line、:行号未知 等无效行号的位置尝试修复。

        Args:
            data: 待修复的数据
            schema_name: Schema名称（用于确定需要修复的字段）

        Returns:
            修复后的数据
        """
        if not isinstance(data, (dict, list)):
            return data

        invalid_patterns = [
            (r':line$', ':1'),
            (r':Line$', ':1'),
            (r':LINE$', ':1'),
            (r':行号未知$', ':1'),
            (r':行号$', ':1'),
            (r':未知$', ':1'),
            (r':unknown$', ':1'),
            (r':Unknown$', ':1'),
        ]

        def fix_location(location_str: str) -> str:
            """修复单个location字符串"""
            if not isinstance(location_str, str):
                return location_str
            for pattern, replacement in invalid_patterns:
                new_location = re.sub(pattern, replacement, location_str, flags=re.IGNORECASE)
                if new_location != location_str:
                    return new_location
            return location_str

        def fix_item(item):
            if isinstance(item, dict):
                fixed = {}
                for key, value in item.items():
                    if key == 'location' and isinstance(value, str):
                        fixed[key] = fix_location(value)
                    elif isinstance(value, (dict, list)):
                        fixed[key] = fix_item(value)
                    else:
                        fixed[key] = value
                return fixed
            elif isinstance(item, list):
                return [fix_item(i) if isinstance(i, (dict, list)) else
                        fix_location(i) if isinstance(i, str) else i
                        for i in item]
            return item

        return fix_item(data)

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
                    elif len(field_value) == 0:
                        pass
                    elif "items" in field_schema:
                        item_schema = field_schema["items"]
                        for i, item in enumerate(field_value):
                            if isinstance(item, dict) and "properties" in item_schema:
                                errors.extend(self._validate_object(item, item_schema, f"{path}.{field}[{i}]"))
                            if isinstance(item, dict) and "required" in item_schema:
                                for req_field in item_schema["required"]:
                                    if req_field not in item or item[req_field] is None or item[req_field] == "":
                                        errors.append(f"Missing required field: {path}.{field}[{i}].{req_field}")

        return errors

    def validate_with_fallback(self, data: Any, schema_name: str) -> Tuple[Dict[str, Any], bool]:
        """验证数据，如果不符合Schema则尝试修复（宽松模式）

        Args:
            data: 待验证的数据
            schema_name: Schema名称

        Returns:
            (修复后的数据, 是否通过验证)
        """
        max_retries = 2
        current_data = data
        validation_passed = False

        for attempt in range(max_retries + 1):
            is_valid, error = self.validate(current_data, schema_name)
            if is_valid:
                strict_valid, strict_errors = self.validate_strict_output_contract(current_data, schema_name)
                if not strict_valid:
                    print(f"[WARN] Strict output contract violations for {schema_name}: {strict_errors}")
                    current_data = self.fix_unknown_outputs(current_data)
                current_data = self.fix_invalid_locations(current_data, schema_name)
                validation_passed = True
                return current_data, True

            if attempt < max_retries:
                print(f"[DEBUG] Schema validation failed for {schema_name}: {error}")
                print(f"[DEBUG] Attempting to fix structure (attempt {attempt + 1}/{max_retries})...")
                current_data = self._fix_structure(current_data, schema_name)
                current_data = self.fix_unknown_outputs(current_data)
                current_data = self.fix_invalid_locations(current_data, schema_name)
                current_data = self._ensure_required_fields(current_data, schema_name)
            else:
                print(f"[WARN] Schema validation failed for {schema_name}: {error}")
                print(f"[WARN] Final attempt exhausted, returning fixed data (may be incomplete)")
                current_data = self._fix_structure(current_data, schema_name)
                current_data = self.fix_unknown_outputs(current_data)
                current_data = self.fix_invalid_locations(current_data, schema_name)
                current_data = self._ensure_required_fields(current_data, schema_name)

        return current_data, validation_passed

    def _ensure_required_fields(self, data: Dict[str, Any], schema_name: str) -> Dict[str, Any]:
        """确保schema必需的字段存在

        Args:
            data: 待修复的数据
            schema_name: Schema名称

        Returns:
            修复后的数据
        """
        if schema_name in ["vulnerability", "risk_enumeration", "attack_chain"]:
            if "signal_tracking" not in data or not isinstance(data.get("signal_tracking"), dict):
                print(f"[DEBUG] [Schema Fix] 确保 signal_tracking 字段存在 for {schema_name}")
                data["signal_tracking"] = {
                    "signals_new": 0,
                    "signals_confirmed": 0,
                    "signals_rejected": 0,
                    "signals_refined": 0
                }

        if schema_name == "vulnerability":
            if "vulnerabilities" not in data or not isinstance(data.get("vulnerabilities"), list):
                print(f"[DEBUG] [Schema Fix] 确保 vulnerabilities 字段存在 for {schema_name}")
                data["vulnerabilities"] = []

        return data

    def _get_empty_result_for_schema(self, schema_name: str) -> Dict[str, Any]:
        """根据schema类型返回空结果

        Args:
            schema_name: Schema名称

        Returns:
            对应schema的空结果
        """
        if schema_name == "vulnerability":
            return {
                "vulnerabilities": [],
                "signal_tracking": {
                    "signals_confirmed": 0,
                    "signals_rejected": 0,
                    "signals_refined": 0,
                    "signals_new": 0
                }
            }
        elif schema_name == "adversarial":
            return {
                "adversarial_analysis": [],
                "cross_agent_agreement": []
            }
        elif schema_name == "risk_enumeration":
            return {
                "risks": [],
                "signal_tracking": {
                    "signals_confirmed": 0,
                    "signals_rejected": 0,
                    "signals_refined": 0,
                    "signals_new": 0
                }
            }
        elif schema_name == "attack_chain":
            return {
                "attack_chains": [],
                "signal_tracking": {
                    "signals_confirmed": 0,
                    "signals_rejected": 0,
                    "signals_new": 0
                }
            }
        elif schema_name == "final_decision":
            return {
                "final_findings": [],
                "summary": {
                    "total_vulnerabilities": 0,
                    "valid_vulnerabilities": 0,
                    "uncertain_vulnerabilities": 0,
                    "invalid_vulnerabilities": 0,
                    "high_severity_count": 0,
                    "medium_severity_count": 0,
                    "low_severity_count": 0
                }
            }
        else:
            return {"unknown_schema": schema_name, "data": data if 'data' in dir() else {}}

    def validate_with_retry(self, data: Any, schema_name: str, max_retries: int = 3) -> Dict[str, Any]:
        """验证数据，如果不符合Schema则修复并重试验证

        Args:
            data: 待验证的数据
            schema_name: Schema名称
            max_retries: 最大修复次数

        Returns:
            修复后的数据
        """
        current_data = data
        for attempt in range(max_retries):
            is_valid, error = self.validate(current_data, schema_name)
            if is_valid:
                strict_valid, strict_errors = self.validate_strict_output_contract(current_data, schema_name)
                if strict_valid:
                    print(f"[DEBUG] Schema validation passed on attempt {attempt + 1}")
                    current_data = self.fix_invalid_locations(current_data, schema_name)
                    current_data = self._ensure_required_fields(current_data, schema_name)
                    return current_data
                print(f"[WARN] Strict contract violations on attempt {attempt + 1}: {strict_errors}")

            if attempt < max_retries - 1:
                print(f"[DEBUG] Fixing structure (attempt {attempt + 1}/{max_retries})...")
                current_data = self._fix_structure(current_data, schema_name)
                current_data = self.fix_unknown_outputs(current_data)
                current_data = self.fix_invalid_locations(current_data, schema_name)
            else:
                print(f"[WARN] Max retries reached for {schema_name}, using last fixed data")

        current_data = self._ensure_required_fields(current_data, schema_name)
        return current_data

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
            field_type = field_schema.get("type")
            is_required = field in schema.get("required", [])
            field_value = data.get(field)

            needs_fix = False
            if field not in data:
                needs_fix = True
            elif field_value is None:
                needs_fix = True
            elif field_type == "array" and not isinstance(field_value, list):
                needs_fix = True
            elif field_type == "object" and not isinstance(field_value, dict):
                needs_fix = True

            if not needs_fix:
                fixed[field] = field_value
                if field_type == "array" and isinstance(field_value, list):
                    item_schema = field_schema.get("items", {})
                    if "properties" in item_schema:
                        for i, item in enumerate(fixed[field]):
                            if isinstance(item, dict):
                                fixed[field][i] = self._fix_item_structure(item, item_schema, schema_name)
            elif is_required:
                if field == "signal_tracking":
                    if schema_name == "attack_chain":
                        items = data.get("attack_chains", [])
                        confirmed = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "CONFIRMED")
                        rejected = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "REJECTED")
                        refined = 0
                        new_count = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "NEW")
                        fixed[field] = {
                            "total_signals": len(items),
                            "signals_new": new_count,
                            "signals_confirmed": confirmed,
                            "signals_rejected": rejected
                        }
                    else:
                        items = data.get("vulnerabilities", data.get("risks", []))
                        confirmed = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "CONFIRMED")
                        rejected = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "REJECTED")
                        refined = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "REFINED")
                        new_count = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "NEW")
                        fixed[field] = {
                            "total_signals": len(items),
                            "signals_new": new_count,
                            "signals_confirmed": confirmed,
                            "signals_rejected": rejected,
                            "signals_refined": refined
                        }
                elif field == "risks" and "potential_vulnerabilities" in data:
                    converted_risks = self._convert_potential_to_risks(data.get("potential_vulnerabilities", []))
                    print(f"[DEBUG] [Schema Fix] 将 {len(converted_risks)} 个 potential_vulnerabilities 转换为 risks")
                    fixed[field] = converted_risks
                elif field == "vulnerabilities" and "potential_vulnerabilities" in data:
                    converted_vulns = self._convert_potential_to_risks(data.get("potential_vulnerabilities", []))
                    print(f"[DEBUG] [Schema Fix] 将 {len(converted_vulns)} 个 potential_vulnerabilities 转换为 vulnerabilities")
                    fixed[field] = converted_vulns
                else:
                    fixed[field] = self._get_default_value(field_schema)
        for key in data:
            if key not in fixed:
                fixed[key] = data[key]

        if "signal_tracking" in fixed and isinstance(fixed["signal_tracking"], dict):
            if not any(k in fixed["signal_tracking"] for k in ["signals_confirmed", "signals_rejected", "signals_refined", "signals_new"]):
                if schema_name == "attack_chain":
                    items = data.get("attack_chains", [])
                    confirmed = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "CONFIRMED")
                    rejected = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "REJECTED")
                    new_count = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "NEW")
                    fixed["signal_tracking"] = {
                        "total_signals": len(items),
                        "signals_new": new_count,
                        "signals_confirmed": confirmed,
                        "signals_rejected": rejected
                    }
                else:
                    items = data.get("vulnerabilities", data.get("risks", []))
                    confirmed = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "CONFIRMED")
                    rejected = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "REJECTED")
                    refined = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "REFINED")
                    new_count = sum(1 for v in items if isinstance(v, dict) and v.get("signal_state") == "NEW")
                    fixed["signal_tracking"] = {
                        "total_signals": len(items),
                        "signals_new": new_count,
                        "signals_confirmed": confirmed,
                        "signals_rejected": rejected,
                        "signals_refined": refined
                    }

        return fixed

    def _convert_potential_to_risks(self, potential_vulnerabilities: List[Dict]) -> List[Dict[str, Any]]:
        """将 potential_vulnerabilities 转换为 risks 格式"""
        risks = []
        for i, pv in enumerate(potential_vulnerabilities):
            if isinstance(pv, dict):
                risks.append({
                    "risk_type": pv.get("type", "Unknown Risk"),
                    "severity": self._infer_severity(pv),
                    "location": pv.get("location", "Unknown"),
                    "signal_id": pv.get("signal_id", f"RISK-POTENTIAL-{i}"),
                    "signal_state": "NEW",
                    "description": pv.get("description", ""),
                    "evidence": pv.get("evidence", [])
                })
        return risks

    def _fix_item_structure(self, item: Dict[str, Any], item_schema: Dict[str, Any], schema_name: str = None) -> Dict[str, Any]:
        """修复数组项的结构

        Args:
            item: 数组项数据
            item_schema: 数组项的Schema
            schema_name: Schema名称（用于特殊处理）

        Returns:
            修复后的数组项
        """
        fixed = dict(item)
        properties = item_schema.get("properties", {})
        required = item_schema.get("required", [])

        for prop, prop_schema in properties.items():
            needs_fix = False
            if prop not in fixed:
                needs_fix = True
            elif fixed[prop] is None or fixed[prop] == "":
                needs_fix = True

            if needs_fix and prop in required:
                if prop == "severity":
                    fixed[prop] = self._infer_severity(item)
                elif prop == "signal_tracking":
                    fixed[prop] = {
                        "signal_id": item.get("risk_id", "unknown"),
                        "state": "NEW",
                        "created_at": datetime.now().isoformat()
                    }
                elif prop == "attack_chain_name" and schema_name == "adversarial":
                    chain_name = item.get("chain_name", "")
                    if not chain_name:
                        chain_name = item.get("name", "")
                    if not chain_name or chain_name == "unknown":
                        signal_id = item.get("signal_id", "")
                        if signal_id and signal_id != "unknown":
                            chain_name = signal_id
                        else:
                            chain_name = "CHAIN"
                    fixed[prop] = chain_name
                elif prop == "evidence" and isinstance(fixed.get("reason"), str):
                    fixed[prop] = [{
                        "type": "code_line",
                        "location": item.get("location", "unknown"),
                        "reason": fixed["reason"],
                        "confidence": 0.5
                    }]
                elif prop == "signal_id" and schema_name == "risk_enumeration":
                    risk_id = item.get("risk_id")
                    if risk_id and risk_id != "unknown":
                        fixed[prop] = risk_id
                    else:
                        risk_type = item.get('risk_type', 'unknown')
                        location = item.get('location', '')
                        unique_str = f"{risk_type}:{location}"
                        short_hash = hashlib.md5(unique_str.encode()).hexdigest()[:6]
                        fixed[prop] = f"RISK-{risk_type}-{short_hash}"
                elif prop == "signal_id" and schema_name == "adversarial":
                    chain_name = item.get("chain_name", "")
                    if not chain_name or chain_name == "unknown":
                        chain_name = fixed.get("attack_chain_name", "")
                    if chain_name and chain_name != "unknown":
                        fixed[prop] = f"SIGNAL-{chain_name}"
                    else:
                        fixed[prop] = item.get("id", f"SIGNAL-unknown")
                elif prop == "signal_type":
                    fixed[prop] = item.get("signal_type", item.get("type", "risk"))
                elif prop == "original_agent":
                    fixed[prop] = item.get("original_agent", item.get("agent", "unknown"))
                elif prop == "current_state":
                    current = item.get("current_state", "NEW")
                    if current not in [s.value for s in SignalState]:
                        current = "NEW"
                    fixed[prop] = current
                elif prop == "evidence_chain":
                    if not isinstance(fixed.get("evidence_chain"), list):
                        fixed[prop] = item.get("evidence_chain", [])
                else:
                    fixed[prop] = self._get_default_value(prop_schema)

        for prop, prop_schema in properties.items():
            if prop in fixed and isinstance(fixed[prop], list):
                if prop_schema.get("type") == "array" and "items" in prop_schema:
                    item_schema_inner = prop_schema["items"]
                    if isinstance(item_schema_inner, dict) and "properties" in item_schema_inner:
                        fixed_items = []
                        for inner_item in fixed[prop]:
                            if isinstance(inner_item, dict):
                                fixed_items.append(self._fix_item_structure(inner_item, item_schema_inner, schema_name))
                            else:
                                fixed_items.append(inner_item)
                        fixed[prop] = fixed_items

        return fixed

    def _infer_severity(self, item: Dict[str, Any]) -> str:
        """从risk_type或description推断severity

        Args:
            item: 数组项数据

        Returns:
            推断的severity值
        """
        risk_type = item.get("risk_type", "").upper()
        description = item.get("description", "").upper()
        title = item.get("title", "").upper()

        combined_text = f"{risk_type} {description} {title}"

        high_keywords = ["SQL", "INJECT", "XSS", "CSRF", "COMMAND", "RCE", "PRIVILEGE",
                         "AUTHENTICATION", "CREDENTIAL", "SECRET", "KEY", "PASSWORD",
                         "UNSAFE", "DESERIALIZ"]
        for kw in high_keywords:
            if kw in combined_text:
                return "HIGH"

        medium_keywords = ["WEAK", "DEFAULT", "SUSPICIOUS", "PATTERN", "MISSING",
                          "INSUFFICIENT", "HARDCODED", "CONFIGURATION", "BROKEN",
                          "INSECURE", "PATH", "TRAVERSAL"]
        for kw in medium_keywords:
            if kw in combined_text:
                return "MEDIUM"

        low_keywords = ["INFO", "LOGGING", "DEBUG", "REMEDIATION", "BEST", "PRACTICE"]
        for kw in low_keywords:
            if kw in combined_text:
                return "LOW"

        return "INFO"

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
                emergency_result = self._emergency_fix(response_text, schema_name)
                if emergency_result:
                    print(f"[DEBUG] [Fallback] Using text extraction result for {schema_name}")
                    return emergency_result
                return None

            data = json.loads(json_str)
            validated_data, is_valid = self.validate_with_fallback(data, schema_name)

            if self._is_result_empty(validated_data, schema_name):
                print(f"[WARN] [Fallback] Validated data is empty for {schema_name}, trying text extraction")
                emergency_result = self._emergency_fix(response_text, schema_name)
                if emergency_result:
                    print(f"[DEBUG] [Fallback] Using text extraction result for {schema_name}")
                    return emergency_result

            return validated_data

        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON parse error for {schema_name}: {e}")
            emergency_result = self._emergency_fix(response_text, schema_name)
            if emergency_result:
                print(f"[DEBUG] [Fallback] Using text extraction after JSON error for {schema_name}")
                return emergency_result
            return None
        except Exception as e:
            print(f"[ERROR] Unexpected error parsing {schema_name}: {e}")
            emergency_result = self._emergency_fix(response_text, schema_name)
            if emergency_result:
                print(f"[DEBUG] [Fallback] Using text extraction after exception for {schema_name}")
                return emergency_result
            return None

    def _is_result_empty(self, data: Optional[Dict[str, Any]], schema_name: str) -> bool:
        """检查验证结果是否为空

        Args:
            data: 验证后的数据
            schema_name: Schema名称

        Returns:
            是否为空
        """
        if not data:
            return True

        if schema_name == "risk_enumeration":
            risks = data.get('risks', [])
            return len(risks) == 0

        elif schema_name == "vulnerability":
            vulns = data.get('vulnerabilities', [])
            return len(vulns) == 0

        elif schema_name == "adversarial":
            chains = data.get('adversarial_analysis', [])
            return len(chains) == 0

        elif schema_name == "final_decision":
            findings = data.get('final_findings', [])
            return len(findings) == 0

        return False

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

        elif schema_name == "risk_enumeration":
            risks = self._extract_risks_from_text(response_text)
            print(f"[DEBUG] [Emergency Fix] Extracted {len(risks)} risks from raw text for {schema_name}")
            if risks:
                return {
                    "risks": risks,
                    "signal_tracking": {
                        "total_signals": len(risks),
                        "signals_new": len(risks),
                        "signals_confirmed": 0,
                        "signals_rejected": 0,
                        "signals_refined": 0
                    }
                }

        elif schema_name == "adversarial":
            chains = self._extract_chains_from_text(response_text)
            if chains:
                return {
                    "adversarial_analysis": chains,
                    "signal_tracking": {
                        "total_signals": len(chains),
                        "signals_new": len(chains),
                        "signals_confirmed": 0,
                        "signals_rejected": 0
                    }
                }

        elif schema_name == "vulnerability":
            vulnerabilities = self._extract_vulnerabilities_from_text(response_text)
            if vulnerabilities:
                return {
                    "vulnerabilities": vulnerabilities,
                    "signal_tracking": {
                        "total_signals": len(vulnerabilities),
                        "signals_new": len(vulnerabilities),
                        "signals_confirmed": 0,
                        "signals_rejected": 0,
                        "signals_refined": 0
                    }
                }

        return None

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

    def _extract_risks_from_text(self, text: str) -> List[Dict]:
        """从文本中提取风险信息（用于risk_enumeration schema）

        当JSON解析失败时，从原始文本中提取风险信号

        Args:
            text: 响应文本

        Returns:
            风险列表
        """
        risks = []
        counter = 0

        severity_map = {
            "CRITICAL": ["critical", "严重", "高危", "严重漏洞"],
            "HIGH": ["high", "高风险", "高", "高危"],
            "MEDIUM": ["medium", "中风险", "中", "中危"],
            "LOW": ["low", "低风险", "低", "低危"],
            "INFO": ["info", "信息", "信息性"]
        }

        vuln_keywords = [
            "SQL注入", "SQL injection", "sql注入",
            "XSS", "跨站脚本", "cross-site scripting",
            "命令注入", "command injection", "命令执行",
            "路径遍历", "path traversal", "目录遍历",
            "SSRF", "服务器端请求伪造",
            "CSRF", "跨站请求伪造",
            "认证绕过", "authentication bypass",
            "授权绕过", "authorization bypass",
            "敏感信息泄露", "sensitive information leak",
            "硬编码", "hardcoded", "硬编码凭证",
            "反序列化", "deserialization", "反序列化漏洞",
            "越权", "privilege", "权限提升",
            "会话管理", "session management",
            "中间人攻击", "MITM", "man in the middle",
            "XML外部实体", "XXE", "xml external entity",
            "模板注入", "SSTI", "template injection",
            "代码注入", "code injection",
            "文件上传", "file upload", "任意文件上传",
            "未授权访问", "unauthorized access",
            "密码策略", "password policy", "弱密码",
            "JWT", "token泄露", "token leak",
            "CORS", "跨域", "cross-origin",
            "API安全", "api security",
            "注入", "injection"
        ]

        text_lower = text.lower()

        for severity, severity_terms in severity_map.items():
            for term in severity_terms:
                if term.lower() in text_lower:
                    for vuln_kw in vuln_keywords:
                        if vuln_kw.lower() in text_lower:
                            counter += 1
                            location_match = re.search(r'([A-Za-z]:\\[^:\s]+|/[^\s:]+):(\d+)', text)
                            location = location_match.group(0) if location_match else "Unknown location"

                            code_snippet_match = re.search(r'[`"\']([^`"\']{{3,100}})[`"\']', text)
                            code_snippet = code_snippet_match.group(1) if code_snippet_match else ""

                            risks.append({
                                "risk_type": f"{severity} - {vuln_kw}",
                                "vuln_type": "security_vuln",
                                "severity": severity,
                                "confidence": 0.5,
                                "location": location,
                                "description": f"检测到{severity}级别安全问题: {vuln_kw}",
                                "potential_impact": f"可能导致{severity}级别的安全风险",
                                "cvss_score": "N/A",
                                "signal_id": f"RISK-TEXT-{counter:03d}",
                                "signal_state": "NEW",
                                "evidence": [{
                                    "type": "code_line",
                                    "location": location,
                                    "reason": f"文本分析发现: {vuln_kw}",
                                    "confidence": 0.5,
                                    "code_snippet": code_snippet
                                }],
                                "requires_human_review": True
                            })
                            break
                    break

        print(f"[DEBUG] [Text Extraction] Found {len(risks)} potential risks in text")
        return risks[:10]

    def _extract_chains_from_text(self, text: str) -> List[Dict]:
        """从文本中提取攻击链信息（用于adversarial schema）

        Args:
            text: 响应文本

        Returns:
            攻击链列表
        """
        chains = []

        chain_keywords = [
            "攻击链", "attack chain", "攻击路径",
            "利用链", "exploitation chain", "利用路径",
            "漏洞组合", "vulnerability combination",
            "链式攻击", "chained attack"
        ]

        text_lower = text.lower()
        for kw in chain_keywords:
            if kw.lower() in text_lower:
                chains.append({
                    "chain_name": "Extracted Attack Chain",
                    "attack_chain_description": text[:500],
                    "signal_id": "CHAIN-TEXT-001",
                    "signal_state": "UNCERTAIN",
                    "confidence": 0.5,
                    "attack_prerequisites": "需要进一步分析",
                    "attack_steps": ["从文本提取的攻击链信息，需要人工复核"],
                    "potential_impact": "可能导致多层次安全风险",
                    "estimated_cvss": "N/A",
                    "requires_human_review": True
                })
                break

        return chains[:3]

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


class LineNumberValidator:
    """LineNumber验证器

    验证和校正AI报告的行号，确保漏洞位置准确。
    """

    DEFAULT_CONFIG_PATH = "hos-ls.yaml"

    def __init__(self, tolerance: int = None, project_root: str = None):
        self.tolerance = self._load_tolerance(tolerance)
        self.mapper = LineNumberMapper()
        self._spel_parser = None
        self._project_root = project_root

    def _load_tolerance(self, tolerance: int = None) -> int:
        """从配置文件加载tolerance值

        Args:
            tolerance: 直接传入的tolerance值，如果不为None则优先使用

        Returns:
            tolerance值
        """
        if tolerance is not None:
            return tolerance

        try:
            config_path = self.DEFAULT_CONFIG_PATH
            if not os.path.exists(config_path):
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                config_path = os.path.join(project_root, "hos-ls.yaml")

            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    validation_config = config.get("validation", {})
                    tolerance_value = validation_config.get("line_number_tolerance", None)
                    if tolerance_value is not None and tolerance_value > 0:
                        return tolerance_value
        except Exception:
            pass

        return 10

    def validate_location(self, vulnerability: dict, file_content: str) -> dict:
        """验证并校正行号

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            扩展后的漏洞数据
        """
        result = dict(vulnerability)

        location = vulnerability.get("location", "")
        evidence = vulnerability.get("evidence", [])
        code_snippet = ""
        for ev in evidence:
            if isinstance(ev, dict) and ev.get("code_snippet"):
                code_snippet = ev["code_snippet"]
                break

        ai_reported_line = -1
        _, parsed_line = self.mapper.parse_location(location)
        if parsed_line is not None:
            ai_reported_line = parsed_line

        result["ai_reported_line"] = ai_reported_line

        if not file_content:
            result["verified_line"] = -1
            result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
            result["candidate_lines"] = []
            return result

        actual_line, match_status, candidates = self.find_actual_line(vulnerability, file_content)
        result["verified_line"] = actual_line
        result["candidate_lines"] = candidates

        if actual_line == -1:
            result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
            return result

        if match_status == "EXACT":
            deviation = self.mapper.calculate_line_deviation(ai_reported_line, actual_line)
            if self.mapper.is_within_tolerance(deviation, self.tolerance):
                result["line_match_status"] = LineMatchStatus.EXACT.value
            else:
                if self.tolerance == 0:
                    result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
                else:
                    result["line_match_status"] = LineMatchStatus.ADJUSTED.value
        elif match_status == "FUZZY":
            deviation = self.mapper.calculate_line_deviation(ai_reported_line, actual_line)
            if self.tolerance == 0:
                result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
            else:
                result["line_match_status"] = LineMatchStatus.ADJUSTED.value
        elif match_status == "ADJUSTED":
            result["line_match_status"] = LineMatchStatus.ADJUSTED.value
        elif match_status == "REPORTED":
            result["line_match_status"] = LineMatchStatus.EXACT.value
        else:
            result["line_match_status"] = LineMatchStatus.UNVERIFIED.value

        # 添加操作类型验证
        result["operation_verification"] = self._verify_operation_type_consistency(vulnerability, file_content)
        
        # 添加框架安全模式验证
        result["framework_safe"] = False
        framework_patterns = match_framework_patterns(file_content)
        if check_safe_pattern(file_content):
            result["framework_safe"] = True
            # 降低置信度20%
            current_confidence = result.get("confidence", 0.85)
            if isinstance(current_confidence, (int, float)):
                result["confidence"] = max(0.0, current_confidence - 0.2)
            elif isinstance(current_confidence, str):
                # 如果是字符串格式，尝试转换为数字
                try:
                    conf_num = float(current_confidence)
                    result["confidence"] = max(0.0, conf_num - 0.2)
                except ValueError:
                    pass
        
        # 添加Bean引用验证
        bean_verification = self._verify_bean_references(vulnerability, file_content)
        result.update(bean_verification)
        
        # 添加数据完整性检查
        actual_line = result.get("verified_line", -1)
        code_snippet = result.get("code_snippet", "")
        
        if actual_line <= 0 or not code_snippet or len(str(code_snippet).strip()) == 0:
            # 代码上下文无效，标记为待人工复核
            result["data_integrity_issue"] = True
            result["review_required"] = True
            print(f"[WARN] Code context invalid or empty (line: {actual_line}, snippet: {len(code_snippet) if code_snippet else 0}), marking as REVIEW_REQUIRED")
        
        # 如果line_match_status为UNVERIFIED，标记为待人工复核
        if result.get("line_match_status") == LineMatchStatus.UNVERIFIED.value:
            result["review_required"] = True
            print(f"[DEBUG] Location unverifiable (line_match_status=UNVERIFIED), marking as REVIEW_REQUIRED")
        
        # 添加置信度与状态一致性检查
        verification_decision = vulnerability.get("verification_decision", "")
        confidence = result.get("confidence", 0.0)
        
        # CONFIRMED状态要求置信度≥0.6
        if verification_decision == "CONFIRMED" and confidence < 0.6:
            result["confidence_status_inconsistent"] = True
            print(f"[WARN] CONFIRMED status with low confidence ({confidence:.2f}), forcing to 0.6")
            # 强制设置置信度为0.6
            result["confidence"] = 0.6
        
        # UNCERTAIN状态不应显示高置信度
        if verification_decision == "UNCERTAIN" and confidence > 0.8:
            result["confidence_status_inconsistent"] = True
            print(f"[WARN] UNCERTAIN status with high confidence ({confidence:.2f}), adjusting to 0.8")
            result["confidence"] = 0.8
        
        return result
    
    def _verify_operation_type_consistency(self, vulnerability: dict, file_content: str) -> dict:
        """验证风险类型与代码操作类型的一致性
        
        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容
            
        Returns:
            dict: {
                'is_consistent': bool,
                'detected_operation': str,
                'reported_risk': str,
                'confidence_impact': float,
                'warning': str
            }
        """
        result = {
            'is_consistent': True,
            'detected_operation': 'unknown',
            'reported_risk': 'unknown',
            'confidence_impact': 0.0,
            'warning': ''
        }
        
        rule_name = vulnerability.get('rule_name', '').lower()
        description = vulnerability.get('description', '').lower()
        
        # 检测报告的风险类型
        reported_risk = 'unknown'
        if any(keyword in rule_name + description for keyword in ['sql', '注入', 'sql injection', 'injection']):
            reported_risk = 'sql_injection'
        elif any(keyword in rule_name + description for keyword in ['xss', '跨站', 'cross-site']):
            reported_risk = 'xss'
        elif any(keyword in rule_name + description for keyword in ['敏感信息', 'secret', 'password', '密钥', 'api_key']):
            reported_risk = 'sensitive_data'
        
        result['reported_risk'] = reported_risk
        
        # 如果无法确定风险类型，跳过验证
        if reported_risk == 'unknown':
            return result
        
        # 获取验证后的行号
        verified_line = vulnerability.get('verified_line', -1)
        if verified_line <= 0:
            return result
        
        # 获取代码上下文
        code_context = vulnerability.get('code_context', {})
        if code_context:
            vulnerable_line = code_context.get('vulnerable_line', '')
            context_before = code_context.get('context_before', [])
            context_after = code_context.get('context_after', [])
        else:
            # 从文件中提取代码上下文
            lines = file_content.split('\n')
            if verified_line <= len(lines):
                vulnerable_line = lines[verified_line - 1]
                context_before = lines[max(0, verified_line - 6):verified_line - 1]
                context_after = lines[verified_line:min(len(lines), verified_line + 5)]
            else:
                return result
        
        # 检测代码操作类型
        detected_operation = 'unknown'
        
        # Redis操作检测
        redis_patterns = [
            r'redisTemplate\.',
            r'redis\.',
            r'RedisTemplate',
            r'opsForValue\(\)',
            r'opsForHash\(\)',
            r'opsForList\(\)',
            r'opsForSet\(\)',
            r'opsForZSet\(\)',
            r'StringRedisSerializer',
            r'JdkSerializationRedisSerializer',
            r'redisTemplate\.set\(',
            r'redisTemplate\.get\(',
            r'redisTemplate\.opsForValue\(\)\.get',
            r'redisTemplate\.opsForValue\(\)\.set',
        ]
        
        # 数据库操作检测
        db_patterns = [
            r'jdbcTemplate\.',
            r'JdbcTemplate',
            r'mybatis',
            r'ibatis',
            r'SqlSession',
            r'\.query\(',
            r'\.execute\(',
            r'\.executeQuery\(',
            r'createQuery\(',
            r'createNativeQuery\(',
            r'\.find\(',
            r'\.select\(',
            r'@Query\(',
            r'Wrappers\.',
            r'QueryWrapper',
            r'EntityWrapper',
            r'\.selectSql\(',
        ]
        
        # MyBatis-Plus安全模式（不触发SQL注入警告）
        mybatis_plus_safe_patterns = [
            r'Wrappers\.query\(',
            r'Wrappers\.lambdaQuery\(',
            r'Wrappers\.lambdaQuery\(\w+\)',
            r'new QueryWrapper<\w+>\(\)',
            r'new LambdaQueryWrapper<\w+>\(\)',
            r'queryWrapper\.eq\(',
            r'queryWrapper\.ne\(',
            r'queryWrapper\.like\(',
            r'queryWrapper\.in\(',
            r'queryWrapper\.ge\(',
            r'queryWrapper\.gt\(',
            r'queryWrapper\.le\(',
            r'queryWrapper\.lt\(',
            r'queryWrapper\.between\(',
            r'queryWrapper\.orderBy\(',
            r'queryWrapper\.select\(',
            r'lambdaQuery\(\)\.eq\(',
            r'lambdaQuery\(\)\.ne\(',
            r'lambdaQuery\(\)\.like\(',
            r'lambdaQuery\(\)\.in\(',
            r'lambdaQuery\(\)\.orderBy\(',
            r'Wrappers\.update\(',
            r'Wrappers\.delete\(',
        ]
        
        all_context = ' '.join([vulnerable_line] + context_before + context_after).lower()
        
        redis_matches = [p for p in redis_patterns if re.search(p, all_context)]
        db_matches = [p for p in db_patterns if re.search(p, all_context)]
        safe_mybatis_matches = [p for p in mybatis_plus_safe_patterns if re.search(p, all_context)]
        
        # 扩展搜索范围：在漏洞描述、标题和证据中也搜索MyBatis-Plus安全模式
        vulnerability_text = ' '.join([
            vulnerability.get('title', ''),
            vulnerability.get('rule_name', ''),
            vulnerability.get('description', ''),
            vulnerable_line
        ]).lower()
        
        # 从证据列表中提取文本
        evidence_list = vulnerability.get('evidence', [])
        if isinstance(evidence_list, list):
            for ev in evidence_list:
                if isinstance(ev, dict):
                    vulnerability_text += ' ' + ev.get('code_snippet', '').lower()
                    vulnerability_text += ' ' + ev.get('reason', '').lower()
        
        safe_mybatis_in_text = [p for p in mybatis_plus_safe_patterns if re.search(p, vulnerability_text)]
        if safe_mybatis_in_text and not safe_mybatis_matches:
            safe_mybatis_matches = safe_mybatis_in_text
        
        if redis_matches and not db_matches:
            detected_operation = 'redis_operation'
        elif db_matches and not redis_matches:
            detected_operation = 'database_operation'
        elif redis_matches and db_matches:
            detected_operation = 'mixed_operation'
        
        result['detected_operation'] = detected_operation
        
        # 验证一致性
        if reported_risk == 'sql_injection' and detected_operation == 'redis_operation':
            result['is_consistent'] = False
            result['confidence_impact'] = 0.4
            result['warning'] = f'检测到风险类型为SQL注入，但代码实际使用Redis操作，操作类型不一致。检测到的操作: {", ".join(redis_matches[:2])}'
            print(f"[WARN] 操作类型不一致: 报告风险={reported_risk}, 检测操作={detected_operation}")
        elif reported_risk == 'sql_injection' and detected_operation == 'unknown':
            result['is_consistent'] = False
            result['confidence_impact'] = 0.2
            result['warning'] = '无法在代码中检测到数据库操作，SQL注入风险可能不适用'
            print(f"[WARN] 无法确认数据库操作: 报告风险={reported_risk}")
        
        # MyBatis-Plus安全模式检测
        if reported_risk == 'sql_injection' and safe_mybatis_matches:
            result['is_consistent'] = False
            result['confidence_impact'] = 0.7
            result['warning'] = f'检测到MyBatis-Plus安全模式使用预编译语句，SQL注入风险评估降低。检测到的安全模式: {", ".join(safe_mybatis_matches[:2])}'
            print(f"[INFO] MyBatis-Plus安全模式: 报告风险={reported_risk}, 检测到安全模式={", ".join(safe_mybatis_matches[:2])}")
        
        return result
    
    def _verify_bean_references(self, vulnerability: dict, file_content: str) -> dict:
        """验证安全注解中的Bean引用
        
        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容
            
        Returns:
            dict: {
                'bean_verified': bool,
                'verified_refs': list,
                'unverified_refs': list,
                'confidence_adjustment': float
            }
        """
        result = {
            'bean_verified': False,
            'verified_refs': [],
            'unverified_refs': [],
            'confidence_adjustment': 0.0
        }
        
        # 检查漏洞描述是否包含安全注解相关内容
        rule_name = vulnerability.get('rule_name', '').lower()
        description = vulnerability.get('description', '').lower()
        
        # 只对安全相关漏洞进行Bean验证
        security_keywords = ['preauthorize', 'secured', 'permission', 'authority', 'authorization', '权限']
        if not any(keyword in rule_name + description for keyword in security_keywords):
            return result
        
        # 初始化SpEL解析器
        if self._spel_parser is None and self._project_root:
            try:
                module_analyzer = ModuleAnalyzer(self._project_root)
                if module_analyzer.parse_project():
                    bean_scanner = BeanScanner(module_analyzer)
                    bean_scanner.scan_all_modules()
                    self._spel_parser = SpELParser(module_analyzer, bean_scanner)
                    print(f"[INFO] Bean分析器初始化完成，共扫描 {len(bean_scanner.beans)} 个Bean")
            except Exception as e:
                print(f"[WARN] 初始化Bean分析器失败: {e}")
                return result
        
        if self._spel_parser is None:
            return result
        
        # 解析安全注解
        try:
            spel_refs = self._spel_parser.parse_security_annotations(file_content)
            
            if not spel_refs:
                return result
            
            # 获取文件路径
            file_path = vulnerability.get('location', '')
            if ':' in file_path:
                file_path = file_path.split(':')[0]
            
            # 验证Bean引用
            verification_results = self._spel_parser.verify_references(spel_refs, file_path)
            
            verified_refs = []
            unverified_refs = []
            
            for vr in verification_results:
                if vr.exists:
                    verified_refs.append({
                        'bean_name': vr.sp_el_ref.bean_name,
                        'method_name': vr.sp_el_ref.method_name,
                        'found_module': vr.found_module,
                        'file_path': vr.bean_definitions[0].file_path if vr.bean_definitions else '',
                        'line_number': vr.bean_definitions[0].line_number if vr.bean_definitions else 0
                    })
                else:
                    unverified_refs.append({
                        'bean_name': vr.sp_el_ref.bean_name,
                        'method_name': vr.sp_el_ref.method_name,
                        'search_path': vr.search_path
                    })
            
            result['verified_refs'] = verified_refs
            result['unverified_refs'] = unverified_refs
            
            # 根据验证结果调整置信度
            if verified_refs and not unverified_refs:
                # 所有Bean引用都验证通过，不降低置信度
                result['bean_verified'] = True
                result['confidence_adjustment'] = 0.0
                print(f"[DEBUG] Bean验证通过: {len(verified_refs)} 个引用已验证")
            elif unverified_refs and not verified_refs:
                # 所有Bean引用都未验证，降低置信度20%
                result['bean_verified'] = False
                result['confidence_adjustment'] = 0.2
                print(f"[WARN] Bean验证失败: {len(unverified_refs)} 个引用未找到")
                for ref in unverified_refs:
                    print(f"[WARN]   - @{ref['bean_name']} (搜索路径: {' -> '.join(ref['search_path'])})")
            else:
                # 部分验证通过，降低置信度10%
                result['bean_verified'] = False
                result['confidence_adjustment'] = 0.1
                print(f"[WARN] Bean部分验证: {len(verified_refs)} 已验证, {len(unverified_refs)} 未验证")
            
            return result
            
        except Exception as e:
            print(f"[WARN] Bean验证过程出错: {e}")
            return result
    
    def find_actual_line(self, vulnerability: dict, file_content: str) -> tuple[int, str, list]:
        """查找实际匹配行

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            (实际行号, 匹配状态, 候选行列表)
            匹配状态: "EXACT", "ADJUSTED", "FUZZY", "NOT_FOUND"
        """
        rule_name = vulnerability.get("rule_name", "unknown")
        print(f"\n[DEBUG] ====== find_actual_line START ======")
        print(f"[DEBUG] Rule: {rule_name}")

        if file_content:
            original_line_count = len(file_content.split('\n'))
            file_content = self._normalize_line_endings(file_content)
            normalized_line_count = len(file_content.split('\n'))
            if original_line_count != normalized_line_count:
                print(f"[DEBUG] Line ending normalization: {original_line_count} -> {normalized_line_count} lines")

        evidence = vulnerability.get("evidence", [])
        code_snippet = ""
        ai_reported_line = None

        for ev in evidence:
            if isinstance(ev, dict) and ev.get("code_snippet"):
                code_snippet = ev["code_snippet"]
                break

        location = vulnerability.get("location", "")
        raw_line_str = ""
        file_path = ""
        
        if location:
            # 特殊处理Windows路径（如 C:\path\file.java:69）
            # 冒号可能出现在驱动器号、URL、或行号分隔符中
            parts = str(location).split(":")
            
            # 策略：如果是Windows路径（第一部分是单字母驱动器），则重新组合
            if len(parts) >= 3 and len(parts[0]) == 1 and parts[0].isalpha():
                # Windows路径：驱动器字母 + 路径 + 行号
                # 例如：C:\path\file.java:69 -> parts = ['C', '\\path', 'file.java', '69']
                # 我们需要找到最后一个数字部分作为行号，其余作为文件路径
                file_parts = []
                line_part = None
                
                for i, part in enumerate(parts):
                    if i == 0:
                        # 驱动器字母
                        file_parts.append(part)
                    elif part.isdigit():
                        # 数字部分作为行号
                        line_part = part
                    else:
                        # 路径部分
                        if file_parts and not file_parts[-1].startswith('\\') and not file_parts[-1].startswith('/'):
                            file_parts.append('\\' + part)
                        else:
                            file_parts.append(part)
                
                file_path = ''.join(file_parts)
                raw_line_str = line_part if line_part else ""
                
                print(f"[DEBUG] Windows path detected, reconstructed: {file_path}, line: {raw_line_str}")
                
            elif len(parts) >= 2:
                # 标准Unix路径或简单格式：/path/file.java:69 或 file.java:69
                # 假设最后一个部分是数字（行号），其余是文件路径
                last_part = parts[-1]
                if last_part.isdigit() or (len(last_part) > 0 and last_part.replace('-', '').isdigit()):
                    raw_line_str = last_part
                    file_path = ':'.join(parts[:-1])
                else:
                    # 无法解析，默认整个为文件路径
                    file_path = str(location)
            else:
                # 只有一个部分，无法解析
                file_path = str(location)
            
            try:
                if raw_line_str and "-" in raw_line_str:
                    ai_reported_line = int(raw_line_str.split("-")[0])
                    # 如果行号为0，转换为1（0-based到1-based的常见错误）
                    if ai_reported_line == 0:
                        ai_reported_line = 1
                        print(f"[DEBUG] Line number 0 detected, adjusting to 1")
                    print(f"[DEBUG] Range line number detected: {raw_line_str} -> using start: {ai_reported_line}")
                elif raw_line_str:
                    ai_reported_line = int(raw_line_str)
                    # 如果行号为0，转换为1
                    if ai_reported_line == 0:
                        ai_reported_line = 1
                        print(f"[DEBUG] Line number 0 detected, adjusting to 1")
                else:
                    ai_reported_line = None
            except ValueError:
                ai_reported_line = None

        print(f"[DEBUG] AI reported line: {ai_reported_line}")
        print(f"[DEBUG] code_snippet length: {len(code_snippet) if code_snippet else 0}")

        if ai_reported_line and file_content:
            lines = file_content.split('\n')
            if 1 <= ai_reported_line <= len(lines):
                reported_content = lines[ai_reported_line - 1]
                description = vulnerability.get("description", "")
                extracted_identifiers = self._extract_identifiers_from_description(description)

                if code_snippet:
                    ai_line_has_snippet = self._code_snippet_matches_line(code_snippet, reported_content)
                    is_valid_ai_line, reason = self._is_valid_ai_reported_line(reported_content, ai_reported_line, file_content)
                    if ai_line_has_snippet and is_valid_ai_line:
                        print(f"[DEBUG] AI reported line {ai_reported_line} contains code snippet and is valid, using it directly")
                        return ai_reported_line, "REPORTED", []
                    elif is_valid_ai_line:
                        print(f"[DEBUG] AI reported line {ai_reported_line} is valid code (line content verified)")
                        if extracted_identifiers:
                            print(f"[DEBUG] Extracted identifiers from description: {extracted_identifiers}")
                            line_lower = reported_content.lower()
                            matched = any(ident in line_lower for ident in extracted_identifiers)
                            if matched:
                                print(f"[DEBUG] Semantic validation passed: line contains identifier from description")
                                return ai_reported_line, "REPORTED", []
                        print(f"[DEBUG] Using AI reported line directly: {ai_reported_line}")
                        return ai_reported_line, "REPORTED", []
                    else:
                        print(f"[DEBUG] AI reported line rejected: {reason}, trying fuzzy match...")

                is_valid, reason = self._is_valid_ai_reported_line(reported_content, ai_reported_line, file_content)
                if is_valid:
                    print(f"[DEBUG] Using AI reported line directly (has valid code): {ai_reported_line}")
                    print(f"[DEBUG] Content: {reported_content[:60]}...")

                    if extracted_identifiers:
                        print(f"[DEBUG] Extracted identifiers from description: {extracted_identifiers}")
                        line_lower = reported_content.lower()
                        matched = any(ident in line_lower for ident in extracted_identifiers)
                        if matched:
                            print(f"[DEBUG] Semantic validation passed: line contains identifier from description")
                            return ai_reported_line, "REPORTED", []
                        else:
                            print(f"[DEBUG] Semantic validation FAILED: line does not contain identifier from description")
                            print(f"[DEBUG] Triggering keyword-based fuzzy match to find actual line...")
                            candidates = self._find_lines_by_keywords(
                                [], file_content, ai_reported_line, extracted_identifiers
                            )
                            if candidates:
                                print(f"[DEBUG] Keyword match found: line {candidates[0]}")
                                return candidates[0], "FUZZY", candidates
                            print(f"[DEBUG] Keyword match failed, falling back to AI reported line")
                            return ai_reported_line, "FUZZY", []
                    else:
                        return ai_reported_line, "REPORTED", []
                else:
                    print(f"[DEBUG] AI reported line rejected: {reason}, line {ai_reported_line}: {reported_content[:40]}...")
                    fallback_matched = False
                    if extracted_identifiers and file_content:
                        print(f"[DEBUG] Trying identifier-based matching after rejection...")
                        candidates = self._find_lines_by_keywords(
                            [], file_content, ai_reported_line, extracted_identifiers
                        )
                        if candidates:
                            print(f"[DEBUG] Fallback identifier matched: line {candidates[0]}, candidates {candidates}")
                            return candidates[0], "FUZZY", candidates
                        else:
                            fallback_matched = True
                            print(f"[DEBUG] Fallback identifier matching returned no candidates")

                    if fallback_matched or not extracted_identifiers:
                        print(f"[DEBUG] No valid match found after AI line rejected, continuing to keyword search...")

        if self._is_configuration_vulnerability(vulnerability):
            print(f"[DEBUG] Configuration vulnerability detected, trying joint keyword verification...")
            joint_candidates = self._find_lines_by_joint_keywords(
                vulnerability, file_content, ai_reported_line
            )
            if joint_candidates:
                print(f"[DEBUG] Joint verification matched: line {joint_candidates[0]}, candidates {joint_candidates}")
                print(f"[DEBUG] ====== find_actual_line END ======\n")
                return joint_candidates[0], "FUZZY", joint_candidates

        description = vulnerability.get("description", "")
        extracted_identifiers = self._extract_identifiers_from_description(description)
        if extracted_identifiers:
            print(f"[DEBUG] Extracted identifiers from description: {extracted_identifiers}")

        keywords = self._extract_keywords(vulnerability)
        print(f"[DEBUG] Keywords extracted: {len(keywords)}")

        security_keywords = self._extract_security_api_keywords(vulnerability, description)
        if security_keywords:
            print(f"[DEBUG] Security API keywords added: {security_keywords}")
            keywords = list(set(keywords + security_keywords))

        if keywords and file_content:
            print(f"[DEBUG] Trying keyword fuzzy match...")
            candidates = self._find_lines_by_keywords(
                keywords, file_content, ai_reported_line, extracted_identifiers
            )
            if candidates:
                print(f"[DEBUG] Keyword matched: line {candidates[0]}, candidates {candidates}")
                print(f"[DEBUG] ====== find_actual_line END ======\n")
                return candidates[0], "FUZZY", candidates

        if not keywords and extracted_identifiers and file_content:
            print(f"[DEBUG] No keywords but identifiers found, trying identifier-only match...")
            candidates = self._find_lines_by_keywords(
                [], file_content, ai_reported_line, extracted_identifiers
            )
            if candidates:
                print(f"[DEBUG] Identifier-only matched: line {candidates[0]}, candidates {candidates}")
                print(f"[DEBUG] ====== find_actual_line END ======\n")
                return candidates[0], "FUZZY", candidates

        print(f"[DEBUG] No match found, returning NOT_FOUND")
        print(f"[DEBUG] Keywords or file_content empty, cannot use AI reported line directly")
        print(f"[DEBUG] ====== find_actual_line END ======\n")
        return -1, "NOT_FOUND", []

    def _extract_keywords(self, vulnerability: dict) -> list:
        """从漏洞数据中提取英文关键词

        只提取英文代码标识符，不包含中文。
        """
        keywords = []

        rule_name = vulnerability.get("rule_name", "")
        if rule_name:
            words = rule_name.split()
            for w in words:
                w_lower = w.lower()
                if w_lower in ['jsoup', 'shiro', 'struts', 'spring', 'log4j', 'jackson', 'fastjson', 'commons', 'hibernate']:
                    keywords.append(w_lower)
                elif len(w) > 3 and not self._contains_chinese(w):
                    keywords.append(w_lower)
                    camel_parts = self._split_camel_case(w)
                    keywords.extend([p for p in camel_parts if not self._contains_chinese(p)])

        description = vulnerability.get("description", "")
        if description:
            version_pattern = r'(\d+\.\d+\.\d+[a-zA-Z]*)'
            versions = re.findall(version_pattern, description)
            keywords.extend([v.lower() for v in versions])

            important_patterns = [
                r'([a-zA-Z]+(?:[-_]?[a-zA-Z]+){1,3})\s*version\s*(\d+\.\d+\.\d+)',
                r'version\s*(\d+\.\d+\.\d+)',
                r'@(\w+)',
            ]
            for pattern in important_patterns:
                matches = re.findall(pattern, description.lower())
                for m in matches:
                    if isinstance(m, tuple):
                        keywords.extend([x for x in m if x and not self._contains_chinese(x)])
                    else:
                        if not self._contains_chinese(m):
                            keywords.append(m)

            annotation_pattern = r'@(\w+)'
            annotations = re.findall(annotation_pattern, description)
            for ann in annotations:
                if not self._contains_chinese(ann):
                    keywords.append(f"@{ann.lower()}")
                    if len(ann) > 3:
                        keywords.append(ann.lower())

        vulnerability_type = vulnerability.get("vulnerability_type", vulnerability.get("type", ""))
        if vulnerability_type:
            type_keywords = self._extract_type_keywords(vulnerability_type)
            keywords.extend([k for k in type_keywords if not self._contains_chinese(k)])

        location = vulnerability.get("location", "")
        if location and not self._contains_chinese(location):
            location_keywords = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]{2,})', location)
            common_path_components = {
                'main', 'src', 'java', 'cloud', 'bizspring', 'project', 'component',
                'open', 'real', 'base', 'security', 'hos', 'common', 'config',
                'module', 'business', 'gateway', 'auth', 'aaa_project',
                'configuration', 'properties', 'application', 'resources',
                'static', 'test', 'target', 'build', 'lib', 'webapp',
                'file', 'path', 'location', 'line', 'root', 'home',
                'users', 'home', 'documents', 'desktop', 'downloads',
                'windows', 'system32', 'program', 'files', 'appdata',
                'github', 'gitlab', 'gitee', 'repository', 'repo',
                'node_modules', 'package', 'modules', 'dist', 'coverage',
            }
            filtered_keywords = [
                k.lower() for k in location_keywords
                if k.lower() not in ['null', 'none', 'undefined']
                and k.lower() not in common_path_components
                and len(k) > 3
            ]
            keywords.extend(filtered_keywords)

        keywords = list(set(keywords))
        keywords = [k for k in keywords if k and len(k) > 1 and not self._contains_chinese(k)]

        if not keywords:
            print(f"[DEBUG] Keywords still empty after extraction, using identifiers as fallback keywords")
            identifiers = self._extract_identifiers_from_description(vulnerability.get("description", ""))
            keywords = [i.lower() for i in identifiers if i and len(i) > 2][:30]
            keywords = list(set(keywords))

        return keywords[:30]

    def _extract_security_api_keywords(self, vulnerability: dict, description: str) -> list:
        """从漏洞描述和类型中提取安全API关键词
        
        针对常见的Java安全配置漏洞，提取对应的API方法名作为关键词，
        帮助精确匹配到实际的漏洞代码行。
        """
        keywords = []
        desc_lower = description.lower()
        vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "")).lower()
        rule_name = vulnerability.get("rule_name", "").lower()

        csrf_patterns = ['csrf', 'cross-site request forgery', '跨站请求伪造']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in csrf_patterns):
            keywords.extend(['csrf', 'disable', 'csrfdisable', 'csrf().disable', 'httpsecurity'])

        clickjack_patterns = ['clickjack', 'x-frame', 'frameoption', 'frame.options', '点击劫持', 'frame-options']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in clickjack_patterns):
            keywords.extend(['frameoptions', 'frame.options', 'disable', 'headers', 'httpsecurity', 'x-frame'])

        cors_patterns = ['cors', 'cross-origin', '跨域']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in cors_patterns):
            keywords.extend(['cors', 'corsconfiguration', 'allowedorigins', 'addcorsmapping'])

        token_patterns = ['token', 'jwt', 'access.token', 'refresh.token', '令牌']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in token_patterns):
            keywords.extend(['token', 'jwt', 'accesstoken', 'refreshtoken', 'tokenstore', 'authorization'])

        auth_patterns = ['authentication', 'authorization', '认证', '授权', 'permitall', 'permit.all']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in auth_patterns):
            keywords.extend(['permitall', 'authenticated', 'authorizeexchange', 'authentication', 'authorization', 'security'])

        ssrf_patterns = ['ssrf', 'server-side request forgery', '服务端请求伪造']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in ssrf_patterns):
            keywords.extend(['resttemplate', 'httpclient', 'urlconnection', 'fetch', 'request'])

        leak_patterns = ['leak', 'disclosure', '暴露', '泄露', 'sensitive', '敏感']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in leak_patterns):
            keywords.extend(['tostring', 'response', 'body', 'sensitive', 'expose', 'serialize'])

        exception_patterns = ['exception', 'error.handler', '错误处理', '异常']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in exception_patterns):
            keywords.extend(['errorhandler', 'handleerror', 'exceptionhandler', 'responsestatus', 'restcontrolleradvice'])

        swagger_patterns = ['swagger', 'api.doc', 'springfox', '文档']
        if any(p in desc_lower or p in vuln_type or p in rule_name for p in swagger_patterns):
            keywords.extend(['swagger', 'enableswagger', 'swaggerui', 'api-docs', 'springfox'])

        keywords = list(set(k.lower() for k in keywords if k and len(k) > 1))
        return keywords

    def _extract_type_keywords(self, vulnerability_type: str) -> list:
        """从漏洞类型提取英文关键词"""
        keywords = []
        type_lower = vulnerability_type.lower()

        if "configuration" in type_lower or "config" in type_lower:
            keywords.extend(["configuration", "config", "properties", "configurationproperties"])
        if "refreshscope" in type_lower or "refresh" in type_lower:
            keywords.extend(["refreshscope", "refresh", "scope", "refreshbeanscope"])
        if "data" in type_lower and "lombok" not in keywords:
            keywords.extend(["data", "lombok", "tostring"])
        if "sql" in type_lower or "injection" in type_lower:
            keywords.extend(["sql", "injection", "sqlInjection", "parameterized"])
        if "xss" in type_lower or "crosssite" in type_lower:
            keywords.extend(["xss", "crosssite", "escape", "htmlencode"])
        if "path" in type_lower and "traversal" in type_lower:
            keywords.extend(["path", "traversal", "pathtraversal", "pathinjection"])
        if "annotation" in type_lower:
            keywords.extend(["annotation", "annotations", "@"])

        return keywords

    def _normalize_line_endings(self, content: str) -> str:
        """规范化换行符，将 CRLF/CR 统一转换为 LF

        Args:
            content: 原始文件内容

        Returns:
            规范化后的文件内容
        """
        if not content:
            return content
        return re.sub(r'\r\n|\r', '\n', content)

    def _is_inside_multiline_comment(self, file_content: str, target_line: int) -> tuple[bool, str]:
        """检测目标行是否在多行注释块内部

        Args:
            file_content: 文件全部内容
            target_line: 目标行号（1-based）

        Returns:
            (是否在注释块内, 原因)
        """
        if not file_content or target_line <= 0:
            return False, ""

        lines = file_content.split('\n')
        if target_line > len(lines):
            return False, ""

        in_block_comment = False

        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()

            if line_num == target_line:
                if in_block_comment:
                    return True, "在多行注释块内"
                return False, ""

            if '/*' in stripped and '*/' not in stripped:
                in_block_comment = True
            elif '*/' in stripped and in_block_comment:
                in_block_comment = False

        return False, ""

    def _is_valid_ai_reported_line(self, line_content: str, line_number: int = None, file_content: str = None) -> tuple[bool, str]:
        """检查AI报告的行是否为有效的漏洞位置

        Args:
            line_content: 行内容
            line_number: 行号（可选）
            file_content: 文件全部内容（可选，用于检测多行注释）

        Returns:
            (是否有效, 原因)
        """
        if not line_content or not line_content.strip():
            return False, "空行"

        if file_content and line_number is not None:
            inside_comment, reason = self._is_inside_multiline_comment(file_content, line_number)
            if inside_comment:
                return False, reason

        stripped = line_content.strip()

        if stripped.startswith("//"):
            return False, "单行注释"

        if stripped.startswith("/*"):
            return False, "多行注释开始"

        if stripped == "*/":
            return False, "多行注释结束"

        if stripped.startswith("*") and not stripped.startswith("* @"):
            return False, "Javadoc注释行"

        if line_number is not None and line_number <= 15:
            if stripped.startswith("package "):
                return False, "package声明"

            if stripped.startswith("import "):
                return False, "import声明"

        java_keywords = ["public ", "private ", "protected ", "class ", "interface ", "enum "]
        for kw in java_keywords:
            if stripped.startswith(kw):
                return True, "VALID"

        if "@" in stripped and not stripped.startswith("*"):
            annotation_pattern = r'^\s*@(RefreshScope|ConfigurationProperties|Data|Validated|NotNull|NotBlank|Pattern|Value|Component|Controller|RestController|Service|Repository|Bean)'
            if re.search(annotation_pattern, stripped):
                return True, "注解"
            if stripped.startswith("import ") and "@" in stripped:
                return False, "import声明"
            return True, "包含注解"

        if "=" in stripped and not stripped.startswith("//"):
            return True, "赋值语句"

        if stripped.endswith("{") or stripped.endswith("}"):
            return True, "代码块"

        if len(stripped) > 3 and not self._contains_chinese(stripped):
            return True, "有效代码"

        return False, "无效行"

    def _extract_identifiers_from_description(self, description: str) -> list:
        """从描述中提取标识符（字段名、变量名等）

        Args:
            description: 漏洞描述文本

        Returns:
            提取的标识符列表
        """
        identifiers = []

        if not description:
            return identifiers

        single_quoted_pattern = r"'([^']+)'"
        matches = re.findall(single_quoted_pattern, description)
        for m in matches:
            if len(m) > 1 and not self._contains_chinese(m):
                identifiers.append(m.lower())

        double_quoted_pattern = r'"([^"]+)"'
        matches = re.findall(double_quoted_pattern, description)
        for m in matches:
            if len(m) > 1 and not self._contains_chinese(m):
                identifiers.append(m.lower())

        var_pattern = r'变量\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(var_pattern, description)
        for m in matches:
            if not self._contains_chinese(m):
                identifiers.append(m.lower())

        field_pattern = r'字段\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(field_pattern, description)
        for m in matches:
            if not self._contains_chinese(m):
                identifiers.append(m.lower())

        common_field_names = [
            'windows', 'linux', 'mac', 'os', 'platform',
            'username', 'user', 'password', 'pass', 'secret', 'key',
            'token', 'api', 'apikey', 'api_key', 'access',
            'host', 'server', 'url', 'endpoint', 'uri',
            'database', 'db', 'sql', 'query',
            'email', 'phone', 'mobile', 'tel',
            'address', 'ip', 'port', 'path', 'file',
            'timeout', 'retry', 'max', 'min', 'limit',
            'enabled', 'disabled', 'active', 'status', 'state',
        ]

        desc_lower = description.lower()
        for field_name in common_field_names:
            if field_name in desc_lower and len(field_name) > 2:
                identifiers.append(field_name)

        annotation_pattern = r'@(RefreshScope|ConfigurationProperties|Data|Validated|NotNull|NotBlank|Pattern|Value)'
        matches = re.findall(annotation_pattern, description, re.IGNORECASE)
        for m in matches:
            identifiers.append(f"@{m.lower()}")

        words = description.split()
        for word in words:
            word_clean = word.strip('.,;:!?()[]{}').lower()
            if word_clean in ['refreshscope', 'configurationproperties', 'lombok', 'spring', 'java']:
                identifiers.append(word_clean)

        identifiers = list(set(identifiers))
        identifiers = [i for i in identifiers if len(i) > 1]
        return identifiers

    def _code_snippet_matches_line(self, code_snippet: str, line_content: str) -> bool:
        """检查 code snippet 是否与指定行的内容匹配

        使用去空白和大小写不敏感的比较来判断是否匹配。

        Args:
            code_snippet: 代码片段
            line_content: 行内容

        Returns:
            是否匹配
        """
        if not code_snippet or not line_content:
            return False

        snippet_normalized = ' '.join(code_snippet.lower().split())
        line_normalized = ' '.join(line_content.lower().split())

        if snippet_normalized in line_normalized:
            return True

        snippet_keywords = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]+', code_snippet.lower()))
        line_keywords = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]+', line_content.lower()))

        snippet_keywords = {k for k in snippet_keywords if len(k) > 2}
        if not snippet_keywords:
            return False

        matched = sum(1 for kw in snippet_keywords if kw in line_keywords)
        return matched >= len(snippet_keywords) * 0.7

    def _contains_chinese(self, text: str) -> bool:
        """检查文本是否包含中文"""
        for char in text:
            if '\u4e00' <= char <= '\u9fff':
                return True
        return False

    def _split_camel_case(self, word: str) -> list:
        """拆分驼峰命名和蛇形命名"""
        parts = []
        current = ""

        for i, char in enumerate(word):
            if char.isupper() and i > 0:
                if len(current) >= 2:
                    parts.append(current.lower())
                current = char
            elif char == '_' or char == '-':
                if len(current) >= 2:
                    parts.append(current.lower())
                current = ""
            else:
                current += char

        if len(current) >= 2:
            parts.append(current.lower())

        return parts

    def _find_lines_by_keywords(self, keywords: list, file_content: str, preferred_line: int = None, extracted_identifiers: list = None) -> list:
        """根据关键词查找可能的匹配行

        Args:
            keywords: 关键词列表
            file_content: 文件内容
            preferred_line: AI报告的首选行号
            extracted_identifiers: 从描述中提取的标识符列表（字段名等）
        """
        identifiers = extracted_identifiers or []
        if not file_content:
            return []

        if not keywords and not identifiers:
            return []

        if not keywords and identifiers:
            print(f"[DEBUG] Keyword-only mode: using identifiers only (no keywords provided)")

        lines = file_content.split('\n')
        scored_lines = []

        for i, line in enumerate(lines):
            line_lower = line.lower()
            score = 0
            matched_kws = []
            identifier_bonus = 0

            for kw in keywords:
                if isinstance(kw, str) and kw.lower() in line_lower:
                    score += 1
                    matched_kws.append(kw)

            for ident in identifiers:
                ident_lower = ident.lower()
                if ident_lower in line_lower:
                    if self._is_word_boundary_match(ident_lower, line_lower):
                        identifier_bonus += 5
                        matched_kws.append(ident)
                    elif self._is_field_identifier_match(ident_lower, line, line_lower):
                        identifier_bonus += 5
                        matched_kws.append(ident)

            if identifier_bonus > 0 and self._is_field_declaration(line):
                identifier_bonus += 3

            total_score = score + identifier_bonus
            if total_score > 0:
                proximity = abs(i + 1 - preferred_line) if preferred_line else 0
                scored_lines.append((i + 1, total_score, matched_kws, identifier_bonus, proximity))

        scored_lines.sort(key=lambda x: (x[4] if preferred_line else 0, -(x[1] + x[3] * 0.5)), reverse=False)

        print(f"[DEBUG] Keyword match: {len(keywords)} keywords, {len(identifiers)} identifiers, {len(scored_lines)} candidates")
        print(f"[DEBUG] Keywords: {keywords[:10]}...")
        print(f"[DEBUG] Identifiers: {identifiers[:10]}...")
        if scored_lines:
            print(f"[DEBUG] Best candidate: line {scored_lines[0][0]}, score {scored_lines[0][1]}, identifier_bonus {scored_lines[0][3]}, matched {scored_lines[0][2][:5]}")
            if preferred_line:
                print(f"[DEBUG] AI reported: {preferred_line}, offset: {abs(scored_lines[0][0] - preferred_line)} lines")

        if scored_lines:
            best_match = scored_lines[0][0]
            best_score = scored_lines[0][1]
            best_identifier_bonus = scored_lines[0][3]
            best_proximity = scored_lines[0][4]
            tolerance = self.tolerance if self.tolerance > 0 else 5

            if preferred_line:
                offset = abs(best_match - preferred_line)
                if offset <= tolerance:
                    print(f"[DEBUG] Tolerance check passed: offset {offset} <= {tolerance}")
                    return [best_match]
                else:
                    print(f"[DEBUG] Best match exceeds tolerance: offset {offset} > {tolerance}, looking for closer candidates...")
                    closer_candidates = [(ln, score, kws, ib, prox) for ln, score, kws, ib, prox in scored_lines
                                       if abs(ln - preferred_line) <= tolerance]
                    if closer_candidates:
                        closer_candidates.sort(key=lambda x: (x[4], -(x[1] + x[3] * 0.5)))
                        best_match = closer_candidates[0][0]
                        print(f"[DEBUG] Found closer match within tolerance: line {best_match}")
                        return [best_match]
                    else:
                        high_score_threshold = 3
                        if best_identifier_bonus >= high_score_threshold:
                            print(f"[DEBUG] Best match has high identifier score ({best_identifier_bonus} >= {high_score_threshold}), accepting despite offset {offset}")
                            return [best_match]
                        elif best_score >= high_score_threshold * 2:
                            print(f"[DEBUG] Best match has very high keyword score ({best_score} >= {high_score_threshold * 2}), accepting despite offset {offset}")
                            return [best_match]
                        print(f"[DEBUG] No candidates within tolerance, returning best available")
                        top_candidates = [ln for ln, _, _, _, _ in scored_lines[:5]]
                        print(f"[DEBUG] Returning top 5 candidates: {top_candidates}")
                        return top_candidates
            elif best_identifier_bonus > 0:
                print(f"[DEBUG] Identifier match found (no preferred_line), accepting match")
                return [best_match]

            if identifiers:
                target_candidates = [(ln, score, kws, ib, prox) for ln, score, kws, ib, prox in scored_lines
                                   if any(ident in kws for ident in identifiers)]
                if target_candidates:
                    target_candidates.sort(key=lambda x: (x[4], -(x[1] + x[3] * 0.5)))
                    best_target = target_candidates[0]
                    print(f"[DEBUG] Found target identifier match: line {best_target[0]}, score {best_target[1]}")
                    return [best_target[0]]
                else:
                    print(f"[DEBUG] No target identifier found in candidates")

            top_candidates = [ln for ln, _, _, _, _ in scored_lines[:5]]
            print(f"[DEBUG] Returning top 5 candidates: {top_candidates}")
            return top_candidates

    def _is_configuration_vulnerability(self, vulnerability: dict) -> bool:
        """检查是否为配置类漏洞（需要联合关键词验证）

        Args:
            vulnerability: 漏洞数据

        Returns:
            是否为配置类漏洞
        """
        rule_name = vulnerability.get("rule_name", "").lower()
        description = vulnerability.get("description", "").lower()
        vulnerability_type = vulnerability.get("vulnerability_type", "").lower()

        config_keywords = [
            "configuration", "config", "routerfunction", "router",
            "endpoint", "handler", "mapping", "requestmapping",
            "getmapping", "postmapping", "putmapping", "deletemapping",
            "bean", "refreshscope", "configurationproperties",
            "resttemplate", "webclient", "feign", "loadbalancer"
        ]

        combined = f"{rule_name} {description} {vulnerability_type}"
        return any(kw in combined for kw in config_keywords)

    def _extract_joint_keywords(self, vulnerability: dict) -> tuple[list, list]:
        """提取联合验证关键词

        对于配置类漏洞，提取必须同时出现的关键词对。

        Args:
            vulnerability: 漏洞数据

        Returns:
            (必需关键词列表, 可选关键词列表)
        """
        required_keywords = []
        optional_keywords = []

        rule_name = vulnerability.get("rule_name", "")
        description = vulnerability.get("description", "")
        vulnerability_type = vulnerability.get("vulnerability_type", "")

        if "routerfunction" in rule_name.lower() or "routerfunction" in description.lower():
            router_patterns = [
                r'router\s*\(',
                r'functions?\.router',
                r'route\s*\(',
                r'path\s*=',
                r'method\s*=',
            ]
            for pattern in router_patterns:
                matches = re.findall(pattern, description, re.IGNORECASE)
                required_keywords.extend([m.lower() for m in matches if m])

            handler_patterns = [
                r'(?:handler|bean|method)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                r'::\s*([a-zA-Z_][a-zA-Z0-9_]*)',
            ]
            for pattern in handler_patterns:
                matches = re.findall(pattern, description, re.IGNORECASE)
                optional_keywords.extend([m.lower() for m in matches if m])

        if "resttemplate" in rule_name.lower() or "resttemplate" in description.lower():
            resttemplate_patterns = [
                r'RestTemplate',
                r'@LoadBalanced',
                r'URL\s*\(',
                r'getForObject',
                r'getForEntity',
                r'postForObject',
            ]
            for pattern in resttemplate_patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    required_keywords.append(pattern.lower())

        if "configurationproperties" in rule_name.lower() or "configurationproperties" in description.lower():
            configprops_patterns = [
                r'@ConfigurationProperties',
                r'prefix\s*=',
                r'@RefreshScope',
            ]
            for pattern in configprops_patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    required_keywords.append(pattern.lower())

        description_keywords = self._extract_keywords(vulnerability)
        required_keywords.extend(description_keywords[:5])
        optional_keywords.extend(description_keywords[5:])

        required_keywords = list(set([k for k in required_keywords if k and len(k) > 1]))
        optional_keywords = list(set([k for k in optional_keywords if k and len(k) > 1]))

        return required_keywords, optional_keywords

    def _find_lines_by_joint_keywords(
        self,
        vulnerability: dict,
        file_content: str,
        preferred_line: int = None
    ) -> list:
        """根据联合关键词查找匹配行（所有必需关键词必须同时出现）

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容
            preferred_line: AI报告的首选行号

        Returns:
            匹配行号列表
        """
        if not file_content:
            return []

        required_kws, optional_kws = self._extract_joint_keywords(vulnerability)

        if not required_kws:
            return self._find_lines_by_keywords(
                self._extract_keywords(vulnerability),
                file_content,
                preferred_line,
                None
            )

        print(f"[DEBUG] Joint verification: {len(required_kws)} required keywords, {len(optional_kws)} optional keywords")
        print(f"[DEBUG] Required keywords: {required_kws}")
        print(f"[DEBUG] Optional keywords: {optional_kws}")

        lines = file_content.split('\n')
        joint_candidates = []

        for i, line in enumerate(lines):
            line_lower = line.lower()
            matched_required = []
            matched_optional = []

            for kw in required_kws:
                if isinstance(kw, str) and kw.lower() in line_lower:
                    matched_required.append(kw)

            if len(matched_required) < len(required_kws):
                continue

            for kw in optional_kws:
                if isinstance(kw, str) and kw.lower() in line_lower:
                    matched_optional.append(kw)

            all_matched = matched_required + matched_optional
            if all_matched:
                joint_candidates.append((i + 1, len(all_matched), all_matched, matched_required))

        joint_candidates.sort(
            key=lambda x: (
                len(x[3]),
                x[1],
                -abs(x[0] - (preferred_line or 0)) if preferred_line else 0
            ),
            reverse=True
        )

        if joint_candidates:
            print(f"[DEBUG] Joint verification found {len(joint_candidates)} candidates")
            print(f"[DEBUG] Best joint match: line {joint_candidates[0][0]}, required matched: {joint_candidates[0][3]}")
            return [ln for ln, _, _, _ in joint_candidates]

        print(f"[DEBUG] Joint verification failed, falling back to standard keyword search")
        return self._find_lines_by_keywords(
            required_kws + optional_kws,
            file_content,
            preferred_line,
            None
        )

    def _is_field_declaration(self, line: str) -> bool:
        """检查行是否为字段声明"""
        line_stripped = line.strip()
        if not line_stripped:
            return False
        field_patterns = [
            r'private\s+\w+',
            r'public\s+\w+',
            r'protected\s+\w+',
            r'\w+\s+\w+\s*=',
        ]
        import re
        for pattern in field_patterns:
            if re.search(pattern, line):
                return True
        return False

    def _is_word_boundary_match(self, word: str, text: str) -> bool:
        """检查单词是否作为独立单词出现在文本中（使用单词边界）

        Args:
            word: 要检查的单词
            text: 文本（已转换为小写）

        Returns:
            是否作为独立单词出现
        """
        import re
        pattern = r'\b' + re.escape(word) + r'\b'
        return bool(re.search(pattern, text))

    def _is_field_identifier_match(self, word: str, line: str, line_lower: str = None) -> bool:
        """检查单词是否作为字段标识符出现在行中

        字段标识符匹配的情况：
        1. 单词作为变量名出现在赋值语句中（如 private String xxx = xxx）
        2. 单词作为方法参数名出现

        Args:
            word: 要检查的单词
            line: 行内容
            line_lower: 行内容的小写版本（可选，如果为None会重新计算）

        Returns:
            是否作为字段标识符出现
        """
        if line_lower is None:
            line_lower = line.lower()

        import re
        field_assignment_patterns = [
            r'private\s+\w+\s+\w+\s*=',
            r'public\s+\w+\s+\w+\s*=',
            r'protected\s+\w+\s+\w+\s*=',
            r'\w+\s+\w+\s*=\s*"?\w+"?\s*;',
        ]

        for pattern in field_assignment_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if word in line_lower:
                    return True
        return False

    def adjust_line_number(self, vulnerability: dict, file_content: str) -> dict:
        """执行自动校正

        Args:
            vulnerability: 漏洞数据
            file_content: 文件内容

        Returns:
            校正后的漏洞数据
        """
        validated = self.validate_location(vulnerability, file_content)

        if validated.get("line_match_status") == LineMatchStatus.UNVERIFIED.value:
            return self.mark_unverified(validated, validated.get("candidate_lines", []))

        if validated.get("verified_line", -1) > 0:
            location = validated.get("location", "")
            file_path, _ = self.mapper.parse_location(location)
            if file_path and validated.get("verified_line", -1) > 0:
                adjusted_location = f"{file_path}:{validated['verified_line']}"
                validated["location"] = adjusted_location

        return validated

    def mark_unverified(self, vulnerability: dict, candidates: list) -> dict:
        """标记无法验证的漏洞

        Args:
            vulnerability: 漏洞数据
            candidates: 候选行号列表

        Returns:
            标记后的漏洞数据
        """
        result = dict(vulnerability)
        result["line_match_status"] = LineMatchStatus.UNVERIFIED.value
        result["candidate_lines"] = candidates

        if result.get("signal_state") == SignalState.CONFIRMED.value:
            result["signal_state"] = SignalState.UNCERTAIN.value
            result["verification_decision"] = "UNCERTAIN"
            result["verification_reason"] = (
                f"行号无法验证，候选行: {candidates[:5]}" if candidates
                else "行号无法验证，未找到匹配代码"
            )

        return result

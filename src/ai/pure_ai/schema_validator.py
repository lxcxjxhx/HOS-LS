"""Schema验证器模块

提供Schema验证、自动修复和重试机制。
"""

import hashlib
import json
import os
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml

from src.ai.pure_ai.line_number_mapper import LineNumberMapper
from src.ai.pure_ai.schema import (
    ADVERSARIAL_SCHEMA,
    FINAL_DECISION_SCHEMA,
    RISK_ENUMERATION_SCHEMA,
    VULNERABILITY_SCHEMA,
    LineMatchStatus,
    SignalState,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)

FORBIDDEN_PATTERNS = [
    r"^Unknown$",
    r"^未知$",
    r"^Unknown\s+risk",
    r"^未知\s+风险",
    r"Unable to determine",
    r"无法确定",
]

STRUCTURED_TAGS = [
    "SUSPICIOUS_PATTERN",
    "WEAK_SECURITY_SIGNAL",
    "NEEDS_VERIFICATION",
    "ARCHITECTURAL_RISK",
]


class SchemaValidationError(Exception):
    """Schema验证异常"""


class ForbiddenOutputError(Exception):
    """禁止的输出异常"""


class SchemaValidator:
    """Schema验证器

    提供结构验证、自动修复和重试功能。
    """

    def __init__(self):
        self.schemas = {
            "final_decision": FINAL_DECISION_SCHEMA,
            "vulnerability": VULNERABILITY_SCHEMA,
            "adversarial": ADVERSARIAL_SCHEMA,
            "risk_enumeration": RISK_ENUMERATION_SCHEMA,
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

    def validate_strict_output_contract(
        self, data: Dict[str, Any], schema_name: str
    ) -> tuple[bool, List[str]]:
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

    def _check_forbidden_patterns(self, data: Any, path: str = "") -> List[str]:
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
                            if value.count("Unknown") == 1 and len(value.split()) <= 2:
                                errors.append(
                                    f"Forbidden pattern at {current_path}: '{value}' - use STRUCTURED_TAGS instead"
                                )
                elif isinstance(value, dict):
                    errors.extend(self._check_forbidden_patterns(value, current_path))
                elif isinstance(value, list):
                    errors.extend(self._check_forbidden_patterns(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                if isinstance(item, dict):
                    errors.extend(self._check_forbidden_patterns(item, current_path))
                elif isinstance(item, list):
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
        errors: List[str] = []

        evidence_required_schemas = {
            "final_decision": ["final_findings"],
            "vulnerability": ["vulnerabilities"],
            "adversarial": ["adversarial_analysis"],
            "risk_enumeration": ["risks"],
            "attack_chain": ["attack_chains"],
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
                            errors.append(
                                f"Evidence at {field}[{i}] must be array, got {type(evidence).__name__}"
                            )
                        elif len(evidence) == 0 and item.get("signal_state") not in [
                            "REFINED",
                            "NEW",
                        ]:
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
        errors: List[str] = []

        signal_tracking_schemas = {
            "vulnerability": ["vulnerabilities"],
            "risk_enumeration": ["risks"],
            "attack_chain": ["attack_chains"],
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

    def fix_unknown_outputs(self, data: Any) -> Any:
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
            return [
                (
                    self.fix_unknown_outputs(item)
                    if isinstance(item, (dict, list))
                    else self.sanitize_forbidden_output(item)
                    if isinstance(item, str)
                    else item
                )
                for item in data
            ]
        return data

    def fix_invalid_locations(
        self, data: Dict[str, Any], schema_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """修复无效的位置信息

        将包含 :line、:行号未知 等无效行号的位置尝试修复。

        Args:
            data: 待修复的数据
            schema_name: Schema名称（用于确定需要修复的字段）

        Returns:
            修复后的数据
        """
        if not isinstance(data, (dict, list)):
            return data  # type: ignore

        invalid_patterns = [
            (r":line$", ":1"),
            (r":Line$", ":1"),
            (r":LINE$", ":1"),
            (r":行号未知$", ":1"),
            (r":行号$", ":1"),
            (r":未知$", ":1"),
            (r":unknown$", ":1"),
            (r":Unknown$", ":1"),
        ]

        def fix_location(location_str: Any) -> Any:
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
                    if key == "location" and isinstance(value, str):
                        fixed[key] = fix_location(value)
                    elif isinstance(value, (dict, list)):
                        fixed[key] = fix_item(value)
                    else:
                        fixed[key] = value
                return fixed
            elif isinstance(item, list):
                return [
                    (
                        fix_item(i)
                        if isinstance(i, (dict, list))
                        else fix_location(i)
                        if isinstance(i, str)
                        else i
                    )
                    for i in item
                ]
            return item

        return fix_item(data)  # type: ignore[no-any-return]

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
                        errors.append(
                            f"Expected dict for {path}.{field}, got {type(field_value).__name__}"
                        )
                    elif "properties" in field_schema:
                        errors.extend(
                            self._validate_object(field_value, field_schema, f"{path}.{field}")
                        )
                elif field_type == "array":
                    if not isinstance(field_value, list):
                        errors.append(
                            f"Expected array for {path}.{field}, got {type(field_value).__name__}"
                        )
                    elif len(field_value) == 0:
                        pass
                    elif "items" in field_schema:
                        item_schema = field_schema["items"]
                        for i, item in enumerate(field_value):
                            if isinstance(item, dict) and "properties" in item_schema:
                                errors.extend(
                                    self._validate_object(item, item_schema, f"{path}.{field}[{i}]")
                                )
                            if isinstance(item, dict) and "required" in item_schema:
                                for req_field in item_schema["required"]:
                                    if (
                                        req_field not in item
                                        or item[req_field] is None
                                        or item[req_field] == ""
                                    ):
                                        errors.append(
                                            f"Missing required field: {path}.{field}[{i}].{req_field}"
                                        )

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
                strict_valid, strict_errors = self.validate_strict_output_contract(
                    current_data, schema_name
                )
                if not strict_valid:
                    logger.warning(
                        f"Strict output contract violations for {schema_name}: {strict_errors}"
                    )
                    current_data = self.fix_unknown_outputs(current_data)
                current_data = self.fix_invalid_locations(current_data, schema_name)
                validation_passed = True
                return current_data, True

            if attempt < max_retries:
                logger.warning(f" Schema validation failed for {schema_name}: {error}")
                logger.debug(
                    f"Attempting to fix structure (attempt {attempt + 1}/{max_retries})..."
                )
                current_data = self._fix_structure(current_data, schema_name)
                current_data = self.fix_unknown_outputs(current_data)
                current_data = self.fix_invalid_locations(current_data, schema_name)
                current_data = self._ensure_required_fields(current_data, schema_name)
            else:
                logger.warning(f" Schema validation failed for {schema_name}: {error}")
                logger.debug(" Final attempt exhausted, returning fixed data (may be incomplete)")
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
                logger.debug(f" [Schema Fix] 确保 signal_tracking 字段存在 for {schema_name}")
                data["signal_tracking"] = {
                    "signals_new": 0,
                    "signals_confirmed": 0,
                    "signals_rejected": 0,
                    "signals_refined": 0,
                }

        if schema_name == "vulnerability":
            if "vulnerabilities" not in data or not isinstance(data.get("vulnerabilities"), list):
                logger.debug(f" [Schema Fix] 确保 vulnerabilities 字段存在 for {schema_name}")
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
                    "signals_new": 0,
                },
            }
        elif schema_name == "adversarial":
            return {"adversarial_analysis": [], "cross_agent_agreement": []}
        elif schema_name == "risk_enumeration":
            return {
                "risks": [],
                "signal_tracking": {
                    "signals_confirmed": 0,
                    "signals_rejected": 0,
                    "signals_refined": 0,
                    "signals_new": 0,
                },
            }
        elif schema_name == "attack_chain":
            return {
                "attack_chains": [],
                "signal_tracking": {
                    "signals_confirmed": 0,
                    "signals_rejected": 0,
                    "signals_new": 0,
                },
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
                    "low_severity_count": 0,
                },
            }
        else:
            return {"unknown_schema": schema_name, "data": {}}

    def validate_with_retry(
        self, data: Any, schema_name: str, max_retries: int = 3
    ) -> Dict[str, Any]:
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
                strict_valid, strict_errors = self.validate_strict_output_contract(
                    current_data, schema_name
                )
                if strict_valid:
                    logger.debug(f" Schema validation passed on attempt {attempt + 1}")
                    current_data = self.fix_invalid_locations(current_data, schema_name)
                    current_data = self._ensure_required_fields(current_data, schema_name)
                    return current_data
                logger.warning(
                    f"Strict contract violations on attempt {attempt + 1}: {strict_errors}"
                )
            if attempt < max_retries - 1:
                logger.debug(f" Fixing structure (attempt {attempt + 1}/{max_retries})...")
                current_data = self._fix_structure(current_data, schema_name)
                current_data = self.fix_unknown_outputs(current_data)
                current_data = self.fix_invalid_locations(current_data, schema_name)
            else:
                logger.debug(f" Max retries reached for {schema_name}, using last fixed data")

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
            return data  # type: ignore[no-any-return]

        fixed = {}

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        for field, field_schema in properties.items():
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
                        field_list = fixed[field]
                        if isinstance(field_list, list):
                            for i, item in enumerate(field_list):
                                if isinstance(item, dict):
                                    field_list[i] = self._fix_item_structure(
                                        item, item_schema, schema_name
                                    )
            elif is_required:
                if field == "signal_tracking":
                    if schema_name == "attack_chain":
                        items = data.get("attack_chains", [])
                        if not isinstance(items, list):
                            items = []
                        confirmed = sum(
                            1
                            for v in items
                            if isinstance(v, dict) and v.get("signal_state") == "CONFIRMED"
                        )
                        rejected = sum(
                            1
                            for v in items
                            if isinstance(v, dict) and v.get("signal_state") == "REJECTED"
                        )
                        refined = 0
                        new_count = sum(
                            1
                            for v in items
                            if isinstance(v, dict) and v.get("signal_state") == "NEW"
                        )
                        fixed[field] = {
                            "total_signals": len(items),
                            "signals_new": new_count,
                            "signals_confirmed": confirmed,
                            "signals_rejected": rejected,
                        }
                    else:
                        items = data.get("vulnerabilities", data.get("risks", []))
                        if not isinstance(items, list):
                            items = []
                        confirmed = sum(
                            1
                            for v in items
                            if isinstance(v, dict) and v.get("signal_state") == "CONFIRMED"
                        )
                        rejected = sum(
                            1
                            for v in items
                            if isinstance(v, dict) and v.get("signal_state") == "REJECTED"
                        )
                        refined = sum(
                            1
                            for v in items
                            if isinstance(v, dict) and v.get("signal_state") == "REFINED"
                        )
                        new_count = sum(
                            1
                            for v in items
                            if isinstance(v, dict) and v.get("signal_state") == "NEW"
                        )
                        fixed[field] = {
                            "total_signals": len(items),
                            "signals_new": new_count,
                            "signals_confirmed": confirmed,
                            "signals_rejected": rejected,
                            "signals_refined": refined,
                        }
                elif field == "risks" and "potential_vulnerabilities" in data:
                    converted_risks = self._convert_potential_to_risks(
                        data.get("potential_vulnerabilities", [])
                    )
                    logger.debug(
                        f"[Schema Fix] 将 {len(converted_risks)} 个 potential_vulnerabilities 转换为 risks"
                    )
                    fixed[field] = converted_risks
                elif field == "vulnerabilities" and "potential_vulnerabilities" in data:
                    converted_vulns = self._convert_potential_to_risks(
                        data.get("potential_vulnerabilities", [])
                    )
                    logger.debug(
                        f"[Schema Fix] 将 {len(converted_vulns)} 个 potential_vulnerabilities 转换为 vulnerabilities"
                    )
                    fixed[field] = converted_vulns
                else:
                    fixed[field] = self._get_default_value(field_schema)
        for key in data:
            if key not in fixed:
                fixed[key] = data[key]

        if "signal_tracking" in fixed and isinstance(fixed["signal_tracking"], dict):
            if not any(
                k in fixed["signal_tracking"]
                for k in ["signals_confirmed", "signals_rejected", "signals_refined", "signals_new"]
            ):
                if schema_name == "attack_chain":
                    items = data.get("attack_chains", [])
                    if not isinstance(items, list):
                        items = []
                    confirmed = sum(
                        1
                        for v in items
                        if isinstance(v, dict) and v.get("signal_state") == "CONFIRMED"
                    )
                    rejected = sum(
                        1
                        for v in items
                        if isinstance(v, dict) and v.get("signal_state") == "REJECTED"
                    )
                    new_count = sum(
                        1 for v in items if isinstance(v, dict) and v.get("signal_state") == "NEW"
                    )
                    fixed["signal_tracking"] = {
                        "total_signals": len(items),
                        "signals_new": new_count,
                        "signals_confirmed": confirmed,
                        "signals_rejected": rejected,
                    }
                else:
                    items = data.get("vulnerabilities", data.get("risks", []))
                    if not isinstance(items, list):
                        items = []
                    confirmed = sum(
                        1
                        for v in items
                        if isinstance(v, dict) and v.get("signal_state") == "CONFIRMED"
                    )
                    rejected = sum(
                        1
                        for v in items
                        if isinstance(v, dict) and v.get("signal_state") == "REJECTED"
                    )
                    refined = sum(
                        1
                        for v in items
                        if isinstance(v, dict) and v.get("signal_state") == "REFINED"
                    )
                    new_count = sum(
                        1 for v in items if isinstance(v, dict) and v.get("signal_state") == "NEW"
                    )
                    fixed["signal_tracking"] = {
                        "total_signals": len(items),
                        "signals_new": new_count,
                        "signals_confirmed": confirmed,
                        "signals_rejected": rejected,
                        "signals_refined": refined,
                    }

        return fixed

    def _convert_potential_to_risks(
        self, potential_vulnerabilities: List[Dict]
    ) -> List[Dict[str, Any]]:
        """将 potential_vulnerabilities 转换为 risks 格式"""
        risks = []
        for i, pv in enumerate(potential_vulnerabilities):
            if isinstance(pv, dict):
                risks.append(
                    {
                        "risk_type": pv.get("type", "Unknown Risk"),
                        "severity": self._infer_severity(pv),
                        "location": pv.get("location", "Unknown"),
                        "signal_id": pv.get("signal_id", f"RISK-POTENTIAL-{i}"),
                        "signal_state": "NEW",
                        "description": pv.get("description", ""),
                        "evidence": pv.get("evidence", []),
                    }
                )
        return risks

    def _fix_item_structure(
        self, item: Dict[str, Any], item_schema: Dict[str, Any], schema_name: Optional[str] = None
    ) -> Dict[str, Any]:
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
                        "created_at": datetime.now().isoformat(),
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
                    fixed[prop] = [
                        {
                            "type": "code_line",
                            "location": item.get("location", "unknown"),
                            "reason": fixed["reason"],
                            "confidence": 0.5,
                        }
                    ]
                elif prop == "signal_id" and schema_name == "risk_enumeration":
                    risk_id = item.get("risk_id")
                    if risk_id and risk_id != "unknown":
                        fixed[prop] = risk_id
                    else:
                        risk_type = item.get("risk_type", "unknown")
                        location = item.get("location", "")
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
                        fixed[prop] = item.get("id", "SIGNAL-unknown")
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
                                fixed_items.append(
                                    self._fix_item_structure(
                                        inner_item, item_schema_inner, schema_name
                                    )
                                )
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

        high_keywords = [
            "SQL",
            "INJECT",
            "XSS",
            "CSRF",
            "COMMAND",
            "RCE",
            "PRIVILEGE",
            "AUTHENTICATION",
            "CREDENTIAL",
            "SECRET",
            "KEY",
            "PASSWORD",
            "UNSAFE",
            "DESERIALIZ",
        ]
        for kw in high_keywords:
            if kw in combined_text:
                return "HIGH"

        medium_keywords = [
            "WEAK",
            "DEFAULT",
            "SUSPICIOUS",
            "PATTERN",
            "MISSING",
            "INSUFFICIENT",
            "HARDCODED",
            "CONFIGURATION",
            "BROKEN",
            "INSECURE",
            "PATH",
            "TRAVERSAL",
        ]
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
                logger.debug(f" No JSON found in response for {schema_name}")
                emergency_result = self._emergency_fix(response_text, schema_name)
                if emergency_result:
                    logger.debug(f"  Using text extraction result for {schema_name}")
                    return emergency_result
                return None

            data = json.loads(json_str)
            validated_data, is_valid = self.validate_with_fallback(data, schema_name)

            if self._is_result_empty(validated_data, schema_name):
                logger.warning(
                    f" Validated data is empty for {schema_name}, trying text extraction"
                )
                emergency_result = self._emergency_fix(response_text, schema_name)
                if emergency_result:
                    logger.debug(f"  Using text extraction result for {schema_name}")
                    return emergency_result

            return validated_data

        except json.JSONDecodeError as e:
            logger.debug(f" JSON parse error for {schema_name}: {e}")
            emergency_result = self._emergency_fix(response_text, schema_name)
            if emergency_result:
                logger.debug(
                    f" Using text extraction after JSON error for {schema_name}"
                )
                return emergency_result
            return None
        except Exception as e:
            logger.debug(f" Unexpected error parsing {schema_name}: {e}")
            emergency_result = self._emergency_fix(response_text, schema_name)
            if emergency_result:
                logger.warning(f"  Using text extraction after exception for {schema_name}")
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
            risks = data.get("risks", [])
            return len(risks) == 0

        elif schema_name == "vulnerability":
            vulns = data.get("vulnerabilities", [])
            return len(vulns) == 0

        elif schema_name == "adversarial":
            chains = data.get("adversarial_analysis", [])
            return len(chains) == 0

        elif schema_name == "final_decision":
            findings = data.get("final_findings", [])
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
            r"\{[^{}]*\}",
            r'\{[\s\S]*"final_findings"[\s\S]*\}',
            r'\{[\s\S]*"vulnerabilities"[\s\S]*\}',
            r'\{[\s\S]*"adversarial_analysis"[\s\S]*\}',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                try:
                    json.loads(match)
                    return str(match)
                except BaseException:
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
        logger.debug(f" Attempting emergency fix for {schema_name}")

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
                        "high_severity_count": sum(
                            1 for v in vulnerabilities if v.get("severity") == "HIGH"
                        ),
                        "medium_severity_count": sum(
                            1 for v in vulnerabilities if v.get("severity") == "MEDIUM"
                        ),
                        "low_severity_count": sum(
                            1 for v in vulnerabilities if v.get("severity") == "LOW"
                        ),
                    },
                }

        elif schema_name == "risk_enumeration":
            risks = self._extract_risks_from_text(response_text)
            logger.debug(
                f"[Emergency Fix] Extracted {len(risks)} risks from raw text for {schema_name}"
            )
            if risks:
                return {
                    "risks": risks,
                    "signal_tracking": {
                        "total_signals": len(risks),
                        "signals_new": len(risks),
                        "signals_confirmed": 0,
                        "signals_rejected": 0,
                        "signals_refined": 0,
                    },
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
                        "signals_rejected": 0,
                    },
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
                        "signals_refined": 0,
                    },
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
            "LOW": ["low", "低风险", "低"],
        }

        # vulnerability_keywords = [
        #     "sql injection",
        #     "sql注入",
        #     "xss",
        #     "cross-site",
        #     "跨站",
        #     "command injection",
        #     "命令注入",
        #     "path traversal",
        #     "路径遍历",
        #     "ssrf",
        #     "服务器端请求伪造",
        #     "csrf",
        #     "跨站请求伪造",
        #     "authentication",
        #     "认证",
        #     "authorization",
        #     "授权",
        #     "sensitive data",
        #     "敏感数据",
        #     "hardcoded",
        #     "硬编码",
        # ]

        for severity, keywords in severity_keywords.items():
            for keyword in keywords:
                if keyword.lower() in text.lower():
                    vulnerabilities.append(
                        {
                            "vulnerability": f"Detected {severity} issue",
                            "location": "Unknown (extracted from text)",
                            "severity": severity,
                            "status": "UNCERTAIN",
                            "confidence": "MEDIUM",
                            "evidence": text[:500],
                            "recommendation": "Manual review required",
                            "requires_human_review": True,
                        }
                    )
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
            "INFO": ["info", "信息", "信息性"],
        }

        vuln_keywords = [
            "SQL注入",
            "SQL injection",
            "sql注入",
            "XSS",
            "跨站脚本",
            "cross-site scripting",
            "命令注入",
            "command injection",
            "命令执行",
            "路径遍历",
            "path traversal",
            "目录遍历",
            "SSRF",
            "服务器端请求伪造",
            "CSRF",
            "跨站请求伪造",
            "认证绕过",
            "authentication bypass",
            "授权绕过",
            "authorization bypass",
            "敏感信息泄露",
            "sensitive information leak",
            "硬编码",
            "hardcoded",
            "硬编码凭证",
            "反序列化",
            "deserialization",
            "反序列化漏洞",
            "越权",
            "privilege",
            "权限提升",
            "会话管理",
            "session management",
            "中间人攻击",
            "MITM",
            "man in the middle",
            "XML外部实体",
            "XXE",
            "xml external entity",
            "模板注入",
            "SSTI",
            "template injection",
            "代码注入",
            "code injection",
            "文件上传",
            "file upload",
            "任意文件上传",
            "未授权访问",
            "unauthorized access",
            "密码策略",
            "password policy",
            "弱密码",
            "JWT",
            "token泄露",
            "token leak",
            "CORS",
            "跨域",
            "cross-origin",
            "API安全",
            "api security",
            "注入",
            "injection",
        ]

        text_lower = text.lower()

        for severity, severity_terms in severity_map.items():
            for term in severity_terms:
                if term.lower() in text_lower:
                    for vuln_kw in vuln_keywords:
                        if vuln_kw.lower() in text_lower:
                            counter += 1
                            location_match = re.search(r"([A-Za-z]:\\[^:\s]+|/[^\s:]+):(\d+)", text)
                            location = (
                                location_match.group(0) if location_match else "Unknown location"
                            )

                            code_snippet_match = re.search(r'[`"\']([^`"\']{{3,100}})[`"\']', text)
                            code_snippet = code_snippet_match.group(1) if code_snippet_match else ""

                            risks.append(
                                {
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
                                    "evidence": [
                                        {
                                            "type": "code_line",
                                            "location": location,
                                            "reason": f"文本分析发现: {vuln_kw}",
                                            "confidence": 0.5,
                                            "code_snippet": code_snippet,
                                        }
                                    ],
                                    "requires_human_review": True,
                                }
                            )
                            break
                    break

        logger.debug(f" [Text Extraction] Found {len(risks)} potential risks in text")
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
            "攻击链",
            "attack chain",
            "攻击路径",
            "利用链",
            "exploitation chain",
            "利用路径",
            "漏洞组合",
            "vulnerability combination",
            "链式攻击",
            "chained attack",
        ]

        text_lower = text.lower()
        for kw in chain_keywords:
            if kw.lower() in text_lower:
                chains.append(
                    {
                        "chain_name": "Extracted Attack Chain",
                        "attack_chain_description": text[:500],
                        "signal_id": "CHAIN-TEXT-001",
                        "signal_state": "UNCERTAIN",
                        "confidence": 0.5,
                        "attack_prerequisites": "需要进一步分析",
                        "attack_steps": ["从文本提取的攻击链信息，需要人工复核"],
                        "potential_impact": "可能导致多层次安全风险",
                        "estimated_cvss": "N/A",
                        "requires_human_review": True,
                    }
                )
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
            last_error: Optional[Exception] = None
            for attempt in range(max_retries):
                try:
                    result = await func(*args, **kwargs)
                    validator = SchemaValidator()
                    is_valid, error = validator.validate(result, "final_decision")
                    if is_valid:
                        return result
                    logger.warning(f" Attempt {attempt + 1} validation failed: {error}")
                    last_error = Exception(error) if error else None
                except Exception as e:
                    last_error = e
                    logger.warning(f" Attempt {attempt + 1} failed: {e}")

            logger.warning(f" All {max_retries} attempts failed. Last error: {last_error}")
            raise SchemaValidationError(f"Failed after {max_retries} attempts: {last_error}")

        return wrapper

    return decorator


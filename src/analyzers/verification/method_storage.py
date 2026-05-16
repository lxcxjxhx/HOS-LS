from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import hashlib
import json
from dataclasses import dataclass, asdict


@dataclass
class MethodDefinition:
    """验证方法定义"""
    id: str
    name: str
    vuln_type: str
    pattern: str
    confidence_level: str
    validation: Dict[str, Any]
    poc_template: str
    evidence_required: List[str]
    version: str = "1.0"
    enabled: bool = True
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MethodDefinition':
        return cls(**data)


class MethodStorage:
    """
    验证方法存储管理器

    职责：
    - 存储和管理 POC 验证方法
    - 方法以 YAML/JSON 格式存储，可读可改
    - 支持方法版本管理
    - 支持方法热更新
    """

    def __init__(self, storage_path: str):
        self.storage_path = Path(storage_path)
        self.methods: Dict[str, MethodDefinition] = {}
        self._method_files: Dict[str, Path] = {}
        self._load_all_methods()

    def _load_all_methods(self):
        """加载所有方法文件"""
        if not self.storage_path.exists():
            self.storage_path.mkdir(parents=True, exist_ok=True)
            return

        for yaml_file in self.storage_path.glob("*.yaml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'methods' in data:
                        for method_id, method_data in data['methods'].items():
                            method_def = MethodDefinition.from_dict(method_data)
                            self.methods[method_id] = method_def
                            self._method_files[method_id] = yaml_file
            except Exception as e:
                print(f"Failed to load methods from {yaml_file}: {e}")

    def _get_method_file(self, method_id: str) -> Path:
        """获取方法对应的文件路径"""
        if method_id in self._method_files:
            return self._method_files[method_id]

        vuln_type = self.methods[method_id].vuln_type if method_id in self.methods else 'general'
        return self.storage_path / f"{vuln_type}_methods.yaml"

    def save_method(self, method_id: str, method_def: MethodDefinition) -> bool:
        """
        保存验证方法

        Args:
            method_id: 方法唯一标识
            method_def: 方法定义

        Returns:
            是否保存成功
        """
        try:
            method_def.id = method_id
            self.methods[method_id] = method_def

            yaml_file = self._get_method_file(method_id)
            self._method_files[method_id] = yaml_file

            self._save_to_file(yaml_file)
            return True
        except Exception as e:
            print(f"Failed to save method {method_id}: {e}")
            return False

    def _save_to_file(self, yaml_file: Path):
        """保存方法到文件"""
        methods_in_file = {
            mid: self.methods[mid].to_dict()
            for mid in self.methods
            if self._method_files.get(mid) == yaml_file
        }

        data = {'methods': methods_in_file}

        with open(yaml_file, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)

    def load_method(self, method_id: str) -> Optional[MethodDefinition]:
        """
        加载验证方法

        Args:
            method_id: 方法ID

        Returns:
            方法定义，如果不存在返回 None
        """
        return self.methods.get(method_id)

    def list_methods(self, vuln_type: str = None) -> List[MethodDefinition]:
        """
        列出验证方法

        Args:
            vuln_type: 漏洞类型过滤（可选）

        Returns:
            方法定义列表
        """
        if vuln_type is None:
            return list(self.methods.values())

        return [
            method for method in self.methods.values()
            if method.vuln_type == vuln_type
        ]

    def list_method_ids(self, vuln_type: str = None) -> List[str]:
        """
        列出方法ID

        Args:
            vuln_type: 漏洞类型过滤（可选）

        Returns:
            方法ID列表
        """
        if vuln_type is None:
            return list(self.methods.keys())

        return [
            method_id for method_id, method in self.methods.items()
            if method.vuln_type == vuln_type
        ]

    def validate_method(self, method_id: str) -> bool:
        """
        验证方法格式和语法

        Args:
            method_id: 方法ID

        Returns:
            是否有效
        """
        if method_id not in self.methods:
            return False

        method = self.methods[method_id]

        required_fields = ['id', 'name', 'vuln_type', 'pattern', 'confidence_level', 'validation', 'poc_template']
        for field in required_fields:
            if not hasattr(method, field) or getattr(method, field) is None:
                return False

        valid_confidence = ['high', 'medium', 'low']
        if method.confidence_level not in valid_confidence:
            return False

        return True

    def get_method_code(self, method_id: str) -> Optional[str]:
        """
        获取方法的可执行代码

        Args:
            method_id: 方法ID

        Returns:
            Python 代码字符串，如果方法无效返回 None
        """
        method = self.methods.get(method_id)
        if method is None:
            return None

        return self._generate_method_code(method)

    def _generate_method_code(self, method: MethodDefinition) -> str:
        """根据方法定义生成可执行代码"""
        code = f'''
def verify_{method.id.replace('-', '_')}(context: VulnContext) -> ValidationResult:
    """
    {method.name}

    漏洞类型: {method.vuln_type}
    模式: {method.pattern}
    置信度: {method.confidence_level}

    验证步骤:
    {chr(10).join(f"    - {step}" for step in method.validation.get('steps', []))}
    """
    from typing import Any, Dict, List

    code_snippet = context.code_snippet
    project_root = context.project_root

    # POC 模板
    poc_template = """
{method.poc_template}
    """

    # 验证逻辑
    # TODO: 根据 {method.id} 的验证步骤实现具体逻辑

    return ValidationResult(
        is_valid=True,
        is_false_positive=False,
        confidence=0.{method.confidence_level == 'high' and '8' or method.confidence_level == 'medium' and '6' or '4'},
        reason="验证通过",
        evidence={{}}
    )
'''
        return code

    def delete_method(self, method_id: str) -> bool:
        """
        删除方法

        Args:
            method_id: 方法ID

        Returns:
            是否删除成功
        """
        if method_id not in self.methods:
            return False

        try:
            del self.methods[method_id]
            yaml_file = self._method_files.get(method_id)
            if yaml_file:
                del self._method_files[method_id]
                self._save_to_file(yaml_file)
            return True
        except Exception as e:
            print(f"Failed to delete method {method_id}: {e}")
            return False

    def enable_method(self, method_id: str, enabled: bool = True) -> bool:
        """
        启用/禁用方法

        Args:
            method_id: 方法ID
            enabled: 是否启用

        Returns:
            是否操作成功
        """
        if method_id not in self.methods:
            return False

        try:
            self.methods[method_id].enabled = enabled
            yaml_file = self._method_files.get(method_id)
            if yaml_file:
                self._save_to_file(yaml_file)
            return True
        except Exception as e:
            print(f"Failed to {'enable' if enabled else 'disable'} method {method_id}: {e}")
            return False

    def get_method_hash(self, method_id: str) -> Optional[str]:
        """
        获取方法的哈希值（用于版本管理）

        Args:
            method_id: 方法ID

        Returns:
            方法的 SHA256 哈希值
        """
        method = self.methods.get(method_id)
        if method is None:
            return None

        method_str = json.dumps(method.to_dict(), sort_keys=True)
        return hashlib.sha256(method_str.encode()).hexdigest()

    def reload(self):
        """重新加载所有方法"""
        self.methods.clear()
        self._method_files.clear()
        self._load_all_methods()

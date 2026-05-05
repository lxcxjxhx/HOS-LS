"""API 密钥管理器模块

统一管理多个提供商的 API 密钥，支持加密存储和轮换。
"""

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class ProviderType(Enum):
    """提供商类型"""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"
    GOOGLE = "google"
    AZURE = "azure"
    CUSTOM = "custom"


class KeyStatus(Enum):
    """密钥状态"""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"


@dataclass
class APIKey:
    """API 密钥"""

    provider: ProviderType
    key: str
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    usage_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "provider": self.provider.value,
            "key": self.key,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "usage_count": self.usage_count,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "APIKey":
        """从字典创建"""
        return cls(
            provider=ProviderType(data["provider"]),
            key=data["key"],
            status=KeyStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data["expires_at"] else None,
            last_used_at=datetime.fromisoformat(data["last_used_at"]) if data["last_used_at"] else None,
            usage_count=data.get("usage_count", 0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class KeyConfig:
    """密钥配置"""

    auto_rotate: bool = True
    rotation_days: int = 30
    key_file: Optional[str] = None
    encryption_key: Optional[str] = None
    max_keys_per_provider: int = 5


class APIKeyManager:
    """API 密钥管理器

    统一管理多个提供商的 API 密钥。
    """

    def __init__(self, config_manager: Optional[Any] = None, config: Optional[KeyConfig] = None):
        """初始化 API 密钥管理器

        Args:
            config_manager: 配置管理器
            config: 密钥配置
        """
        self.config_manager = config_manager
        self.config = config or KeyConfig()

        self._keys: Dict[str, List[APIKey]] = {}
        self._encryption_key: Optional[bytes] = None
        self._load_encryption_key()
        self._load_keys()

    def get_api_key(self, provider: Union[ProviderType, str]) -> str:
        """获取 API 密钥

        Args:
            provider: 提供商

        Returns:
            API 密钥

        Raises:
            ValueError: 没有可用的 API 密钥
        """
        if isinstance(provider, str):
            try:
                provider = ProviderType(provider.lower())
            except ValueError:
                raise ValueError(f"Invalid provider: {provider}")

        provider_key = provider.value
        keys = self._keys.get(provider_key, [])

        valid_keys = [
            key for key in keys
            if key.status == KeyStatus.ACTIVE and 
            (key.expires_at is None or key.expires_at > datetime.now())
        ]

        if not valid_keys:
            raise ValueError(f"No valid API keys for provider: {provider.value}")

        # 选择使用频率最低的密钥
        key = min(valid_keys, key=lambda k: k.usage_count)
        key.usage_count += 1
        key.last_used_at = datetime.now()

        self._save_keys()
        return key.key

    def set_api_key(
        self,
        provider: Union[ProviderType, str],
        api_key: str,
        encrypt: bool = True,
        expires_days: Optional[int] = None,
    ) -> APIKey:
        """设置 API 密钥

        Args:
            provider: 提供商
            api_key: API 密钥
            encrypt: 是否加密
            expires_days: 过期天数

        Returns:
            API 密钥对象
        """
        if isinstance(provider, str):
            try:
                provider = ProviderType(provider.lower())
            except ValueError:
                raise ValueError(f"Invalid provider: {provider}")

        provider_key = provider.value

        if encrypt and CRYPTO_AVAILABLE:
            api_key = self._encrypt(api_key)

        expires_at = None
        if expires_days:
            expires_at = datetime.now() + timedelta(days=expires_days)

        api_key_obj = APIKey(
            provider=provider,
            key=api_key,
            expires_at=expires_at,
        )

        if provider_key not in self._keys:
            self._keys[provider_key] = []

        # 限制每个提供商的密钥数量
        if len(self._keys[provider_key]) >= self.config.max_keys_per_provider:
            # 删除最旧的密钥
            self._keys[provider_key].sort(key=lambda k: k.created_at)
            self._keys[provider_key] = self._keys[provider_key][-self.config.max_keys_per_provider + 1:]

        self._keys[provider_key].append(api_key_obj)
        self._save_keys()

        return api_key_obj

    def rotate_key(self, provider: Union[ProviderType, str]) -> APIKey:
        """轮换 API 密钥

        Args:
            provider: 提供商

        Returns:
            新的 API 密钥对象

        Raises:
            ValueError: 没有可用的 API 密钥
        """
        if isinstance(provider, str):
            try:
                provider = ProviderType(provider.lower())
            except ValueError:
                raise ValueError(f"Invalid provider: {provider}")

        provider_key = provider.value
        keys = self._keys.get(provider_key, [])

        if not keys:
            raise ValueError(f"No API keys for provider: {provider.value}")

        # 撤销所有旧密钥
        for key in keys:
            key.status = KeyStatus.REVOKED

        # 生成新的占位密钥
        new_key = APIKey(
            provider=provider,
            key="NEW_KEY_PLACEHOLDER",
            status=KeyStatus.PENDING,
        )

        self._keys[provider_key].append(new_key)
        self._save_keys()

        return new_key

    def validate_key(self, provider: Union[ProviderType, str], api_key: str) -> bool:
        """验证 API 密钥

        Args:
            provider: 提供商
            api_key: API 密钥

        Returns:
            是否有效
        """
        if isinstance(provider, str):
            try:
                provider = ProviderType(provider.lower())
            except ValueError:
                return False

        provider_key = provider.value
        keys = self._keys.get(provider_key, [])

        for key in keys:
            if key.status == KeyStatus.ACTIVE:
                stored_key = key.key
                if CRYPTO_AVAILABLE:
                    try:
                        stored_key = self._decrypt(stored_key)
                    except Exception:
                        pass

                if stored_key == api_key:
                    return True

        return False

    def get_all_keys(self, provider: Optional[Union[ProviderType, str]] = None) -> List[APIKey]:
        """获取所有密钥

        Args:
            provider: 提供商（可选）

        Returns:
            API 密钥列表
        """
        if provider:
            if isinstance(provider, str):
                try:
                    provider = ProviderType(provider.lower())
                except ValueError:
                    return []
            return self._keys.get(provider.value, [])
        else:
            all_keys = []
            for keys in self._keys.values():
                all_keys.extend(keys)
            return all_keys

    def revoke_key(self, key_id: str) -> bool:
        """撤销密钥

        Args:
            key_id: 密钥 ID

        Returns:
            是否成功
        """
        for provider, keys in self._keys.items():
            for key in keys:
                if self._get_key_id(key) == key_id:
                    key.status = KeyStatus.REVOKED
                    self._save_keys()
                    return True
        return False

    def get_key_info(self, key_id: str) -> Optional[APIKey]:
        """获取密钥信息

        Args:
            key_id: 密钥 ID

        Returns:
            API 密钥对象
        """
        for provider, keys in self._keys.items():
            for key in keys:
                if self._get_key_id(key) == key_id:
                    return key
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息
        """
        stats = {
            "total_keys": 0,
            "by_provider": {},
            "by_status": {},
            "expiring_soon": 0,
        }

        for provider, keys in self._keys.items():
            stats["total_keys"] += len(keys)
            stats["by_provider"][provider] = len(keys)

            for key in keys:
                status = key.status.value
                stats["by_status"][status] = stats["by_status"].get(status, 0) + 1

                if key.expires_at:
                    if key.expires_at - datetime.now() < timedelta(days=7):
                        stats["expiring_soon"] += 1

        return stats

    def cleanup_expired_keys(self) -> int:
        """清理过期密钥

        Returns:
            清理的密钥数量
        """
        count = 0
        for provider, keys in self._keys.items():
            valid_keys = [
                key for key in keys
                if not (key.status == KeyStatus.ACTIVE and 
                        key.expires_at and 
                        key.expires_at < datetime.now())
            ]
            count += len(keys) - len(valid_keys)
            self._keys[provider] = valid_keys

        if count > 0:
            self._save_keys()

        return count

    def _load_encryption_key(self) -> None:
        """加载加密密钥"""
        if not CRYPTO_AVAILABLE:
            return

        if self.config.encryption_key:
            self._encryption_key = self.config.encryption_key.encode()
        else:
            key_file = self.config.key_file or Path.home() / ".api_key_encryption_key"
            if key_file.exists():
                try:
                    with open(key_file, "rb") as f:
                        self._encryption_key = f.read()
                except Exception:
                    self._encryption_key = self._generate_encryption_key()
            else:
                self._encryption_key = self._generate_encryption_key()

    def _generate_encryption_key(self) -> bytes:
        """生成加密密钥"""
        key = Fernet.generate_key()

        if self.config.key_file:
            key_file = Path(self.config.key_file)
        else:
            key_file = Path.home() / ".api_key_encryption_key"

        try:
            key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(key)
            key_file.chmod(0o600)
        except Exception:
            pass

        return key

    def _encrypt(self, data: str) -> str:
        """加密数据

        Args:
            data: 要加密的数据

        Returns:
            加密后的数据
        """
        if not CRYPTO_AVAILABLE or not self._encryption_key:
            return data

        try:
            f = Fernet(self._encryption_key)
            encrypted = f.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception:
            return data

    def _decrypt(self, data: str) -> str:
        """解密数据

        Args:
            data: 要解密的数据

        Returns:
            解密后的数据
        """
        if not CRYPTO_AVAILABLE or not self._encryption_key:
            return data

        try:
            encrypted = base64.b64decode(data.encode())
            f = Fernet(self._encryption_key)
            decrypted = f.decrypt(encrypted)
            return decrypted.decode()
        except Exception:
            return data

    def _load_keys(self) -> None:
        """加载密钥"""
        if self.config_manager and hasattr(self.config_manager, "get"):
            keys_data = self.config_manager.get("api_keys", {})
            self._load_from_dict(keys_data)
        else:
            key_file = self.config.key_file or Path.home() / ".api_keys.json"
            if key_file.exists():
                try:
                    with open(key_file, "r", encoding="utf-8") as f:
                        keys_data = json.load(f)
                        self._load_from_dict(keys_data)
                except Exception:
                    pass

    def _save_keys(self) -> None:
        """保存密钥"""
        keys_data = self._to_dict()

        if self.config_manager and hasattr(self.config_manager, "set"):
            self.config_manager.set("api_keys", keys_data)
        else:
            key_file = self.config.key_file or Path.home() / ".api_keys.json"
            try:
                key_file.parent.mkdir(parents=True, exist_ok=True)
                with open(key_file, "w", encoding="utf-8") as f:
                    json.dump(keys_data, f, indent=2, ensure_ascii=False)
                key_file.chmod(0o600)
            except Exception:
                pass

    def _load_from_dict(self, data: Dict[str, Any]) -> None:
        """从字典加载密钥"""
        for provider, keys_data in data.items():
            self._keys[provider] = [APIKey.from_dict(k) for k in keys_data]

    def _to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {}
        for provider, keys in self._keys.items():
            result[provider] = [k.to_dict() for k in keys]
        return result

    def _get_key_id(self, key: APIKey) -> str:
        """获取密钥 ID

        Args:
            key: API 密钥

        Returns:
            密钥 ID
        """
        content = f"{key.provider.value}:{key.created_at.isoformat()}:{key.key[:10]}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# 全局 API 密钥管理器实例
_api_key_manager: Optional[APIKeyManager] = None


def get_api_key_manager() -> APIKeyManager:
    """获取全局 API 密钥管理器

    Returns:
        API 密钥管理器实例
    """
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = APIKeyManager()
    return _api_key_manager


def get_api_key(provider: str) -> str:
    """获取 API 密钥

    Args:
        provider: 提供商

    Returns:
        API 密钥
    """
    return get_api_key_manager().get_api_key(provider)


def set_api_key(provider: str, api_key: str) -> APIKey:
    """设置 API 密钥

    Args:
        provider: 提供商
        api_key: API 密钥

    Returns:
        API 密钥对象
    """
    return get_api_key_manager().set_api_key(provider, api_key)

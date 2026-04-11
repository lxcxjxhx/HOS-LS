"""
凭证管理系统

提供安全的凭证存储和管理功能。
使用 AES-256-GCM 加密算法保护敏感信息。
"""

import os
import json
import base64
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from rich.console import Console

console = Console()


@dataclass
class Credential:
    """凭证数据类"""
    name: str
    credential_type: str  # password, api_key, ssh_key, token, etc.
    value: str
    username: Optional[str] = None
    host: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        if self.expires_at:
            return datetime.now() > self.expires_at
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.credential_type,
            'has_value': bool(self.value),
            'username': self.username,
            'host': self.host,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_expired': self.is_expired()
        }


class CredentialManager:
    """
    凭证管理器
    
    功能：
    - AES-256-GCM 加密存储
    - 支持环境变量引用
    - 凭证过期管理
    - 审计日志记录
    """
    
    DEFAULT_KEY_FILE = Path.home() / ".hos-ls" / "credentials.enc"
    DEFAULT_SALT_FILE = Path.home() / ".hos-ls" / ".salt"
    
    def __init__(
        self,
        master_password: str = None,
        key_file: Path = None,
        auto_load: bool = True
    ):
        self.master_password = master_password or os.environ.get(
            'HOS_LS_MASTER_PASSWORD',
            'default-insecure-password'
        )
        self.key_file = key_file or self.DEFAULT_KEY_FILE
        self.salt_file = self.DEFAULT_SALT_FILE
        
        self._fernet: Optional[Fernet] = None
        self._credentials: Dict[str, Credential] = {}
        self._audit_log: List[Dict] = []
        
        if auto_load and CRYPTO_AVAILABLE:
            self._initialize_encryption()
    
    def _initialize_encryption(self):
        """初始化加密组件"""
        try:
            salt = self._get_or_create_salt()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            
            key = base64.urlsafe_b64encode(
                kdf.derive(self.master_password.encode())
            )
            
            self._fernet = Fernet(key)
            
        except Exception as e:
            console.print(f"[red]初始化加密失败: {e}[/red]")
    
    def _get_or_create_salt(self) -> bytes:
        """获取或创建盐值"""
        if self.salt_file.exists():
            with open(self.salt_file, 'rb') as f:
                return f.read()
        
        salt = os.urandom(16)
        self.salt_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        
        return salt
    
    def store_credential(
        self,
        name: str,
        value: str,
        credential_type: str = "password",
        username: str = None,
        host: str = None,
        expires_in_days: int = None,
        **metadata
    ) -> Credential:
        """
        存储凭证
        
        Args:
            name: 凭证名称
            value: 凭证值（将被加密）
            credential_type: 凭证类型
            username: 关联用户名
            host: 关联主机
            expires_in_days: 过期天数
            
        Returns:
            创建的凭证对象
        """
        if not CRYPTO_AVAILABLE or not self._fernet:
            raise RuntimeError("加密组件未初始化")
        
        encrypted_value = self._fernet.encrypt(value.encode()).decode()
        
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)
        
        credential = Credential(
            name=name,
            credential_type=credential_type,
            value=encrypted_value,
            username=username,
            host=host,
            expires_at=expires_at,
            metadata=metadata
        )
        
        self._credentials[name] = credential
        
        self._log_action('store', name, credential_type)
        
        console.print(f"[green]✓ 凭证已安全存储: {name}[/green]")
        
        return credential
    
    def get_credential(self, name: str) -> Optional[Credential]:
        """
        获取凭证（解密）
        
        Args:
            name: 凭证名称
            
        Returns:
            凭证对象（值已解密）
        """
        if not CRYPTO_AVAILABLE or not self._fernet:
            raise RuntimeError("加密组件未初始化")
        
        credential = self._credentials.get(name)
        
        if not credential:
            return None
        
        if credential.is_expired():
            console.print(f"[yellow]警告: 凭证已过期: {name}[/yellow]")
        
        try:
            decrypted_value = self._fernet.decrypt(credential.value.encode()).decode()
            
            decrypted_credential = Credential(
                name=credential.name,
                credential_type=credential.credential_type,
                value=decrypted_value,
                username=credential.username,
                host=credential.host,
                created_at=credential.created_at,
                expires_at=credential.expires_at,
                metadata=credential.metadata
            )
            
            self._log_action('retrieve', name, credential.credential_type)
            
            return decrypted_credential
            
        except Exception as e:
            console.print(f"[red]解密凭证失败 {name}: {e}[/red]")
            return None
    
    def delete_credential(self, name: str) -> bool:
        """
        删除凭证
        
        Args:
            name: 凭证名称
            
        Returns:
            是否删除成功
        """
        if name in self._credentials:
            del self._credentials[name]
            self._log_action('delete', name, 'unknown')
            console.print(f"[green]✓ 凭证已删除: {name}[/green]")
            return True
        
        return False
    
    def list_credentials(self, show_values: bool = False) -> List[Dict]:
        """
        列出所有凭证
        
        Args:
            show_values: 是否显示解密后的值（不推荐）
            
        Returns:
            凭证信息列表
        """
        results = []
        
        for name, cred in self._credentials.items():
            info = cred.to_dict()
            
            if show_values:
                full_cred = self.get_credential(name)
                if full_cred:
                    info['value'] = full_cred.value
            
            results.append(info)
        
        return results
    
    def resolve_environment_variable(self, value: str) -> str:
        """
        解析环境变量引用
        
        支持格式：${VAR_NAME}
        
        Args:
            value: 可能包含环境变量引用的字符串
            
        Returns:
            解析后的字符串
        """
        import re
        
        pattern = r'\$\{(\w+)\}'
        
        def replace_env_var(match):
            var_name = match.group(1)
            env_value = os.environ.get(var_name)
            
            if env_value is None:
                console.print(
                    f"[yellow]警告: 环境变量 {var_name} 未定义[/yellow]"
                )
                return match.group(0)
            
            return env_value
        
        return re.sub(pattern, replace_env_var, value)
    
    def save_to_file(self, file_path: Path = None) -> bool:
        """
        将凭证保存到文件（加密存储）
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否保存成功
        """
        if not CRYPTO_AVAILABLE or not self._fernet:
            return False
        
        file_path = file_path or self.key_file
        
        try:
            data = {
                'version': '1.0',
                'created_at': datetime.now().isoformat(),
                'credentials': {
                    name: {
                        'encrypted_value': cred.value,
                        'type': cred.credential_type,
                        'username': cred.username,
                        'host': cred.host,
                        'expires_at': cred.expires_at.isoformat() if cred.expires_at else None,
                        'metadata': cred.metadata
                    }
                    for name, cred in self._credentials.items()
                }
            }
            
            json_data = json.dumps(data, indent=2)
            encrypted_data = self._fernet.encrypt(json_data.encode())
            
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            self._log_action('save', str(file_path), 'file')
            
            console.print(f"[green]✓ 凭证已保存到: {file_path}[/green]")
            
            return True
            
        except Exception as e:
            console.print(f"[red]保存凭证失败: {e}[/red]")
            return False
    
    def load_from_file(self, file_path: Path = None) -> bool:
        """
        从文件加载凭证
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否加载成功
        """
        if not CRYPTO_AVAILABLE or not self._fernet:
            return False
        
        file_path = file_path or self.key_file
        
        if not file_path.exists():
            return False
        
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            json_data = self._fernet.decrypt(encrypted_data).decode()
            data = json.loads(json_data)
            
            for name, cred_data in data.get('credentials', {}).items():
                credential = Credential(
                    name=name,
                    credential_type=cred_data.get('type', 'password'),
                    value=cred_data['encrypted_value'],
                    username=cred_data.get('username'),
                    host=cred_data.get('host'),
                    expires_at=datetime.fromisoformat(cred_data['expires_at']) if cred_data.get('expires_at') else None,
                    metadata=cred_data.get('metadata', {})
                )
                
                self._credentials[name] = credential
            
            self._log_action('load', str(file_path), 'file')
            
            console.print(f"[green]✓ 已从文件加载 {len(self._credentials)} 个凭证[/green]")
            
            return True
            
        except Exception as e:
            console.print(f"[red]加载凭证失败: {e}[/red]")
            return False
    
    def _log_action(self, action: str, target: str, cred_type: str):
        """记录审计日志"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'target': target,
            'type': cred_type
        }
        
        self._audit_log.append(log_entry)
        
        if len(self._audit_log) > 1000:
            self._audit_log = self._audit_log[-500:]
    
    def get_audit_log(self, limit: int = 50) -> List[Dict]:
        """获取审计日志"""
        return self._audit_log[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self._credentials)
        expired = sum(1 for c in self._credentials.values() if c.is_expired())
        
        type_counts = {}
        for c in self._credentials.values():
            type_counts[c.credential_type] = type_counts.get(c.credential_type, 0) + 1
        
        return {
            'total_credentials': total,
            'expired_credentials': expired,
            'active_credentials': total - expired,
            'by_type': type_counts,
            'audit_log_entries': len(self._audit_log),
            'encryption_enabled': CRYPTO_AVAILABLE and self._fernet is not None
        }


def create_credential_manager(master_password: str = None) -> CredentialManager:
    """
    创建凭证管理器实例
    
    Args:
        master_password: 主密码（或使用环境变量 HOS_LS_MASTER_PASSWORD）
        
    Returns:
        凭证管理器实例
    """
    return CredentialManager(master_password=master_password)


def resolve_connection_credentials(config_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    解析连接配置中的凭证
    
    自动处理：
    - 环境变量引用 (${VAR})
    - 凭证管理器查找
    - 直接值
    
    Args:
        config_dict: 连接配置字典
        
    Returns:
        解析后的配置字典
    """
    manager = create_credential_manager()
    
    credentials = config_dict.get('credentials', {})
    resolved_credentials = {}
    
    for key, value in credentials.items():
        if isinstance(value, str) and '${' in value:
            resolved_credentials[key] = manager.resolve_environment_variable(value)
        elif isinstance(value, str):
            stored_cred = manager.get_credential(value)
            if stored_cred:
                resolved_credentials[key] = stored_cred.value
            else:
                resolved_credentials[key] = value
        else:
            resolved_credentials[key] = value
    
    result = config_dict.copy()
    result['credentials'] = resolved_credentials
    
    return result

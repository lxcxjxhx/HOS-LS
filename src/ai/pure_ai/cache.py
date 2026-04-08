import os
import hashlib
import json
from pathlib import Path
from typing import Dict, Any, Optional
import time

class CacheManager:
    """缓存管理器
    
    管理分析结果的缓存，提高性能
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化缓存管理器
        
        Args:
            config: 配置参数
        """
        self.config = config or {}
        self.cache_dir = Path(self.config.get('cache_dir', '.cache/hos-ls/pure-ai'))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = self.config.get('cache_ttl', 86400)  # 24小时
    
    def get_file_hash(self, file_path: str) -> str:
        """计算文件哈希值
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件哈希值
        """
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            return hashlib.sha256(content).hexdigest()
        except Exception:
            return None
    
    def get_cache_key(self, file_path: str) -> str:
        """生成缓存键
        
        Args:
            file_path: 文件路径
            
        Returns:
            缓存键
        """
        file_hash = self.get_file_hash(file_path)
        if file_hash:
            return f"{file_hash}.json"
        return None
    
    def get(self, file_path: str) -> Optional[Dict[str, Any]]:
        """获取缓存的分析结果
        
        Args:
            file_path: 文件路径
            
        Returns:
            缓存的分析结果，如果不存在或已过期则返回None
        """
        cache_key = self.get_cache_key(file_path)
        if not cache_key:
            return None
        
        cache_file = self.cache_dir / cache_key
        if not cache_file.exists():
            return None
        
        # 检查缓存是否过期
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            timestamp = data.get('timestamp', 0)
            if time.time() - timestamp > self.cache_ttl:
                # 缓存过期，删除
                os.remove(cache_file)
                return None
            
            return data.get('result')
        except Exception:
            # 缓存文件损坏，删除
            if cache_file.exists():
                os.remove(cache_file)
            return None
    
    def set(self, file_path: str, result: Dict[str, Any]) -> bool:
        """缓存分析结果
        
        Args:
            file_path: 文件路径
            result: 分析结果
            
        Returns:
            是否缓存成功
        """
        cache_key = self.get_cache_key(file_path)
        if not cache_key:
            return False
        
        try:
            cache_file = self.cache_dir / cache_key
            data = {
                'timestamp': time.time(),
                'result': result,
                'file_path': file_path
            }
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception:
            return False
    
    def invalidate(self, file_path: str) -> bool:
        """使缓存失效
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否成功使缓存失效
        """
        cache_key = self.get_cache_key(file_path)
        if not cache_key:
            return False
        
        cache_file = self.cache_dir / cache_key
        if cache_file.exists():
            try:
                os.remove(cache_file)
                return True
            except Exception:
                pass
        return False
    
    def clear(self) -> bool:
        """清除所有缓存
        
        Returns:
            是否成功清除缓存
        """
        try:
            for cache_file in self.cache_dir.glob('*.json'):
                os.remove(cache_file)
            return True
        except Exception:
            return False
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息
        
        Returns:
            缓存统计信息
        """
        try:
            cache_files = list(self.cache_dir.glob('*.json'))
            valid_count = 0
            expired_count = 0
            
            for cache_file in cache_files:
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    timestamp = data.get('timestamp', 0)
                    if time.time() - timestamp > self.cache_ttl:
                        expired_count += 1
                    else:
                        valid_count += 1
                except Exception:
                    expired_count += 1
            
            return {
                'total_files': len(cache_files),
                'valid_files': valid_count,
                'expired_files': expired_count,
                'cache_dir': str(self.cache_dir),
                'cache_ttl': self.cache_ttl
            }
        except Exception:
            return {
                'error': '无法获取缓存统计信息'
            }

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
        # 支持 --pure-ai-cache-ttl 配置，默认7天
        self.cache_ttl = self._parse_ttl(self.config.get('cache_ttl', '7d'))
        # 语义指纹缓存
        self.semantic_cache_dir = self.cache_dir / 'semantic'
        self.semantic_cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _parse_ttl(self, ttl_str: str) -> int:
        """解析TTL配置
        
        Args:
            ttl_str: TTL字符串，如 "7d"、"24h"
            
        Returns:
            TTL值（秒）
        """
        try:
            if isinstance(ttl_str, int):
                return ttl_str
            
            ttl_str = str(ttl_str).strip().lower()
            if ttl_str.endswith('d'):
                return int(ttl_str[:-1]) * 86400  # 天
            elif ttl_str.endswith('h'):
                return int(ttl_str[:-1]) * 3600  # 小时
            elif ttl_str.endswith('m'):
                return int(ttl_str[:-1]) * 60  # 分钟
            else:
                return int(ttl_str)  # 秒
        except Exception:
            return 7 * 86400  # 默认7天
    
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
    
    def get_semantic_hash(self, function_code: str) -> str:
        """计算函数语义哈希
        
        Args:
            function_code: 函数代码
            
        Returns:
            32位语义哈希
        """
        try:
            # 简单的语义哈希实现
            # 移除空白和注释，只保留核心逻辑
            import re
            # 移除注释
            code = re.sub(r'#.*$', '', function_code, flags=re.MULTILINE)
            # 移除空白
            code = re.sub(r'\s+', '', code)
            # 计算哈希
            hash_obj = hashlib.sha256(code.encode('utf-8'))
            # 返回前32位
            return hash_obj.hexdigest()[:8]
        except Exception:
            return None
    
    def get_semantic_cache_key(self, function_name: str, semantic_hash: str) -> str:
        """生成语义缓存键
        
        Args:
            function_name: 函数名
            semantic_hash: 语义哈希
            
        Returns:
            语义缓存键
        """
        return f"semantic_{function_name}_{semantic_hash}.json"
    
    def get_semantic_cache(self, function_name: str, semantic_hash: str) -> Optional[Dict[str, Any]]:
        """获取语义缓存
        
        Args:
            function_name: 函数名
            semantic_hash: 语义哈希
            
        Returns:
            缓存的分析结果
        """
        cache_key = self.get_semantic_cache_key(function_name, semantic_hash)
        cache_file = self.semantic_cache_dir / cache_key
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
            
            timestamp = data.get('timestamp', 0)
            if time.time() - timestamp > self.cache_ttl:
                try:
                    os.remove(cache_file)
                except Exception:
                    pass
                return None
            
            return data.get('result')
        except Exception:
            if cache_file.exists():
                try:
                    os.remove(cache_file)
                except Exception:
                    pass
            return None
    
    def set_semantic_cache(self, function_name: str, semantic_hash: str, result: Dict[str, Any]) -> bool:
        """设置语义缓存
        
        Args:
            function_name: 函数名
            semantic_hash: 语义哈希
            result: 分析结果
            
        Returns:
            是否缓存成功
        """
        cache_key = self.get_semantic_cache_key(function_name, semantic_hash)
        try:
            cache_file = self.semantic_cache_dir / cache_key
            data = {
                'timestamp': time.time(),
                'result': result,
                'function_name': function_name,
                'semantic_hash': semantic_hash
            }
            
            with open(cache_file, 'w', encoding='utf-8', errors='replace') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception:
            return False
    
    def get_cache_key(self, file_path: str) -> str:
        """生成缓存键
        
        Args:
            file_path: 文件路径
            
        Returns:
            缓存键
        """
        file_hash = self.get_file_hash(file_path)
        if file_hash:
            # 添加文件修改时间到缓存键，确保文件修改后缓存失效
            try:
                mtime = str(int(os.path.getmtime(file_path)))
                return f"{file_hash}_{mtime}.json"
            except Exception:
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
            # 尝试清理旧的缓存文件
            self._clean_old_cache_files(file_path)
            return None
        
        # 检查缓存是否过期
        try:
            with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
            
            timestamp = data.get('timestamp', 0)
            # 根据文件大小动态调整缓存过期时间
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            dynamic_ttl = self._get_dynamic_ttl(file_size)
            
            if time.time() - timestamp > dynamic_ttl:
                # 缓存过期，删除
                try:
                    os.remove(cache_file)
                except Exception:
                    pass
                return None
            
            return data.get('result')
        except Exception:
            # 缓存文件损坏，删除
            if cache_file.exists():
                try:
                    os.remove(cache_file)
                except Exception:
                    pass
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
            # 获取文件大小
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            data = {
                'timestamp': time.time(),
                'result': result,
                'file_path': file_path,
                'file_size': file_size
            }
            
            with open(cache_file, 'w', encoding='utf-8', errors='replace') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            # 定期清理过期缓存
            if time.time() % 10 == 0:  # 每10次缓存操作清理一次
                self._clean_expired_cache()
            
            return True
        except Exception:
            return False
    
    def _get_dynamic_ttl(self, file_size: int) -> int:
        """根据文件大小动态调整缓存过期时间
        
        Args:
            file_size: 文件大小（字节）
            
        Returns:
            动态过期时间（秒）
        """
        # 小文件（< 10KB）缓存时间较短
        if file_size < 10240:
            return self.cache_ttl // 2  # 12小时
        # 大文件（> 1MB）缓存时间较长
        elif file_size > 1048576:
            return self.cache_ttl * 2  # 48小时
        # 中等文件使用默认缓存时间
        else:
            return self.cache_ttl
    
    def _clean_old_cache_files(self, file_path: str) -> None:
        """清理旧的缓存文件
        
        Args:
            file_path: 文件路径
        """
        try:
            file_hash = self.get_file_hash(file_path)
            if not file_hash:
                return
            
            # 查找并删除旧的缓存文件
            for cache_file in self.cache_dir.glob(f"{file_hash}_*.json"):
                try:
                    os.remove(cache_file)
                except Exception:
                    pass
        except Exception:
            pass
    
    def _clean_expired_cache(self) -> None:
        """清理过期的缓存文件
        """
        try:
            current_time = time.time()
            for cache_file in self.cache_dir.glob('*.json'):
                try:
                    with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
                        data = json.load(f)
                    
                    timestamp = data.get('timestamp', 0)
                    file_size = data.get('file_size', 0)
                    dynamic_ttl = self._get_dynamic_ttl(file_size)
                    
                    if current_time - timestamp > dynamic_ttl:
                        os.remove(cache_file)
                except Exception:
                    # 缓存文件损坏，删除
                    try:
                        os.remove(cache_file)
                    except Exception:
                        pass
        except Exception:
            pass
    
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
            # 清除常规缓存
            for cache_file in self.cache_dir.glob('*.json'):
                try:
                    os.remove(cache_file)
                except Exception:
                    pass
            # 清除语义缓存
            for cache_file in self.semantic_cache_dir.glob('*.json'):
                try:
                    os.remove(cache_file)
                except Exception:
                    pass
            return True
        except Exception:
            return False
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息
        
        Returns:
            缓存统计信息
        """
        try:
            # 常规缓存统计
            cache_files = list(self.cache_dir.glob('*.json'))
            semantic_cache_files = list(self.semantic_cache_dir.glob('*.json'))
            
            valid_count = 0
            expired_count = 0
            
            for cache_file in cache_files:
                try:
                    with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
                        data = json.load(f)
                    timestamp = data.get('timestamp', 0)
                    if time.time() - timestamp > self.cache_ttl:
                        expired_count += 1
                    else:
                        valid_count += 1
                except Exception:
                    expired_count += 1
            
            # 语义缓存统计
            semantic_valid_count = 0
            semantic_expired_count = 0
            
            for cache_file in semantic_cache_files:
                try:
                    with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
                        data = json.load(f)
                    timestamp = data.get('timestamp', 0)
                    if time.time() - timestamp > self.cache_ttl:
                        semantic_expired_count += 1
                    else:
                        semantic_valid_count += 1
                except Exception:
                    semantic_expired_count += 1
            
            return {
                'total_files': len(cache_files) + len(semantic_cache_files),
                'valid_files': valid_count + semantic_valid_count,
                'expired_files': expired_count + semantic_expired_count,
                'regular_cache': {
                    'total': len(cache_files),
                    'valid': valid_count,
                    'expired': expired_count
                },
                'semantic_cache': {
                    'total': len(semantic_cache_files),
                    'valid': semantic_valid_count,
                    'expired': semantic_expired_count
                },
                'cache_dir': str(self.cache_dir),
                'semantic_cache_dir': str(self.semantic_cache_dir),
                'cache_ttl': self.cache_ttl
            }
        except Exception:
            return {
                'error': '无法获取缓存统计信息'
            }
    
    def _clean_expired_cache(self) -> None:
        """清理过期的缓存文件
        """
        try:
            current_time = time.time()
            # 清理常规缓存
            for cache_file in self.cache_dir.glob('*.json'):
                try:
                    with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
                        data = json.load(f)
                    
                    timestamp = data.get('timestamp', 0)
                    file_size = data.get('file_size', 0)
                    dynamic_ttl = self._get_dynamic_ttl(file_size)
                    
                    if current_time - timestamp > dynamic_ttl:
                        os.remove(cache_file)
                except Exception:
                    # 缓存文件损坏，删除
                    try:
                        os.remove(cache_file)
                    except Exception:
                        pass
            
            # 清理语义缓存
            for cache_file in self.semantic_cache_dir.glob('*.json'):
                try:
                    with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
                        data = json.load(f)
                    
                    timestamp = data.get('timestamp', 0)
                    if current_time - timestamp > self.cache_ttl:
                        os.remove(cache_file)
                except Exception:
                    # 缓存文件损坏，删除
                    try:
                        os.remove(cache_file)
                    except Exception:
                        pass
        except Exception:
            pass

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
缓存管理模块

功能：
1. 缓存扫描结果，避免重复分析
2. 基于文件内容和配置生成缓存键
3. 支持缓存过期和清理
4. 提供缓存统计信息
"""

import os
import hashlib
import json
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class CacheStats:
    """缓存统计信息"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_items: int = 0
    cache_size: int = 0
    last_cleanup: float = 0.0


class CacheManager:
    """缓存管理器"""
    
    def __init__(self, cache_dir: str = ".hos_ls_cache", max_size: int = 1000, ttl: int = 3600):
        """初始化缓存管理器
        
        Args:
            cache_dir: 缓存目录
            max_size: 最大缓存项数
            ttl: 缓存过期时间（秒）
        """
        self.cache_dir = cache_dir
        self.max_size = max_size
        self.ttl = ttl
        self.stats = CacheStats()
        
        # 创建缓存目录
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # 清理过期缓存
        self._cleanup_expired()
    
    def _generate_cache_key(self, code: str, config: Dict[str, Any]) -> str:
        """生成缓存键
        
        Args:
            code: 代码内容
            config: 配置信息
            
        Returns:
            缓存键
        """
        # 组合代码和配置生成哈希
        combined = f"{code}{json.dumps(config, sort_keys=True)}"
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def _get_cache_file(self, key: str) -> str:
        """获取缓存文件路径
        
        Args:
            key: 缓存键
            
        Returns:
            缓存文件路径
        """
        # 使用前8个字符作为子目录，提高文件系统性能
        subdir = key[:8]
        subdir_path = os.path.join(self.cache_dir, subdir)
        os.makedirs(subdir_path, exist_ok=True)
        return os.path.join(subdir_path, f"{key}.json")
    
    def get(self, code: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """获取缓存结果
        
        Args:
            code: 代码内容
            config: 配置信息
            
        Returns:
            缓存的结果，如果不存在或过期则返回 None
        """
        key = self._generate_cache_key(code, config)
        cache_file = self._get_cache_file(key)
        
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 检查是否过期
                timestamp = data.get('timestamp', 0)
                if time.time() - timestamp < self.ttl:
                    self.stats.hits += 1
                    return data.get('result')
                else:
                    # 过期，删除缓存文件
                    os.remove(cache_file)
                    self.stats.misses += 1
                    self.stats.evictions += 1
        except Exception as e:
            print(f"获取缓存失败: {str(e)}")
        
        self.stats.misses += 1
        return None
    
    def set(self, code: str, config: Dict[str, Any], result: Dict[str, Any]) -> bool:
        """设置缓存结果
        
        Args:
            code: 代码内容
            config: 配置信息
            result: 扫描结果
            
        Returns:
            是否设置成功
        """
        key = self._generate_cache_key(code, config)
        cache_file = self._get_cache_file(key)
        
        try:
            # 检查缓存大小
            self._cleanup_if_needed()
            
            # 保存缓存
            data = {
                'timestamp': time.time(),
                'result': result,
                'key': key
            }
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.stats.total_items += 1
            self._update_cache_size()
            return True
        except Exception as e:
            print(f"设置缓存失败: {str(e)}")
            return False
    
    def _cleanup_expired(self):
        """清理过期缓存"""
        try:
            for root, dirs, files in os.walk(self.cache_dir):
                for file in files:
                    if file.endswith('.json'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                            timestamp = data.get('timestamp', 0)
                            if time.time() - timestamp >= self.ttl:
                                os.remove(file_path)
                                self.stats.evictions += 1
                        except:
                            # 如果文件损坏，删除它
                            os.remove(file_path)
                            self.stats.evictions += 1
            
            self.stats.last_cleanup = time.time()
            self._update_cache_size()
        except Exception as e:
            print(f"清理过期缓存失败: {str(e)}")
    
    def _cleanup_if_needed(self):
        """如果缓存超过大小限制，清理最旧的缓存"""
        if self.stats.total_items >= self.max_size:
            # 获取所有缓存文件及其时间戳
            cache_files = []
            for root, dirs, files in os.walk(self.cache_dir):
                for file in files:
                    if file.endswith('.json'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                            timestamp = data.get('timestamp', 0)
                            cache_files.append((file_path, timestamp))
                        except:
                            # 如果文件损坏，删除它
                            os.remove(file_path)
                            self.stats.evictions += 1
            
            # 按时间戳排序，删除最旧的文件
            cache_files.sort(key=lambda x: x[1])
            to_delete = len(cache_files) - self.max_size // 2  # 删除一半
            
            for file_path, _ in cache_files[:to_delete]:
                try:
                    os.remove(file_path)
                    self.stats.evictions += 1
                    self.stats.total_items -= 1
                except:
                    pass
            
            self._update_cache_size()
    
    def _update_cache_size(self):
        """更新缓存大小统计"""
        try:
            total_size = 0
            total_items = 0
            for root, dirs, files in os.walk(self.cache_dir):
                for file in files:
                    if file.endswith('.json'):
                        file_path = os.path.join(root, file)
                        total_size += os.path.getsize(file_path)
                        total_items += 1
            
            self.stats.cache_size = total_size
            self.stats.total_items = total_items
        except Exception as e:
            print(f"更新缓存大小失败: {str(e)}")
    
    def clear(self):
        """清空所有缓存"""
        try:
            for root, dirs, files in os.walk(self.cache_dir):
                for file in files:
                    if file.endswith('.json'):
                        file_path = os.path.join(root, file)
                        os.remove(file_path)
            
            # 重置统计信息
            self.stats = CacheStats()
            return True
        except Exception as e:
            print(f"清空缓存失败: {str(e)}")
            return False
    
    def get_stats(self) -> CacheStats:
        """获取缓存统计信息
        
        Returns:
            缓存统计信息
        """
        return self.stats
    
    def get_cache_info(self) -> Dict[str, Any]:
        """获取缓存信息
        
        Returns:
            缓存信息
        """
        return {
            "cache_dir": self.cache_dir,
            "max_size": self.max_size,
            "ttl": self.ttl,
            "stats": {
                "hits": self.stats.hits,
                "misses": self.stats.misses,
                "evictions": self.stats.evictions,
                "total_items": self.stats.total_items,
                "cache_size": self.stats.cache_size,
                "last_cleanup": self.stats.last_cleanup
            }
        }


if __name__ == '__main__':
    # 测试缓存管理器
    cache_manager = CacheManager()
    
    # 测试代码
    test_code = "def login(username, password):\n    query = f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"\n    cursor.execute(query)\n    return cursor.fetchone()"
    
    test_config = {
        "use_ai_analysis": True,
        "ai_model": "deepseek"
    }
    
    # 测试缓存未命中
    result = cache_manager.get(test_code, test_config)
    print(f"第一次查询结果: {result}")
    print(f"缓存统计: 命中={cache_manager.stats.hits}, 未命中={cache_manager.stats.misses}")
    
    # 测试设置缓存
    test_result = {
        "issues": [
            {
                "type": "sql_injection",
                "severity": "high",
                "details": "检测到 SQL 注入漏洞"
            }
        ]
    }
    cache_manager.set(test_code, test_config, test_result)
    print(f"设置缓存后，总缓存项数: {cache_manager.stats.total_items}")
    
    # 测试缓存命中
    result = cache_manager.get(test_code, test_config)
    print(f"第二次查询结果: {result}")
    print(f"缓存统计: 命中={cache_manager.stats.hits}, 未命中={cache_manager.stats.misses}")
    
    # 测试缓存信息
    cache_info = cache_manager.get_cache_info()
    print(f"缓存信息: {json.dumps(cache_info, indent=2, ensure_ascii=False)}")
    
    # 测试清空缓存
    cache_manager.clear()
    print(f"清空缓存后，总缓存项数: {cache_manager.stats.total_items}")

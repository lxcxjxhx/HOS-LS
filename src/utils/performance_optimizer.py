#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
性能优化模块

功能：
1. 支持本地模型（DeepSeek-R1、Qwen2.5-Coder）
2. 实现缓存机制
3. 支持分批处理
4. 优化向量库构建
"""

import os
import json
import time
import hashlib
from typing import List, Dict, Any, Optional
from langchain_openai import OpenAI
from langchain_community.llms import HuggingFacePipeline
from langchain_community.embeddings import HuggingFaceEmbeddings

class PerformanceOptimizer:
    def __init__(self, cache_dir: str = '.hos_ls_cache'):
        """
        初始化性能优化器
        
        Args:
            cache_dir: 缓存目录
        """
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # 本地模型配置
        self.local_models = {
            'deepseek-r1': {
                'model_name': 'deepseek-ai/deepseek-coder-7b-base',
                'type': 'coder'
            },
            'qwen2.5': {
                'model_name': 'Qwen/Qwen2.5-7B-Instruct',
                'type': 'general'
            }
        }
    
    def get_llm(self, model_type: str = 'openai', model_name: str = 'gpt-3.5-turbo') -> Any:
        """
        获取 LLM 实例
        
        Args:
            model_type: 模型类型 (openai, local)
            model_name: 模型名称
            
        Returns:
            LLM 实例
        """
        if model_type == 'openai':
            # 使用 OpenAI 模型
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OpenAI API key is required")
            return OpenAI(api_key=api_key, temperature=0.3)
        elif model_type == 'local':
            # 使用本地模型
            if model_name not in self.local_models:
                raise ValueError(f"Unknown local model: {model_name}")
            
            model_config = self.local_models[model_name]
            return HuggingFacePipeline.from_model_id(
                model_id=model_config['model_name'],
                task="text-generation",
                model_kwargs={"temperature": 0.3}
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
    def get_embeddings(self, model_type: str = 'openai', model_name: str = 'text-embedding-ada-002') -> Any:
        """
        获取 Embeddings 实例
        
        Args:
            model_type: 模型类型 (openai, local)
            model_name: 模型名称
            
        Returns:
            Embeddings 实例
        """
        if model_type == 'openai':
            # 使用 OpenAI Embeddings
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OpenAI API key is required")
            from langchain_openai import OpenAIEmbeddings
            return OpenAIEmbeddings(api_key=api_key)
        elif model_type == 'local':
            # 使用本地 Embeddings
            return HuggingFaceEmbeddings(
                model_name=model_name or "sentence-transformers/all-MiniLM-L6-v2"
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
    def cache_key(self, prompt: str, model: str) -> str:
        """
        生成缓存键
        
        Args:
            prompt: 提示词
            model: 模型名称
            
        Returns:
            缓存键
        """
        content = f"{model}:{prompt}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get_cached_response(self, prompt: str, model: str) -> Optional[str]:
        """
        获取缓存的响应
        
        Args:
            prompt: 提示词
            model: 模型名称
            
        Returns:
            缓存的响应，如果不存在则返回 None
        """
        cache_key = self.cache_key(prompt, model)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            return cache_data.get('response')
        
        return None
    
    def set_cached_response(self, prompt: str, model: str, response: str):
        """
        设置缓存的响应
        
        Args:
            prompt: 提示词
            model: 模型名称
            response: 响应
        """
        cache_key = self.cache_key(prompt, model)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        cache_data = {
            'prompt': prompt,
            'model': model,
            'response': response,
            'timestamp': time.time()
        }
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)
    
    def batch_process(self, items: List[Any], batch_size: int = 10) -> List[Any]:
        """
        分批处理
        
        Args:
            items: 待处理的项目列表
            batch_size: 批处理大小
            
        Returns:
            处理结果列表
        """
        results = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i+batch_size]
            # 处理批次
            batch_results = self._process_batch(batch)
            results.extend(batch_results)
        
        return results
    
    def _process_batch(self, batch: List[Any]) -> List[Any]:
        """
        处理单个批次
        
        Args:
            batch: 批次项目
            
        Returns:
            处理结果
        """
        # 这里可以实现具体的批处理逻辑
        # 例如，批量调用 LLM 或 Embeddings
        return batch
    
    def optimize_vector_store(self, documents: List[Any], embeddings: Any, use_incremental: bool = True) -> Any:
        """
        优化向量库构建
        
        Args:
            documents: 文档列表
            embeddings: Embeddings 实例
            use_incremental: 是否使用增量更新
            
        Returns:
            向量库实例
        """
        from langchain_community.vectorstores import Chroma
        
        persist_directory = os.path.join(self.cache_dir, 'vector_store')
        
        if use_incremental and os.path.exists(persist_directory):
            # 增量更新
            vector_store = Chroma(
                persist_directory=persist_directory,
                embedding_function=embeddings
            )
            vector_store.add_documents(documents)
        else:
            # 重新构建
            vector_store = Chroma.from_documents(
                documents=documents,
                embedding=embeddings,
                persist_directory=persist_directory
            )
        
        return vector_store
    
    def clear_cache(self, older_than: Optional[int] = None):
        """
        清理缓存
        
        Args:
            older_than: 清理多少秒之前的缓存
        """
        current_time = time.time()
        
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('.json'):
                file_path = os.path.join(self.cache_dir, filename)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                    
                    if older_than and current_time - cache_data.get('timestamp', 0) > older_than:
                        os.remove(file_path)
                except Exception:
                    pass
    
    def get_cache_stats(self) -> Dict[str, int]:
        """
        获取缓存统计信息
        
        Returns:
            缓存统计信息
        """
        cache_files = [f for f in os.listdir(self.cache_dir) if f.endswith('.json')]
        return {
            'total_cache_files': len(cache_files)
        }

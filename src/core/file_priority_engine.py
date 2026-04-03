#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件优先级引擎

功能：
1. 使用 LangChain 加载项目文件
2. 构建向量库（RAG）
3. 实现文件优先级评分
4. 生成带优先级的文件清单
"""

import os
import json
import time
from typing import List, Dict, Any, Optional
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_community.vectorstores.faiss import FAISS
import networkx as nx
import git

from utils.config_manager import ConfigManager


class FilePriorityEngine:
    def __init__(self, project_path: str, api_key: Optional[str] = None):
        """
        初始化文件优先级引擎
        
        Args:
            project_path: 项目路径
            api_key: API 密钥
        """
        self.project_path = project_path
        
        # 使用配置管理器获取AI配置
        config_manager = ConfigManager()
        ai_config = config_manager.get_ai_config()
        
        self.api_key = api_key or ai_config.get('api_key')
        self.model = ai_config.get('model', 'deepseek-chat')
        
        if not self.api_key:
            raise ValueError("API key is required")
        
        # 尝试使用 DeepSeek 嵌入模型，如果不可用则使用 OpenAI 嵌入模型
        try:
            from langchain_deepseek import DeepSeekEmbeddings
            self.embeddings = DeepSeekEmbeddings(
                api_key=self.api_key,
                model="deepseek-embed"
            )
        except ImportError:
            # 如果 DeepSeek 嵌入模型不可用，使用 OpenAI 嵌入模型
            self.embeddings = OpenAIEmbeddings(
                api_key=self.api_key,
                model="text-embedding-3-small"
            )
        
        self.vector_store = None
        self.files_to_scan = []
        self.file_scores = {}
    
    def load_project_files(self) -> List[str]:
        """
        加载项目文件
        
        Returns:
            文件路径列表
        """
        # 先收集所有文件路径
        for root, dirs, files in os.walk(self.project_path):
            # 跳过不需要的目录
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'venv', '.venv', '__pycache__', '.git', 'dist', 'build', 'target']]
            
            for file in files:
                file_path = os.path.join(root, file)
                # 只添加文本文件
                if os.path.isfile(file_path) and self._is_text_file(file_path):
                    self.files_to_scan.append(file_path)
        
        return self.files_to_scan
    
    def build_vector_store(self, use_faiss: bool = False) -> Any:
        """
        构建向量库
        
        Args:
            use_faiss: 是否使用 FAISS 向量库
            
        Returns:
            向量库实例
        """
        start_time = time.time()
        
        # 加载文件
        if not self.files_to_scan:
            self.load_project_files()
        
        # 加载文档（只加载已过滤的文本文件）
        from langchain_community.document_loaders import TextLoader
        documents = []
        
        for file_path in self.files_to_scan:
            try:
                loader = TextLoader(file_path, encoding='utf-8')
                doc = loader.load()[0]
                documents.append(doc)
            except Exception as e:
                print(f"加载文件 {file_path} 时出错: {e}")
                continue
        
        filtered_docs = documents
        
        # 文本分割
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len
        )
        split_docs = text_splitter.split_documents(filtered_docs)
        
        # 构建向量库
        if use_faiss:
            self.vector_store = FAISS.from_documents(split_docs, self.embeddings)
        else:
            # 使用 Chroma 作为默认向量库
            persist_directory = os.path.join(self.project_path, ".hos_ls", "vector_store")
            os.makedirs(persist_directory, exist_ok=True)
            self.vector_store = Chroma.from_documents(
                split_docs,
                self.embeddings,
                persist_directory=persist_directory
            )
        
        build_time = time.time() - start_time
        print(f"向量库构建完成，耗时: {build_time:.2f} 秒")
        print(f"处理文件数: {len(filtered_docs)}")
        print(f"生成 chunks 数: {len(split_docs)}")
        
        return self.vector_store
    
    def semantic_search(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        """
        语义搜索
        
        Args:
            query: 搜索查询
            k: 返回结果数
            
        Returns:
            搜索结果
        """
        if not self.vector_store:
            self.build_vector_store()
        
        results = self.vector_store.similarity_search_with_score(query, k=k)
        
        search_results = []
        for doc, score in results:
            search_results.append({
                "file": doc.metadata['source'],
                "score": score,
                "content": doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content
            })
        
        return search_results
    
    def calculate_file_priority(self) -> Dict[str, float]:
        """
        计算文件优先级
        
        Returns:
            文件路径到优先级分数的映射
        """
        for file_path in self.files_to_scan:
            try:
                # 计算各维度分数
                business_criticality = self._calculate_business_criticality(file_path)
                complexity = self._calculate_complexity(file_path)
                security_sensitivity = self._calculate_security_sensitivity(file_path)
                change_frequency = self._calculate_change_frequency(file_path)
                
                # 加权计算总分
                total_score = (
                    0.4 * business_criticality +
                    0.25 * complexity +
                    0.25 * security_sensitivity +
                    0.1 * change_frequency
                )
                
                self.file_scores[file_path] = total_score
            except Exception as e:
                print(f"计算文件 {file_path} 优先级时出错: {e}")
                self.file_scores[file_path] = 0.0
        
        return self.file_scores
    
    def generate_file_list(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        生成带优先级的文件清单
        
        Args:
            output_path: 输出文件路径
            
        Returns:
            文件清单
        """
        if not self.file_scores:
            self.calculate_file_priority()
        
        # 按优先级排序
        sorted_files = sorted(
            self.file_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        file_list = {
            "total_files": len(sorted_files),
            "timestamp": time.time(),
            "files": [
                {
                    "path": file_path,
                    "priority": score,
                    "priority_level": self._get_priority_level(score)
                }
                for file_path, score in sorted_files
            ]
        }
        
        # 保存到文件
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(file_list, f, indent=2, ensure_ascii=False)
            print(f"文件清单已保存到: {output_path}")
        
        return file_list
    
    def _is_text_file(self, file_path: str) -> bool:
        """
        判断是否为文本文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否为文本文件
        """
        text_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.html', '.css', '.scss',
            '.json', '.yaml', '.yml', '.xml', '.md', '.txt', '.rst',
            '.sh', '.bat', '.cmd', '.pyw', '.php', '.java', '.c', '.cpp',
            '.h', '.hpp', '.cs', '.go', '.rb', '.swift', '.kt', '.rs'
        }
        
        ext = os.path.splitext(file_path)[1].lower()
        return ext in text_extensions
    
    def _calculate_business_criticality(self, file_path: str) -> float:
        """
        计算业务关键度
        
        Args:
            file_path: 文件路径
            
        Returns:
            业务关键度分数 (0-100)
        """
        # 基于文件路径和内容的简单判断
        critical_keywords = [
            'main', 'app', 'api', 'router', 'controller', 'service',
            'model', 'database', 'auth', 'security', 'config', 'settings',
            'payment', 'billing', 'user', 'admin', 'core', 'lib'
        ]
        
        score = 0.0
        
        # 基于文件名和路径的判断
        file_name = os.path.basename(file_path)
        file_dir = os.path.dirname(file_path)
        
        for keyword in critical_keywords:
            if keyword in file_name.lower() or keyword in file_dir.lower():
                score += 10.0
        
        # 基于文件内容的判断
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # 检查是否包含关键功能
            if any(keyword in content.lower() for keyword in [
                'def main', 'app.run', 'api.route', '@router',
                'auth', 'login', 'password', 'token', 'jwt'
            ]):
                score += 30.0
        except Exception:
            pass
        
        return min(score, 100.0)
    
    def _calculate_complexity(self, file_path: str) -> float:
        """
        计算复杂度与依赖度
        
        Args:
            file_path: 文件路径
            
        Returns:
            复杂度分数 (0-100)
        """
        score = 0.0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # 基于代码行数
            lines = content.split('\n')
            line_count = len([line for line in lines if line.strip()])
            
            # 基于函数/类数量
            import ast
            try:
                tree = ast.parse(content)
                func_count = len([node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)])
                class_count = len([node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)])
                
                # 计算复杂度分数
                score = min(
                    (line_count / 100) * 30 +
                    (func_count * 5) +
                    (class_count * 10),
                    100.0
                )
            except Exception:
                # 如果无法解析 AST，基于行数计算
                score = min((line_count / 100) * 50, 100.0)
        except Exception:
            pass
        
        return score
    
    def _calculate_security_sensitivity(self, file_path: str) -> float:
        """
        计算安全敏感度
        
        Args:
            file_path: 文件路径
            
        Returns:
            安全敏感度分数 (0-100)
        """
        security_keywords = [
            'password', 'secret', 'key', 'token', 'jwt', 'auth',
            'login', 'logout', 'register', 'user', 'admin',
            'permission', 'role', 'access', 'secure', 'encrypt',
            'decrypt', 'hash', 'salt', 'oauth', 'api_key',
            'database', 'connection', 'config', 'setting', 'env'
        ]
        
        score = 0.0
        
        # 基于文件名的判断
        file_name = os.path.basename(file_path)
        if any(keyword in file_name.lower() for keyword in ['config', 'env', 'secret', 'key']):
            score += 50.0
        
        # 基于文件内容的判断
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            for keyword in security_keywords:
                if keyword in content.lower():
                    score += 5.0
        except Exception:
            pass
        
        return min(score, 100.0)
    
    def _calculate_change_frequency(self, file_path: str) -> float:
        """
        计算变更频率
        
        Args:
            file_path: 文件路径
            
        Returns:
            变更频率分数 (0-100)
        """
        score = 0.0
        
        try:
            # 尝试使用 git 历史
            repo = git.Repo(self.project_path)
            relative_path = os.path.relpath(file_path, self.project_path)
            
            # 获取文件的提交历史
            commits = list(repo.iter_commits(paths=relative_path, max_count=20))
            
            # 基于提交次数计算分数
            if commits:
                score = min(len(commits) * 5, 100.0)
        except Exception:
            # 如果无法获取 git 历史，返回默认分数
            pass
        
        return score
    
    def _get_priority_level(self, score: float) -> str:
        """
        根据分数获取优先级等级
        
        Args:
            score: 分数
            
        Returns:
            优先级等级
        """
        if score >= 90:
            return "critical"
        elif score >= 70:
            return "high"
        elif score >= 50:
            return "medium"
        else:
            return "low"

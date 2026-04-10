"""Prompt市场

管理安全分析相关的Prompt模板，包括存储、评分、分享等功能。
"""

import json
import os
import time
from typing import Dict, List, Optional, Tuple

from src.core.config import Config, get_config


class PromptMarket:
    """Prompt市场

    管理安全分析相关的Prompt模板，包括存储、评分、分享等功能。
    """
    
    def __init__(self, config: Optional[Config] = None):
        """初始化Prompt市场
        
        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self.prompt_dir = os.path.join(self.config.data.storage_path, "prompt_market")
        self.prompts_file = os.path.join(self.prompt_dir, "prompts.json")
        
        # 确保Prompt目录存在
        os.makedirs(self.prompt_dir, exist_ok=True)
        
        # 初始化Prompt存储
        self._initialize_prompts()
    
    def _initialize_prompts(self):
        """初始化Prompt存储文件"""
        if not os.path.exists(self.prompts_file):
            with open(self.prompts_file, 'w', encoding='utf-8') as f:
                json.dump({"prompts": [], "last_updated": None}, f, ensure_ascii=False, indent=2)
    
    def get_prompts(self) -> List[Dict]:
        """获取所有Prompt
        
        Returns:
            Prompt列表
        """
        with open(self.prompts_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get("prompts", [])
    
    def add_prompt(self, prompt: Dict) -> bool:
        """添加Prompt
        
        Args:
            prompt: Prompt信息
        
        Returns:
            是否添加成功
        """
        try:
            # 读取现有Prompt
            prompts = self.get_prompts()
            
            # 生成Prompt ID
            prompt_id = f"prompt_{int(time.time())}_{len(prompts)}"
            
            # 添加基础信息
            prompt["id"] = prompt_id
            prompt["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            prompt["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            prompt["rating"] = prompt.get("rating", 0.0)
            prompt["votes"] = prompt.get("votes", 0)
            prompt["downloads"] = prompt.get("downloads", 0)
            
            # 添加到列表
            prompts.append(prompt)
            
            # 更新存储
            self._save_prompts(prompts)
            
            return True
        except Exception as e:
            print(f"添加Prompt失败: {str(e)}")
            return False
    
    def update_prompt(self, prompt_id: str, updates: Dict) -> bool:
        """更新Prompt
        
        Args:
            prompt_id: Prompt ID
            updates: 更新内容
        
        Returns:
            是否更新成功
        """
        try:
            # 读取现有Prompt
            prompts = self.get_prompts()
            
            # 找到目标Prompt
            for i, prompt in enumerate(prompts):
                if prompt.get("id") == prompt_id:
                    # 更新内容
                    prompt.update(updates)
                    prompt["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # 更新存储
                    self._save_prompts(prompts)
                    return True
            
            return False
        except Exception as e:
            print(f"更新Prompt失败: {str(e)}")
            return False
    
    def delete_prompt(self, prompt_id: str) -> bool:
        """删除Prompt
        
        Args:
            prompt_id: Prompt ID
        
        Returns:
            是否删除成功
        """
        try:
            # 读取现有Prompt
            prompts = self.get_prompts()
            
            # 过滤掉目标Prompt
            new_prompts = [prompt for prompt in prompts if prompt.get("id") != prompt_id]
            
            # 更新存储
            self._save_prompts(new_prompts)
            
            return len(new_prompts) < len(prompts)
        except Exception as e:
            print(f"删除Prompt失败: {str(e)}")
            return False
    
    def rate_prompt(self, prompt_id: str, rating: float) -> bool:
        """为Prompt评分
        
        Args:
            prompt_id: Prompt ID
            rating: 评分 (1-5)
        
        Returns:
            是否评分成功
        """
        try:
            # 读取现有Prompt
            prompts = self.get_prompts()
            
            # 找到目标Prompt
            for i, prompt in enumerate(prompts):
                if prompt.get("id") == prompt_id:
                    # 计算新评分
                    current_rating = prompt.get("rating", 0.0)
                    current_votes = prompt.get("votes", 0)
                    
                    new_rating = (current_rating * current_votes + rating) / (current_votes + 1)
                    
                    # 更新评分
                    prompt["rating"] = round(new_rating, 1)
                    prompt["votes"] = current_votes + 1
                    prompt["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # 更新存储
                    self._save_prompts(prompts)
                    return True
            
            return False
        except Exception as e:
            print(f"评分Prompt失败: {str(e)}")
            return False
    
    def download_prompt(self, prompt_id: str) -> Optional[Dict]:
        """下载Prompt
        
        Args:
            prompt_id: Prompt ID
        
        Returns:
            Prompt信息或None
        """
        try:
            # 读取现有Prompt
            prompts = self.get_prompts()
            
            # 找到目标Prompt
            for i, prompt in enumerate(prompts):
                if prompt.get("id") == prompt_id:
                    # 增加下载次数
                    prompt["downloads"] = prompt.get("downloads", 0) + 1
                    prompt["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # 更新存储
                    self._save_prompts(prompts)
                    
                    return prompt
            
            return None
        except Exception as e:
            print(f"下载Prompt失败: {str(e)}")
            return None
    
    def search_prompts(self, query: str, category: Optional[str] = None) -> List[Dict]:
        """搜索Prompt
        
        Args:
            query: 搜索关键词
            category: 分类（可选）
        
        Returns:
            匹配的Prompt列表
        """
        prompts = self.get_prompts()
        results = []
        
        for prompt in prompts:
            # 检查关键词匹配
            if (query.lower() in prompt.get("name", "").lower() or
                query.lower() in prompt.get("description", "").lower() or
                query.lower() in prompt.get("content", "").lower()):
                
                # 检查分类匹配
                if category and prompt.get("category") != category:
                    continue
                
                results.append(prompt)
        
        return results
    
    def get_top_prompts(self, limit: int = 10) -> List[Dict]:
        """获取评分最高的Prompt
        
        Args:
            limit: 限制数量
        
        Returns:
            评分最高的Prompt列表
        """
        prompts = self.get_prompts()
        
        # 按评分和下载量排序
        sorted_prompts = sorted(
            prompts, 
            key=lambda x: (x.get("rating", 0), x.get("downloads", 0)), 
            reverse=True
        )
        
        return sorted_prompts[:limit]
    
    def get_prompts_by_category(self, category: str) -> List[Dict]:
        """按分类获取Prompt
        
        Args:
            category: 分类
        
        Returns:
            该分类的Prompt列表
        """
        prompts = self.get_prompts()
        return [prompt for prompt in prompts if prompt.get("category") == category]
    
    def export_prompt(self, prompt_id: str, output_path: str) -> bool:
        """导出Prompt
        
        Args:
            prompt_id: Prompt ID
            output_path: 输出文件路径
        
        Returns:
            是否导出成功
        """
        try:
            # 找到目标Prompt
            prompt = self.download_prompt(prompt_id)
            if not prompt:
                return False
            
            # 导出到文件
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(prompt, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception as e:
            print(f"导出Prompt失败: {str(e)}")
            return False
    
    def import_prompt(self, input_path: str) -> bool:
        """导入Prompt
        
        Args:
            input_path: 输入文件路径
        
        Returns:
            是否导入成功
        """
        try:
            # 读取Prompt文件
            with open(input_path, 'r', encoding='utf-8') as f:
                prompt = json.load(f)
            
            # 移除ID和时间戳，让系统重新生成
            prompt.pop("id", None)
            prompt.pop("created_at", None)
            prompt.pop("updated_at", None)
            
            # 添加Prompt
            return self.add_prompt(prompt)
        except Exception as e:
            print(f"导入Prompt失败: {str(e)}")
            return False
    
    def _save_prompts(self, prompts: List[Dict]):
        """保存Prompt到存储
        
        Args:
            prompts: Prompt列表
        """
        data = {
            "prompts": prompts,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        with open(self.prompts_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def get_prompt_statistics(self) -> Dict:
        """获取Prompt统计信息
        
        Returns:
            Prompt统计信息
        """
        prompts = self.get_prompts()
        
        # 计算统计信息
        total_prompts = len(prompts)
        total_downloads = sum(prompt.get("downloads", 0) for prompt in prompts)
        total_votes = sum(prompt.get("votes", 0) for prompt in prompts)
        
        # 计算平均评分
        rated_prompts = [prompt for prompt in prompts if prompt.get("votes", 0) > 0]
        average_rating = sum(prompt.get("rating", 0) for prompt in rated_prompts) / len(rated_prompts) if rated_prompts else 0
        
        # 按分类统计
        category_stats = {}
        for prompt in prompts:
            category = prompt.get("category", "Uncategorized")
            if category not in category_stats:
                category_stats[category] = 0
            category_stats[category] += 1
        
        return {
            "total_prompts": total_prompts,
            "total_downloads": total_downloads,
            "total_votes": total_votes,
            "average_rating": round(average_rating, 2),
            "category_stats": category_stats
        }

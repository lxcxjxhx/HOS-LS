from pathlib import Path
from typing import Dict, Any

class FilePrioritizer:
    """文件优先级分析器
    
    根据文件相对路径、文件名称和文件类型判断其重要性和出现问题的概率
    """
    
    def __init__(self):
        """初始化文件优先级分析器"""
        # 目录重要性权重
        self.directory_weights = {
            'src': 0.8,
            'lib': 0.7,
            'utils': 0.6,
            'core': 0.9,
            'cli': 0.7,
            'ai': 0.8,
            'api': 0.9,
            'auth': 0.95,
            'security': 0.95,
            'config': 0.85,
            'database': 0.8,
            'models': 0.75,
            'routes': 0.7,
            'services': 0.75,
            'controllers': 0.7,
            'middleware': 0.8,
            'handlers': 0.7
        }
        
        # 文件名重要性关键词
        self.file_name_keywords = {
            'api': 0.8,
            'auth': 0.95,
            'key': 0.95,
            'token': 0.9,
            'password': 0.95,
            'security': 0.95,
            'config': 0.85,
            'database': 0.8,
            'secret': 0.95,
            'credential': 0.95,
            'login': 0.85,
            'register': 0.8,
            'user': 0.75,
            'admin': 0.85,
            'permission': 0.85,
            'role': 0.8,
            'session': 0.8,
            'jwt': 0.9,
            'oauth': 0.85,
            'encryption': 0.9,
            'decryption': 0.9,
            'hash': 0.85,
            'validate': 0.8,
            'sanitize': 0.8,
            'filter': 0.75
        }
        
        # 文件类型问题概率权重
        self.file_type_weights = {
            '.py': 0.85,
            '.js': 0.8,
            '.ts': 0.75,
            '.jsx': 0.7,
            '.tsx': 0.65,
            '.php': 0.8,
            '.java': 0.7,
            '.c': 0.65,
            '.cpp': 0.65,
            '.cs': 0.7,
            '.go': 0.6,
            '.rb': 0.75,
            '.pl': 0.6,
            '.sh': 0.8,
            '.bat': 0.7,
            '.ps1': 0.7,
            '.yml': 0.6,
            '.yaml': 0.6,
            '.json': 0.55,
            '.xml': 0.5,
            '.ini': 0.5,
            '.env': 0.95,
            '.config': 0.7
        }
        
        # 权重系数
        self.importance_weight = 0.3  # 文件重要性权重
        self.problem_probability_weight = 0.7  # 出现问题的可能性权重
    
    def calculate_priority(self, file_path: str) -> Dict[str, Any]:
        """计算文件优先级
        
        Args:
            file_path: 文件路径
            
        Returns:
            包含优先级分数和详细分析的字典
        """
        path = Path(file_path)
        
        # 1. 计算文件重要性
        importance_score = self._calculate_importance(path)
        
        # 2. 计算出现问题的概率
        problem_probability = self._calculate_problem_probability(path)
        
        # 3. 计算最终优先级（加权平均）
        priority_score = (
            importance_score * self.importance_weight +
            problem_probability * self.problem_probability_weight
        )
        
        return {
            'file_path': file_path,
            'priority_score': round(priority_score, 3),
            'importance_score': round(importance_score, 3),
            'problem_probability': round(problem_probability, 3),
            'analysis': {
                'directory_score': round(self._calculate_directory_score(path), 3),
                'file_name_score': round(self._calculate_file_name_score(path), 3),
                'file_type_score': round(self._calculate_file_type_score(path), 3)
            }
        }
    
    def _calculate_importance(self, path: Path) -> float:
        """计算文件重要性
        
        Args:
            path: 文件路径
            
        Returns:
            重要性分数（0-1）
        """
        # 目录重要性
        directory_score = self._calculate_directory_score(path)
        
        # 文件名重要性
        file_name_score = self._calculate_file_name_score(path)
        
        # 综合重要性（平均）
        return (directory_score + file_name_score) / 2
    
    def _calculate_problem_probability(self, path: Path) -> float:
        """计算出现问题的概率
        
        Args:
            path: 文件路径
            
        Returns:
            问题概率分数（0-1）
        """
        # 文件类型问题概率
        file_type_score = self._calculate_file_type_score(path)
        
        # 文件名问题概率（基于关键词）
        file_name_problem_score = self._calculate_file_name_score(path)
        
        # 综合问题概率（文件类型权重更高）
        return file_type_score * 0.6 + file_name_problem_score * 0.4
    
    def _calculate_directory_score(self, path: Path) -> float:
        """计算目录重要性分数
        
        Args:
            path: 文件路径
            
        Returns:
            目录重要性分数（0-1）
        """
        max_score = 0.0
        
        # 检查所有父目录
        for parent in path.parents:
            dir_name = parent.name.lower()
            if dir_name in self.directory_weights:
                if self.directory_weights[dir_name] > max_score:
                    max_score = self.directory_weights[dir_name]
        
        return max_score
    
    def _calculate_file_name_score(self, path: Path) -> float:
        """计算文件名重要性分数
        
        Args:
            path: 文件路径
            
        Returns:
            文件名重要性分数（0-1）
        """
        file_name = path.stem.lower()
        max_score = 0.5  # 默认分数
        
        # 检查文件名中的关键词
        for keyword, score in self.file_name_keywords.items():
            if keyword in file_name:
                if score > max_score:
                    max_score = score
        
        return max_score
    
    def _calculate_file_type_score(self, path: Path) -> float:
        """计算文件类型问题概率分数
        
        Args:
            path: 文件路径
            
        Returns:
            文件类型问题概率分数（0-1）
        """
        suffix = path.suffix.lower()
        return self.file_type_weights.get(suffix, 0.4)  # 默认分数

"""数据增强模块

用于自动生成训练数据，包括三元组生成、数据增强和数据预处理。
"""

import json
import random
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class DataAugmentation:
    """数据增强器

    用于生成训练数据，包括三元组生成和数据增强。
    """

    def __init__(self, data_dir: Optional[Path] = None):
        """初始化数据增强器

        Args:
            data_dir: 数据目录
        """
        self.data_dir = data_dir
        self._synonyms = self._load_synonyms()
        self._vulnerability_types = self._load_vulnerability_types()

    def generate_triplets(self, data: List[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
        """生成三元组训练数据

        Args:
            data: 原始数据列表，包含漏洞信息、代码片段等

        Returns:
            三元组列表，每个三元组包含 (anchor, positive, negative)
        """
        triplets = []
        
        # 按漏洞类型分组
        by_vulnerability_type = {}
        for item in data:
            vuln_type = item.get('vulnerability_type', 'unknown')
            if vuln_type not in by_vulnerability_type:
                by_vulnerability_type[vuln_type] = []
            by_vulnerability_type[vuln_type].append(item)

        # 生成三元组
        for vuln_type, items in by_vulnerability_type.items():
            if len(items) < 2:
                continue

            for anchor_item in items:
                # 生成 anchor
                anchor = self._generate_anchor(anchor_item)
                
                # 生成 positive
                positive_items = [item for item in items if item != anchor_item]
                if positive_items:
                    positive_item = random.choice(positive_items)
                    positive = self._generate_positive(positive_item)
                    
                    # 生成 negative
                    negative_items = self._get_negative_items(by_vulnerability_type, vuln_type)
                    if negative_items:
                        negative_item = random.choice(negative_items)
                        negative = self._generate_negative(negative_item)
                        
                        triplets.append((anchor, positive, negative))

        logger.info(f"生成了 {len(triplets)} 个三元组")
        return triplets

    def _generate_anchor(self, item: Dict[str, Any]) -> str:
        """生成 anchor 文本

        Args:
            item: 数据项

        Returns:
            anchor 文本
        """
        if 'code' in item:
            return f"代码片段: {item['code']}"
        elif 'ast' in item:
            return f"AST分析: {item['ast']}"
        elif 'description' in item:
            return f"漏洞描述: {item['description']}"
        else:
            return str(item)

    def _generate_positive(self, item: Dict[str, Any]) -> str:
        """生成 positive 文本

        Args:
            item: 数据项

        Returns:
            positive 文本
        """
        if 'vulnerability_type' in item:
            return f"漏洞类型: {item['vulnerability_type']}"
        elif 'cve_id' in item:
            return f"CVE ID: {item['cve_id']}"
        elif 'description' in item:
            return f"漏洞描述: {item['description']}"
        else:
            return str(item)

    def _generate_negative(self, item: Dict[str, Any]) -> str:
        """生成 negative 文本

        Args:
            item: 数据项

        Returns:
            negative 文本
        """
        if 'vulnerability_type' in item:
            return f"漏洞类型: {item['vulnerability_type']}"
        elif 'description' in item:
            return f"安全描述: {item['description']}"
        else:
            return str(item)

    def _get_negative_items(self, by_vulnerability_type: Dict[str, List[Dict]], 
                           current_type: str) -> List[Dict[str, Any]]:
        """获取负样本项

        Args:
            by_vulnerability_type: 按漏洞类型分组的数据
            current_type: 当前漏洞类型

        Returns:
            负样本项列表
        """
        negative_items = []
        for vuln_type, items in by_vulnerability_type.items():
            if vuln_type != current_type:
                negative_items.extend(items)
        return negative_items

    def augment_data(self, triplets: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
        """增强训练数据

        Args:
            triplets: 原始三元组列表

        Returns:
            增强后的三元组列表
        """
        augmented_triplets = []

        for anchor, positive, negative in triplets:
            # 原始三元组
            augmented_triplets.append((anchor, positive, negative))

            # 同义扩展
            if anchor in self._synonyms:
                for synonym in self._synonyms[anchor]:
                    augmented_triplets.append((synonym, positive, negative))

            # 代码到语义的转换
            code_semantic = self._code_to_semantic(anchor)
            if code_semantic:
                augmented_triplets.append((code_semantic, positive, negative))

            # 漏洞到攻击链的扩展
            attack_chain = self._vulnerability_to_attack_chain(positive)
            if attack_chain:
                augmented_triplets.append((anchor, attack_chain, negative))

        logger.info(f"数据增强后，三元组数量从 {len(triplets)} 增加到 {len(augmented_triplets)}")
        return augmented_triplets

    def _code_to_semantic(self, code: str) -> Optional[str]:
        """将代码转换为语义描述

        Args:
            code: 代码片段

        Returns:
            语义描述
        """
        # 简单的代码到语义转换
        if 'exec(' in code:
            return "执行用户输入的命令，可能导致远程代码执行漏洞"
        elif 'sql' in code.lower() and ('select' in code.lower() or 'insert' in code.lower()):
            return "执行SQL查询，可能导致SQL注入漏洞"
        elif 'eval(' in code:
            return "执行动态代码，可能导致代码注入漏洞"
        elif 'open(' in code and 'w' in code:
            return "写入文件操作，可能导致文件操作漏洞"
        else:
            return None

    def _vulnerability_to_attack_chain(self, vulnerability: str) -> Optional[str]:
        """将漏洞转换为攻击链描述

        Args:
            vulnerability: 漏洞描述

        Returns:
            攻击链描述
        """
        if 'SQL注入' in vulnerability or 'SQL injection' in vulnerability:
            return "SQL注入 → 数据库访问 → 数据泄露 → 权限提升"
        elif 'RCE' in vulnerability or '远程代码执行' in vulnerability:
            return "远程代码执行 → 系统控制 → 权限提升 → 横向移动"
        elif 'XSS' in vulnerability or '跨站脚本' in vulnerability:
            return "跨站脚本 → 会话劫持 → 身份冒用 → 权限提升"
        else:
            return None

    def _load_synonyms(self) -> Dict[str, List[str]]:
        """加载同义词表

        Returns:
            同义词字典
        """
        return {
            "SQL注入": ["SQL injection", "数据库注入", "SQLi"],
            "RCE": ["远程代码执行", "代码执行", "remote code execution"],
            "XSS": ["跨站脚本", "cross-site scripting", "脚本注入"],
            "CSRF": ["跨站请求伪造", "cross-site request forgery"],
            "执行用户输入的命令": ["exec(user_input)", "命令注入", "command injection"],
            "执行SQL查询": ["SQL查询", "数据库操作", "database query"]
        }

    def _load_vulnerability_types(self) -> List[str]:
        """加载漏洞类型列表

        Returns:
            漏洞类型列表
        """
        return [
            "SQL注入",
            "RCE",
            "XSS",
            "CSRF",
            "目录遍历",
            "文件上传",
            "认证绕过",
            "权限提升",
            "信息泄露",
            "拒绝服务"
        ]

    def load_from_nvd(self, nvd_path: Path) -> List[Dict[str, Any]]:
        """从 NVD 数据加载漏洞信息

        Args:
            nvd_path: NVD 数据文件路径

        Returns:
            漏洞信息列表
        """
        vulnerabilities = []
        
        try:
            with open(nvd_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            for item in data.get('CVE_Items', []):
                cve = item.get('cve', {})
                description = cve.get('description', {}).get('description_data', [])[0].get('value', '')
                cve_id = cve.get('CVE_data_meta', {}).get('ID', '')
                
                vulnerabilities.append({
                    'cve_id': cve_id,
                    'description': description,
                    'vulnerability_type': self._infer_vulnerability_type(description)
                })
            
            logger.info(f"从 NVD 加载了 {len(vulnerabilities)} 个漏洞")
        except Exception as e:
            logger.error(f"加载 NVD 数据失败: {e}")
        
        return vulnerabilities

    def load_from_github(self, github_path: Path) -> List[Dict[str, Any]]:
        """从 GitHub 漏洞代码加载数据

        Args:
            github_path: GitHub 漏洞代码目录路径

        Returns:
            漏洞代码列表
        """
        vulnerabilities = []
        
        try:
            for code_file in github_path.glob('**/*.py'):
                try:
                    with open(code_file, 'r', encoding='utf-8') as f:
                        code = f.read()
                    
                    vulnerabilities.append({
                        'code': code,
                        'vulnerability_type': self._infer_vulnerability_type(code),
                        'file_path': str(code_file)
                    })
                except Exception as e:
                    logger.warning(f"读取文件 {code_file} 失败: {e}")
            
            logger.info(f"从 GitHub 加载了 {len(vulnerabilities)} 个漏洞代码")
        except Exception as e:
            logger.error(f"加载 GitHub 数据失败: {e}")
        
        return vulnerabilities

    def _infer_vulnerability_type(self, text: str) -> str:
        """推断漏洞类型

        Args:
            text: 文本描述或代码

        Returns:
            漏洞类型
        """
        text_lower = text.lower()
        
        if 'sql' in text_lower and ('inject' in text_lower or 'query' in text_lower):
            return "SQL注入"
        elif 'exec(' in text or 'eval(' in text or 'remote code' in text_lower:
            return "RCE"
        elif 'xss' in text_lower or 'cross-site' in text_lower or 'script' in text_lower:
            return "XSS"
        elif 'csrf' in text_lower or 'cross-site request' in text_lower:
            return "CSRF"
        elif 'directory' in text_lower and 'traversal' in text_lower:
            return "目录遍历"
        elif 'file' in text_lower and 'upload' in text_lower:
            return "文件上传"
        elif 'auth' in text_lower and 'bypass' in text_lower:
            return "认证绕过"
        elif 'privilege' in text_lower and 'escalation' in text_lower:
            return "权限提升"
        elif 'information' in text_lower and 'disclosure' in text_lower:
            return "信息泄露"
        elif 'denial' in text_lower and 'service' in text_lower:
            return "拒绝服务"
        else:
            return "未知"

    def validate_data(self, triplets: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
        """验证和过滤训练数据

        Args:
            triplets: 三元组列表

        Returns:
            验证后的三元组列表
        """
        valid_triplets = []
        
        for anchor, positive, negative in triplets:
            # 检查长度
            if len(anchor) < 10 or len(positive) < 5 or len(negative) < 5:
                continue
            
            # 检查内容
            if anchor == positive or anchor == negative or positive == negative:
                continue
            
            valid_triplets.append((anchor, positive, negative))
        
        logger.info(f"验证后，三元组数量从 {len(triplets)} 减少到 {len(valid_triplets)}")
        return valid_triplets

    def save_training_data(self, triplets: List[Tuple[str, str, str]], output_path: Path):
        """保存训练数据

        Args:
            triplets: 三元组列表
            output_path: 输出文件路径
        """
        try:
            data = [{
                'anchor': anchor,
                'positive': positive,
                'negative': negative
            } for anchor, positive, negative in triplets]
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"训练数据已保存到 {output_path}")
        except Exception as e:
            logger.error(f"保存训练数据失败: {e}")

    def load_training_data(self, input_path: Path) -> List[Tuple[str, str, str]]:
        """加载训练数据

        Args:
            input_path: 输入文件路径

        Returns:
            三元组列表
        """
        triplets = []
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            for item in data:
                triplets.append((
                    item.get('anchor', ''),
                    item.get('positive', ''),
                    item.get('negative', '')
                ))
            
            logger.info(f"从 {input_path} 加载了 {len(triplets)} 个三元组")
        except Exception as e:
            logger.error(f"加载训练数据失败: {e}")
        
        return triplets

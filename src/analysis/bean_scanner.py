"""
Bean扫描器 - 扫描Spring Bean定义

功能：
1. 扫描所有Java源文件中的@Component、@Service、@Repository、@Controller注解
2. 识别@Bean方法定义
3. 建立Bean名称到定义位置的映射
"""

import re
import os
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

# Spring注解模式
COMPONENT_PATTERNS = [
    # @Component("beanName") 或 @Component("beanName")
    (r'@Component\s*\(\s*["\']([^"\']+)["\']\s*\)', 'component'),
    # @Service("beanName")
    (r'@Service\s*\(\s*["\']([^"\']+)["\']\s*\)', 'service'),
    # @Repository("beanName")
    (r'@Repository\s*\(\s*["\']([^"\']+)["\']\s*\)', 'repository'),
    # @Controller("beanName")
    (r'@Controller\s*\(\s*["\']([^"\']+)["\']\s*\)', 'controller'),
    # @RestController("beanName")
    (r'@RestController\s*\(\s*["\']([^"\']+)["\']\s*\)', 'rest_controller'),
    # 无参数注解
    (r'@Component\s*(?=\n|\s|{)', 'component'),
    (r'@Service\s*(?=\n|\s|{)', 'service'),
    (r'@Repository\s*(?=\n|\s|{)', 'repository'),
    (r'@Controller\s*(?=\n|\s|{)', 'controller'),
    (r'@RestController\s*(?=\n|\s|{)', 'rest_controller'),
]

# @Bean方法模式
BEAN_METHOD_PATTERNS = [
    r'@Bean\s*\(\s*["\']([^"\']+)["\']\s*\)',  # @Bean("beanName")
    r'@Bean\s*(?=\n|\s|\()',  # @Bean 无参数
]

# 类名提取模式
CLASS_NAME_PATTERN = r'(?:class|interface)\s+([A-Z][a-zA-Z0-9_]*)\s*(?:extends|implements|\{)'


class BeanScanner:
    def __init__(self, module_analyzer):
        """
        初始化Bean扫描器
        
        Args:
            module_analyzer: ModuleAnalyzer实例
        """
        self.module_analyzer = module_analyzer
        self.beans: Dict[str, List['BeanDefinition']] = {}  # bean名称 -> 定义列表
        self.file_beans: Dict[str, List['BeanDefinition']] = {}  # 文件路径 -> Bean定义列表
        
    def scan_all_modules(self) -> int:
        """
        扫描所有模块中的Bean定义
        
        Returns:
            int: 扫描到的Bean数量
        """
        count = 0
        
        for module_name in self.module_analyzer.list_modules():
            module_info = self.module_analyzer.get_module_info(module_name)
            if module_info:
                count += self.scan_module(module_name)
        
        print(f"[INFO] 共扫描到 {count} 个Bean定义")
        return count
    
    def scan_module(self, module_name: str) -> int:
        """
        扫描单个模块
        
        Args:
            module_name: 模块名
            
        Returns:
            int: 扫描到的Bean数量
        """
        module_info = self.module_analyzer.get_module_info(module_name)
        if not module_info:
            return 0
            
        module_path = Path(module_info.path)
        src_dir = module_path / 'src' / 'main' / 'java'
        
        if not src_dir.exists():
            return 0
            
        count = 0
        for java_file in src_dir.rglob('*.java'):
            count += self.scan_file(str(java_file), module_name)
            
        return count
    
    def scan_file(self, file_path: str, module_name: str) -> int:
        """
        扫描单个Java文件
        
        Args:
            file_path: Java文件路径
            module_name: 所属模块名
            
        Returns:
            int: 扫描到的Bean数量
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            beans = self._parse_beans(content, file_path, module_name)
            
            if beans:
                self.file_beans[file_path] = beans
                
                for bean in beans:
                    if bean.name not in self.beans:
                        self.beans[bean.name] = []
                    self.beans[bean.name].append(bean)
            
            return len(beans)
            
        except Exception as e:
            print(f"[WARN] 扫描文件失败 {file_path}: {e}")
            return 0
    
    def _parse_beans(self, content: str, file_path: str, module_name: str) -> List['BeanDefinition']:
        """
        解析Java文件中的Bean定义
        
        Args:
            content: 文件内容
            file_path: 文件路径
            module_name: 模块名
            
        Returns:
            List[BeanDefinition]: Bean定义列表
        """
        beans = []
        
        # 提取包名
        package_name = self._extract_package_name(content)
        
        # 提取类名
        class_name = self._extract_class_name(content)
        
        # 查找类级别注解（@Component等）
        beans.extend(self._parse_class_level_annotations(
            content, file_path, module_name, package_name, class_name
        ))
        
        # 查找方法级别注解（@Bean）
        beans.extend(self._parse_method_level_annotations(
            content, file_path, module_name, package_name
        ))
        
        return beans
    
    def _extract_package_name(self, content: str) -> str:
        """提取包名"""
        match = re.search(r'^package\s+([a-zA-Z0-9_.]+)\s*;', content, re.MULTILINE)
        return match.group(1) if match else ''
    
    def _extract_class_name(self, content: str) -> str:
        """提取类名"""
        match = re.search(CLASS_NAME_PATTERN, content)
        return match.group(1) if match else ''
    
    def _parse_class_level_annotations(
        self, content: str, file_path: str, module_name: str, 
        package_name: str, class_name: str
    ) -> List['BeanDefinition']:
        """解析类级别的@Component等注解"""
        beans = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, bean_type in COMPONENT_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    # 获取Bean名称
                    bean_name = match.group(1) if len(match.groups()) > 0 else None
                    
                    if not bean_name:
                        # 使用类名（首字母小写）
                        if class_name:
                            bean_name = class_name[0].lower() + class_name[1:]
                        else:
                            continue
                    
                    # 获取完整类名
                    full_class_name = f"{package_name}.{class_name}" if package_name else class_name
                    
                    bean = BeanDefinition(
                        name=bean_name,
                        type=full_class_name,
                        bean_type=bean_type,
                        file_path=file_path,
                        line_number=line_num,
                        module_name=module_name,
                        method_name=None
                    )
                    beans.append(bean)
                    break
        
        return beans
    
    def _parse_method_level_annotations(
        self, content: str, file_path: str, module_name: str, package_name: str
    ) -> List['BeanDefinition']:
        """解析方法级别的@Bean注解"""
        beans = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in BEAN_METHOD_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    # 获取Bean名称
                    bean_name = match.group(1) if len(match.groups()) > 0 else None
                    
                    # 获取方法名（下一行通常是方法定义）
                    method_name = self._extract_method_name(lines, line_num)
                    
                    if not bean_name:
                        bean_name = method_name
                    
                    if bean_name:
                        bean = BeanDefinition(
                            name=bean_name,
                            type=f"{package_name}.{method_name}" if package_name else method_name,
                            bean_type='bean_method',
                            file_path=file_path,
                            line_number=line_num,
                            module_name=module_name,
                            method_name=method_name
                        )
                        beans.append(bean)
                    break
        
        return beans
    
    def _extract_method_name(self, lines: List[str], start_line: int) -> str:
        """从下几行提取方法名"""
        # 查看接下来的几行
        for i in range(start_line, min(start_line + 5, len(lines))):
            line = lines[i].strip()
            # 查找方法定义
            match = re.search(r'(?:public|private|protected)\s+\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
            if match:
                return match.group(1)
        
        return ''
    
    def find_bean(self, bean_name: str) -> List['BeanDefinition']:
        """
        查找Bean定义
        
        Args:
            bean_name: Bean名称
            
        Returns:
            List[BeanDefinition]: Bean定义列表
        """
        return self.beans.get(bean_name, [])
    
    def find_beans_by_module(self, module_name: str) -> List['BeanDefinition']:
        """
        按模块查找Bean
        
        Args:
            module_name: 模块名
            
        Returns:
            List[BeanDefinition]: Bean定义列表
        """
        result = []
        for bean_defs in self.beans.values():
            for bean in bean_defs:
                if bean.module_name == module_name:
                    result.append(bean)
        return result
    
    def print_summary(self) -> None:
        """打印Bean扫描摘要"""
        print("\n=== Bean扫描摘要 ===")
        print(f"总Bean数: {sum(len(v) for v in self.beans.values())}")
        print(f"唯一Bean名称: {len(self.beans)}")
        
        print("\nBean列表:")
        for bean_name, definitions in sorted(self.beans.items()):
            print(f"  {bean_name}:")
            for bean in definitions:
                print(f"    - {bean.type} ({bean.module_name}:{bean.line_number})")


class BeanDefinition:
    """Bean定义信息"""
    
    def __init__(
        self, name: str, type: str, bean_type: str,
        file_path: str, line_number: int, module_name: str,
        method_name: Optional[str] = None
    ):
        self.name = name
        self.type = type  # 全限定类名
        self.bean_type = bean_type  # component/service/repository/controller/bean_method
        self.file_path = file_path
        self.line_number = line_number
        self.module_name = module_name
        self.method_name = method_name  # 对于@Bean方法
    
    def __repr__(self):
        return f"BeanDefinition(name={self.name}, type={self.type}, module={self.module_name})"
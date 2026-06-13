"""
SpEL表达式解析器 - 解析Spring表达式语言

功能：
1. 解析@PreAuthorize等注解中的SpEL表达式
2. 提取Bean引用和方法调用
3. 支持跨模块Bean追踪
"""

import re
from typing import Dict, List, Set, Optional, Tuple

# SpEL表达式模式
SPEL_PATTERNS = [
    # @beanName.method()
    (r'@([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', 'method_call'),
    # @beanName
    (r'@([a-zA-Z_][a-zA-Z0-9_]*)(?!\.)', 'bean_reference'),
]

# 安全注解模式
SECURITY_ANNOTATIONS = [
    r'@PreAuthorize\s*\(\s*["\']([^"\']+)["\']\s*\)',
    r'@Secured\s*\(\s*["\']([^"\']+)["\']\s*\)',
    r'@PostAuthorize\s*\(\s*["\']([^"\']+)["\']\s*\)',
    r'@PreFilter\s*\(\s*["\']([^"\']+)["\']\s*\)',
    r'@PostFilter\s*\(\s*["\']([^"\']+)["\']\s*\)',
]


class SpELParser:
    """SpEL表达式解析器"""
    
    def __init__(self, module_analyzer, bean_scanner):
        """
        初始化SpEL解析器
        
        Args:
            module_analyzer: ModuleAnalyzer实例
            bean_scanner: BeanScanner实例
        """
        self.module_analyzer = module_analyzer
        self.bean_scanner = bean_scanner
        
    def parse_security_annotations(self, content: str) -> List['SpELReference']:
        """
        解析安全注解中的SpEL表达式
        
        Args:
            content: Java文件内容
            
        Returns:
            List[SpELReference]: SpEL引用列表
        """
        references = []
        
        for pattern in SECURITY_ANNOTATIONS:
            matches = re.findall(pattern, content)
            for expr in matches:
                refs = self.parse_expression(expr)
                references.extend(refs)
        
        return references
    
    def parse_expression(self, expression: str) -> List['SpELReference']:
        """
        解析单个SpEL表达式
        
        Args:
            expression: SpEL表达式字符串
            
        Returns:
            List[SpELReference]: SpEL引用列表
        """
        references = []
        
        for pattern, ref_type in SPEL_PATTERNS:
            matches = re.findall(pattern, expression)
            for match in matches:
                if isinstance(match, tuple):
                    bean_name = match[0]
                    method_name = match[1] if len(match) > 1 else None
                else:
                    bean_name = match
                    method_name = None
                
                ref = SpELReference(
                    bean_name=bean_name,
                    method_name=method_name,
                    expression=expression,
                    ref_type=ref_type
                )
                references.append(ref)
        
        return references
    
    def verify_references(
        self, references: List['SpELReference'], file_path: str
    ) -> List['SpELVerificationResult']:
        """
        验证SpEL引用是否有效（跨模块追踪）
        
        Args:
            references: SpEL引用列表
            file_path: 当前文件路径（用于确定当前模块）
            
        Returns:
            List[SpELVerificationResult]: 验证结果列表
        """
        results = []
        
        # 获取当前文件所属模块
        current_module = self.module_analyzer.get_module_by_path(file_path)
        
        for ref in references:
            result = self._verify_reference(ref, current_module)
            results.append(result)
        
        return results
    
    def _verify_reference(
        self, ref: 'SpELReference', current_module: Optional[str]
    ) -> 'SpELVerificationResult':
        """
        验证单个SpEL引用
        
        Args:
            ref: SpEL引用
            current_module: 当前模块名
            
        Returns:
            SpELVerificationResult: 验证结果
        """
        # 首先在当前模块查找
        bean_defs = self.bean_scanner.find_bean(ref.bean_name)
        
        if bean_defs:
            return SpELVerificationResult(
                sp_el_ref=ref,
                exists=True,
                found_module=bean_defs[0].module_name,
                bean_definitions=bean_defs,
                search_path=[current_module] if current_module else []
            )
        
        # 如果当前模块没找到，查找依赖模块
        if current_module:
            dependencies = self.module_analyzer.get_dependencies(current_module, recursive=True)
            
            for dep_module in dependencies:
                bean_defs = self.bean_scanner.find_beans_by_module(dep_module)
                for bean in bean_defs:
                    if bean.name == ref.bean_name:
                        return SpELVerificationResult(
                            sp_el_ref=ref,
                            exists=True,
                            found_module=dep_module,
                            bean_definitions=[bean],
                            search_path=[current_module] + list(dependencies)
                        )
        
        # 全局搜索
        all_beans = self.bean_scanner.find_bean(ref.bean_name)
        if all_beans:
            return SpELVerificationResult(
                sp_el_ref=ref,
                exists=True,
                found_module=all_beans[0].module_name,
                bean_definitions=all_beans,
                search_path=['全局搜索']
            )
        
        # 未找到
        return SpELVerificationResult(
            sp_el_ref=ref,
            exists=False,
            found_module=None,
            bean_definitions=[],
            search_path=[current_module] if current_module else []
        )
    
    def find_all_unverified_references(self, file_path: str) -> List['SpELReference']:
        """
        查找文件中所有未验证的Bean引用
        
        Args:
            file_path: 文件路径
            
        Returns:
            List[SpELReference]: 未验证的引用列表
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            refs = self.parse_security_annotations(content)
            results = self.verify_references(refs, file_path)
            
            return [r.sp_el_ref for r in results if not r.exists]
        except Exception as e:
            print(f"[WARN] 分析文件失败 {file_path}: {e}")
            return []


class SpELReference:
    """SpEL引用信息"""
    
    def __init__(self, bean_name: str, method_name: Optional[str], expression: str, ref_type: str):
        self.bean_name = bean_name
        self.method_name = method_name
        self.expression = expression
        self.ref_type = ref_type  # method_call 或 bean_reference
    
    def __repr__(self):
        if self.method_name:
            return f"SpELReference(@{self.bean_name}.{self.method_name}())"
        return f"SpELReference(@{self.bean_name})"


class SpELVerificationResult:
    """SpEL验证结果"""
    
    def __init__(
        self, sp_el_ref: 'SpELReference', exists: bool,
        found_module: Optional[str], bean_definitions: List['BeanDefinition'],
        search_path: List[str]
    ):
        self.sp_el_ref = sp_el_ref
        self.exists = exists
        self.found_module = found_module
        self.bean_definitions = bean_definitions
        self.search_path = search_path
    
    def __repr__(self):
        status = "✓" if self.exists else "✗"
        return f"SpELVerificationResult({status} @{self.sp_el_ref.bean_name} in {self.found_module})"
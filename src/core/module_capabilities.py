"""功能模块能力映射

定义系统中所有功能模块的能力，确保AI能够识别和调用这些模块。
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ModuleCapability:
    """模块能力定义"""
    name: str  # 模块名称
    description: str  # 模块描述
    capabilities: List[str]  # 模块能力列表
    parameters: Dict[str, Any]  # 模块参数
    dependencies: List[str]  # 模块依赖
    examples: List[str]  # 使用示例


class ModuleCapabilityManager:
    """模块能力管理器"""
    
    _instance: Optional["ModuleCapabilityManager"] = None
    
    def __new__(cls) -> "ModuleCapabilityManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """初始化模块能力映射"""
        self._capabilities: Dict[str, ModuleCapability] = {
            "scan": ModuleCapability(
                name="scan",
                description="代码安全扫描模块，用于检测代码中的安全漏洞",
                capabilities=[
                    "检测代码安全漏洞",
                    "生成安全报告",
                    "支持增量扫描",
                    "支持多语言代码扫描"
                ],
                parameters={
                    "target": "扫描目标路径",
                    "mode": "扫描模式 (auto|pure-ai|standard)",
                    "test_mode": "是否为测试模式",
                    "test_file_count": "测试模式下扫描的文件数量"
                },
                dependencies=[],
                examples=[
                    "扫描当前目录",
                    "使用纯净AI模式扫描src目录",
                    "测试模式扫描一个文件"
                ]
            ),
            "analyze": ModuleCapability(
                name="analyze",
                description="深度分析模块，用于对代码进行深度语义分析",
                capabilities=[
                    "深度语义分析",
                    "代码逻辑分析",
                    "漏洞根因分析",
                    "安全风险评估"
                ],
                parameters={
                    "target": "分析目标路径",
                    "focus": "分析重点",
                    "depth": "分析深度"
                },
                dependencies=[],
                examples=[
                    "深度分析认证模块",
                    "分析登录功能的安全风险"
                ]
            ),
            "exploit": ModuleCapability(
                name="exploit",
                description="漏洞利用模块，用于生成漏洞利用POC",
                capabilities=[
                    "生成漏洞利用POC",
                    "验证漏洞存在性",
                    "提供攻击路径分析"
                ],
                parameters={
                    "target": "目标路径",
                    "vulnerability": "漏洞信息",
                    "output": "输出路径"
                },
                dependencies=["scan"],
                examples=[
                    "为检测到的漏洞生成POC",
                    "验证SQL注入漏洞"
                ]
            ),
            "fix": ModuleCapability(
                name="fix",
                description="修复建议模块，用于提供漏洞修复建议",
                capabilities=[
                    "生成修复建议",
                    "提供代码补丁",
                    "修复方案评估"
                ],
                parameters={
                    "target": "目标路径",
                    "vulnerability": "漏洞信息",
                    "output": "输出路径"
                },
                dependencies=["scan"],
                examples=[
                    "为检测到的漏洞提供修复建议",
                    "修复XSS漏洞"
                ]
            ),
            "plan": ModuleCapability(
                name="plan",
                description="方案管理模块，用于生成和管理安全审计方案",
                capabilities=[
                    "生成安全审计方案",
                    "管理执行计划",
                    "方案优化"
                ],
                parameters={
                    "target": "目标路径",
                    "scope": "审计范围",
                    "output": "输出路径"
                },
                dependencies=[],
                examples=[
                    "生成安全审计方案",
                    "管理执行计划"
                ]
            ),
            "git": ModuleCapability(
                name="git",
                description="Git操作模块，用于执行Git相关操作",
                capabilities=[
                    "Git仓库分析",
                    "提交历史分析",
                    "代码变更分析"
                ],
                parameters={
                    "target": "Git仓库路径",
                    "operation": "Git操作类型"
                },
                dependencies=[],
                examples=[
                    "分析Git仓库的安全问题",
                    "检查代码变更历史"
                ]
            ),
            "code_tool": ModuleCapability(
                name="code_tool",
                description="代码工具模块，用于读取文件、搜索函数等操作",
                capabilities=[
                    "读取文件内容",
                    "搜索函数和变量",
                    "代码结构分析"
                ],
                parameters={
                    "target": "目标文件或目录",
                    "operation": "操作类型",
                    "query": "搜索查询"
                },
                dependencies=[],
                examples=[
                    "读取config.py文件",
                    "搜索包含密码的函数"
                ]
            ),
            "conversion": ModuleCapability(
                name="conversion",
                description="转换模块，用于CLI命令和自然语言之间的转换",
                capabilities=[
                    "CLI命令转自然语言",
                    "自然语言转CLI命令"
                ],
                parameters={
                    "input": "输入文本",
                    "output_format": "输出格式"
                },
                dependencies=[],
                examples=[
                    "将--full-audit命令转换为自然语言",
                    "将'扫描当前目录'转换为CLI命令"
                ]
            ),
            "info": ModuleCapability(
                name="info",
                description="信息查询模块，用于提供帮助和信息",
                capabilities=[
                    "提供使用帮助",
                    "解释漏洞原理",
                    "提供安全最佳实践"
                ],
                parameters={
                    "topic": "查询主题",
                    "detail": "详细程度"
                },
                dependencies=[],
                examples=[
                    "解释SQL注入漏洞",
                    "提供安全编码最佳实践"
                ]
            ),
            "report": ModuleCapability(
                name="report",
                description="报告生成模块，用于生成安全报告",
                capabilities=[
                    "生成HTML报告",
                    "生成JSON报告",
                    "生成Markdown报告",
                    "报告导出"
                ],
                parameters={
                    "format": "报告格式",
                    "output": "输出路径",
                    "include_snippets": "是否包含代码片段"
                },
                dependencies=["scan"],
                examples=[
                    "生成HTML安全报告",
                    "导出JSON格式报告"
                ]
            ),
            "ai": ModuleCapability(
                name="ai",
                description="AI分析模块，用于执行AI驱动的分析",
                capabilities=[
                    "纯AI深度分析",
                    "AI辅助代码审查",
                    "AI驱动的漏洞检测"
                ],
                parameters={
                    "mode": "AI模式",
                    "target": "分析目标",
                    "model": "AI模型"
                },
                dependencies=[],
                examples=[
                    "使用纯AI模式分析代码",
                    "AI辅助审查认证模块"
                ]
            )
        }
    
    def get_capability(self, module_name: str) -> Optional[ModuleCapability]:
        """获取模块能力
        
        Args:
            module_name: 模块名称
            
        Returns:
            模块能力对象，如果模块不存在则返回None
        """
        return self._capabilities.get(module_name)
    
    def get_all_capabilities(self) -> Dict[str, ModuleCapability]:
        """获取所有模块能力
        
        Returns:
            所有模块能力的字典
        """
        return self._capabilities
    
    def get_modules_by_capability(self, capability: str) -> List[str]:
        """根据能力获取模块列表
        
        Args:
            capability: 能力描述
            
        Returns:
            具有该能力的模块列表
        """
        modules = []
        for module_name, module_capability in self._capabilities.items():
            if capability in module_capability.capabilities:
                modules.append(module_name)
        return modules
    
    def search_modules(self, query: str) -> List[str]:
        """搜索模块
        
        Args:
            query: 搜索查询
            
        Returns:
            匹配的模块列表
        """
        matching_modules = []
        query_lower = query.lower()
        
        for module_name, module_capability in self._capabilities.items():
            if (
                query_lower in module_name.lower() or
                query_lower in module_capability.description.lower() or
                any(query_lower in cap.lower() for cap in module_capability.capabilities)
            ):
                matching_modules.append(module_name)
        
        return matching_modules
    
    def get_module_dependencies(self, module_name: str) -> List[str]:
        """获取模块依赖
        
        Args:
            module_name: 模块名称
            
        Returns:
            模块依赖列表
        """
        module = self.get_capability(module_name)
        if module:
            return module.dependencies
        return []
    
    def validate_module_usage(self, module_name: str, parameters: Dict[str, Any]) -> bool:
        """验证模块使用是否正确
        
        Args:
            module_name: 模块名称
            parameters: 模块参数
            
        Returns:
            如果使用正确返回True，否则返回False
        """
        module = self.get_capability(module_name)
        if not module:
            return False
        
        # 检查必需参数
        required_params = [k for k, v in module.parameters.items() if v.endswith("*")]
        for param in required_params:
            param_name = param.rstrip("*")
            if param_name not in parameters:
                return False
        
        return True


def get_module_capabilities() -> ModuleCapabilityManager:
    """获取模块能力管理器实例
    
    Returns:
        模块能力管理器实例
    """
    return ModuleCapabilityManager()


def get_available_modules() -> List[str]:
    """获取可用模块列表
    
    Returns:
        可用模块列表
    """
    return list(get_module_capabilities().get_all_capabilities().keys())


def get_module_info(module_name: str) -> Optional[Dict[str, Any]]:
    """获取模块信息
    
    Args:
        module_name: 模块名称
        
    Returns:
        模块信息字典，如果模块不存在则返回None
    """
    module = get_module_capabilities().get_capability(module_name)
    if module:
        return {
            "name": module.name,
            "description": module.description,
            "capabilities": module.capabilities,
            "parameters": module.parameters,
            "dependencies": module.dependencies,
            "examples": module.examples
        }
    return None
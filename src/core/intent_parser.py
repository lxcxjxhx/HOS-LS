"""智能意图解析器

结合规则匹配和AI理解，准确解析用户意图。
支持中英文混合输入，提供置信度评估。
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
import re


class IntentType(Enum):
    """意图类型枚举"""
    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    FIX = "fix"
    PIPELINE = "pipeline"  # Agent Pipeline相关
    PLAN = "plan"  # Plan管理相关
    GIT = "git"
    INFO = "info"
    CODE_TOOL = "code_tool"  # 代码库工具
    CONVERSION = "conversion"  # CLI/自然语言转换
    GENERAL = "general"


@dataclass
class ParsedIntent:
    """解析后的意图"""
    type: IntentType
    confidence: float  # 0.0 - 1.0
    entities: Dict[str, Any] = field(default_factory=dict)  # 提取的实体（路径、参数等）
    raw_text: str = ""
    suggested_pipeline: Optional[List[str]] = None  # 建议的Pipeline
    
    def __post_init__(self):
        if self.confidence > 1.0:
            self.confidence = 1.0
        elif self.confidence < 0.0:
            self.confidence = 0.0


class RuleBasedIntentParser:
    """基于规则的意图解析器（增强版 - 支持丰富的口语化表达）"""
    
    INTENT_PATTERNS = {
        IntentType.SCAN: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "扫描", "检查", "检测", "测试", "scan",
                    # 口语化表达
                    "查查", "看看", "瞧瞧", "瞅瞅",
                    "帮我查", "帮我看", "帮我测", "帮我检",
                    "有没有漏洞", "安不安全", "有问题吗",
                    "代码安全", "安全检测", "安全测试",
                    "审计一下", "审查一下", "分析一下",
                    "跑一遍", "试一试", "试试看",
                    "开始扫描", "启动检测", "执行测试",
                    "全面检查", "仔细看看", "深度扫描",
                    "快速扫描", "简单测试", "随便测测"
                ],
                "en": ["scan", "check", "test", "inspect", "verify"]
            },
            "patterns": [
                # 标准模式
                r"扫描(.+?)(?:的|目录|项目|文件)?",
                r"scan\s+(.+?)(?:\s|$)",
                r"(?:只|仅)扫描(\d+)个文件",
                r"用(?:纯AI|pure.?ai)模式(?:扫描|分析)",
                
                # 口语化模式（新增）
                r"帮我(?:查查|看看|检查)(.+?)(?:有)?(?:没有)?(?:漏洞|问题)",
                r"(?:看看|查查)(.+?)(?:安不安全|有没有问题)",
                r"(?:这个|那个|当前)(?:项目|目录|文件)(?:有)?(?:什么)?(?:问题|漏洞)",
                r"(?:对|给|替)(.+?)(?:做)?(?:一次)?(?:扫描|检查|测试)",
                r"(?:快速|简单|快速地|简单地)(?:扫|测|检查|测试)(?:一下)?(.+)?",
                r"(?:跑|执行|运行)(?:一下)?(?:扫描|检测|测试)(?:任务)?(.+)?",
                r"(?:我想|我要|想要|需要)(?:扫描|检查|测试)(?:一下)?(.+)?",
                r"(?:能不能|能否|可以)(?:帮我)?(?:扫描|检查|测试)(?:一下)?(.+)?",
                r"(?:用|使用|采用)(?:纯AI|pure.?ai|纯净AI)(?:模式)?(?:来)?(?:扫描|分析|检测)(?:一下)?(.+)?",
                r"(?:只|仅仅|只要|仅)(?:扫|测|检查)(?:前)?(\d+)个?(?:文件)?",
                r"(?:测试|试用|体验)(?:一下)?(?:纯AI|pure.?ai)?(?:模式)?(.+)?"
            ],
            "default_confidence": 0.9,
            "suggested_pipeline": ["scan", "report"]
        },
        IntentType.ANALYZE: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "分析", "评估", "风险", "analyze", "analyse",
                    # 口语化表达
                    "深入分析", "详细分析", "全面评估",
                    "风险评估", "安全评估", "代码质量",
                    "看看怎么样", "分析分析", "研究一下",
                    "了解情况", "摸底", "排查",
                    "找问题", "发现问题", "潜在风险",
                    "代码审查", "代码评审", "静态分析",
                    "动态分析", "行为分析", "语义分析"
                ],
                "en": ["analyze", "assess", "evaluate", "risk", "review"]
            },
            "patterns": [
                # 标准模式
                r"分析(.+?)(?:的|漏洞|安全性|代码)?",
                r"(?:深度|全面)分析",
                r"评估(?:代码)?安全性",
                
                # 口语化模式（新增）
                r"(?:帮我|给我|替我)(?:做)?(?:一个)?(?:深度|全面|详细|深入)(?:的)?(?:分析|评估)(?:报告)?(.+)?",
                r"(?:分析|评估|研判)(?:一下)?(.+?)(?:的)?(?:安全性|风险|质量|状况)",
                r"(?:看看|查查|研究)(.+?)(?:怎么样|如何|什么情况)",
                r"(?:对|针对)(.+?)(?:进行|做)(?:一下)?(?:分析|评估|排查)",
                r"(?:我想|我要|想要|需要)(?:知道|了解|明白)(.+?)(?:的情况|的状态|的问题)",
                r"(?:找一找|找找|查找|搜索)(.+?)(?:中的|里的|存在的)?(?:问题|漏洞|风险|缺陷)",
                r"(?:排查|检查|审视|审查)(?:一下)?(.+?)(?:的)?(?:代码|项目|系统)",
                r"(?:从|在)(.+?)(?:中|里)(?:发现|找出|定位)(?:问题|漏洞|风险)"
            ],
            "default_confidence": 0.85,
            "suggested_pipeline": ["scan", "reason", "report"]
        },
        IntentType.EXPLOIT: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "攻击", "poc", "利用", "exploit", "漏洞利用",
                    # 口语化表达
                    "生成POC", "写个POC", "做个攻击脚本",
                    "验证漏洞", "利用漏洞", "攻击演示",
                    "渗透测试", "模拟攻击", "红队测试",
                    "漏洞复现", "概念验证", "攻击向量",
                    "Exploit开发", "Shellcode", "Payload生成"
                ],
                "en": ["exploit", "poc", "attack", "generate exploit", "payload"]
            },
            "patterns": [
                # 标准模式
                r"生成?(?:漏洞)?(?:的)?POC",
                r"创建攻击脚本",
                r"验证(?:漏洞|POC)",
                
                # 口语化模式（新增）
                r"(?:帮我|给我|替我)(?:生成|创建|写|制作|编写)(?:一个)?(?:漏洞)?(?:的)?(?:POC|攻击脚本|利用代码|exploit)(?:给)?(.+)?",
                r"(?:对|针对|面向)(.+?)(?:的)?(?:漏洞|问题)(?:写|生成|创建)(?:一个)?(?:POC|攻击脚本|利用代码)",
                r"(?:验证|证实|确认|测试)(?:一下)?(.+?)(?:的)?(?:漏洞|POC|可利用性)",
                r"(?:怎么|如何|怎样)(?:利用|攻击|exploit)(?:这个|那个|该)(.+?)(?:漏洞|问题)",
                r"(?:模拟|进行|开展)(?:一次)?(?:攻击|渗透|红队)(?:测试|演练|演习)(?:针对)?(.+)?",
                r"(?:复现|重现|再现)(?:一下)?(.+?)(?:的)?(?:漏洞|安全问题)",
                r"(?:生成|构建|构造)(?:一个)?(?:Payload|Shellcode|攻击载荷)(?:用于)?(.+)?"
            ],
            "default_confidence": 0.88,
            "suggested_pipeline": ["scan", "reason", "poc"]
        },
        IntentType.FIX: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "修复", "补丁", "patch", "fix", "修复建议",
                    # 口语化表达
                    "怎么修", "如何修", "应该怎么改",
                    "帮我修", "帮我改", "帮我补",
                    "修复方案", "解决方案", "改进建议",
                    "代码优化", "重构建议", "最佳实践",
                    "安全加固", "漏洞修补", "缺陷修复",
                    "代码整改", "问题解决", "bug修复"
                ],
                "en": ["fix", "patch", "repair", "suggest fix", "resolve"]
            },
            "patterns": [
                # 标准模式
                r"(?:提供|生成)修复建议?",
                r"生成修复补丁",
                r"如何修复",
                
                # 口语化模式（新增）
                r"(?:怎么|如何|怎样)(?:修复|修补|解决|处理|应对)(?:这个|那个|该)(.+?)(?:问题|漏洞|缺陷|bug)",
                r"(?:帮我|给我|替我)(?:修复|修补|解决|处理)(?:一下)?(.+?)(?:的)?(?:问题|漏洞|缺陷|bug)",
                r"(?:给|为|针对)(.+?)(?:提供|生成|给出|撰写)(?:一个)?(?:修复方案|解决方案|补丁|patch|fix)",
                r"(?:应该|可以|能够|需要)(?:怎么|如何|怎样)(?:修改|改变|调整|优化)(?:这个|那个|该)(.+?)?(?:代码|程序|实现)",
                r"(?:对|针对|面向)(.+?)(?:的)?(?:问题|漏洞|缺陷)(?:提出|给出|提供)(?:修复|解决|改进)(?:建议|方案|措施)",
                r"(?:优化|改进|改善|提升)(?:一下)?(.+?)(?:的)?(?:代码|实现|性能|安全性)",
                r"(?:加固|加强|增强)(?:一下)?(.+?)(?:的)?(?:安全性|防护能力|健壮性)",
                r"(?:消除|去除|清理|修复)(.+?)(?:中的|里边的|存在的)?(?:漏洞|安全隐患|脆弱性)"
            ],
            "default_confidence": 0.87,
            "suggested_pipeline": ["scan", "reason", "fix"]
        },
        IntentType.PLAN: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "方案", "计划", "plan", "生成方案", "创建方案",
                    # 口语化表达
                    "制定计划", "规划方案", "设计方案",
                    "执行计划", "实施方案", "操作步骤",
                    "工作流程", "任务清单", "行动计划",
                    "策略方案", "方法论", "路线图",
                    "分步指南", "操作手册", "执行手册"
                ],
                "en": ["plan", "generate plan", "create plan", "strategy", "roadmap"]
            },
            "patterns": [
                # 标准模式
                r"(?:生成|创建|制定)(?:方案|计划)",
                r"(?:修改|更新)方案",
                r"执行方案",
                r"列出方案",
                
                # 口语化模式（新增）
                r"(?:帮我|给我|替我)(?:制定|设计|规划|构思)(?:一个)?(?:方案|计划|策略|路线图)(?:用于|针对|关于)?(.+)?",
                r"(?:我想|我要|想要|需要)(?:一个)?(?:详细的|完整的|全面的)(?:方案|计划|执行步骤|操作指南)(?:来做|来完成|来实现)?(.+)?",
                r"(?:怎么做|如何做|怎样做)(?:才能|才可以|可以)(?:完成|实现|达成)(?:这个|那个|该)(.+?)(?:任务|目标|需求)",
                r"(?:列出|显示|展示|告诉我)(?:一下)?(?:具体的|详细的|分步的)(?:执行步骤|操作流程|实施方案|工作计划)(?:用于)?(.+)?",
                r"(?:修改|调整|更新|完善)(?:一下)?(?:我的|当前的|现有的)(?:方案|计划|策略)(?:关于)?(.+)?",
                r"(?:给我|向我|为我)(?:解释|说明|介绍|描述)(?:一下)?(?:你的|该)(?:方案|计划|策略|思路)(?:是)?(?:什么|怎样的|如何的)",
                r"(?:分步骤|逐步|按步骤)(?:告诉|说明|解释|描述)(?:我)?(?:如何|怎么|怎样)(?:执行|实施|完成|操作)(?:这个|那个|该)(.+)?"
            ],
            "default_confidence": 0.92,
            "suggested_pipeline": None  # Plan类型不直接对应Pipeline
        },
        IntentType.GIT: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "git", "commit", "提交", "分支", "diff", "差异", "状态",
                    # 口语化表达
                    "版本控制", "代码提交", "创建分支",
                    "查看差异", "合并代码", "拉取更新",
                    "推送代码", "回滚版本", "标签管理",
                    "Git历史", "变更记录", "代码版本"
                ],
                "en": ["git", "commit", "branch", "diff", "status", "push", "pull", "merge"]
            },
            "patterns": [
                # 标准模式
                r"git\s+(?:commit|提交)",
                r"(?:创建|切换)分支",
                r"(?:查看|显示)(?:差异|diff)",
                r"git状态?",
                
                # 口语化模式（新增）
                r"(?:帮我|给我|替我)(?:提交|commit)(?:一下)?(?:代码|更改|修改)(?:到|进|入)(?:git|仓库)?(.+)?",
                r"(?:创建|新建|建立)(?:一个)?(?:新的)?(?:分支|branch)(?:叫|名为|命名为)?(.+)?",
                r"(?:切换|切到|转到|进入)(?:分支|branch)(?:到)?(.+)?",
                r"(?:查看|显示|展示|告诉我)(?:一下)?(?:代码的|文件的|当前的)?(?:差异|diff|变化|变更)(?:内容)?(.+)?",
                r"(?:合并|merge)(?:分支|代码|更改)(?:从|自|由)(.+?)(?:到|入|进)(.+)?",
                r"(?:推|push|上传)(?:送)?(?:代码|更改|提交)(?:到|往|向)(?:远程|remote|服务器|仓库)?(.+)?",
                r"(?:拉取|pull|下载|更新)(?:一下)?(?:最新的|最近的|远程的)(?:代码|更改|提交)(?:从|自)?(.+)?",
                r"(?:查看|显示|展示)(?:一下)?(?:git)?(?:日志|log|历史|提交记录)(?:关于)?(.+)?",
                r"(?:回滚|撤销|取消|还原)(?:一下)?(?:上一次|最近|刚才|上一个)(?:提交|commit|更改|修改)"
            ],
            "default_confidence": 0.95,
            "suggested_pipeline": None
        },
        IntentType.CODE_TOOL: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "@file:", "@func:", "搜索代码", "列出目录", "项目摘要",
                    # 口语化表达
                    "读取文件", "查看文件", "打开文件",
                    "搜索函数", "查找函数", "定位函数",
                    "代码搜索", "文本搜索", "全局搜索",
                    "文件列表", "目录结构", "项目结构",
                    "函数定义", "类定义", "变量位置",
                    "引用查找", "调用关系", "依赖分析"
                ],
                "en": ["@file:", "@func:", "search code", "list dir", "project summary", "read file", "find function"]
            },
            "patterns": [
                # 标准模式
                r"@file:(.+?)(?:\s|$)",
                r"@func:(.+?)(?:\s|$)",
                r"搜索代码[:\s](.+?)(?:\s|$)",
                r"列出目录[:\s]*(.+?)(?:\s|$)",
                r"项目(?:信息|摘要)",
                
                # 口语化模式（新增）
                r"(?:读取|查看|打开|显示|展示)(?:文件)?(.+?)(?:的内容|源码|代码)?",
                r"(?:搜索|查找|寻找|定位)(?:一下)?(?:函数|方法|类|变量)(?:叫|名为|名称是)?(.+)?",
                r"(?:在|从|于)(.+?)(?:中|里|里面)(?:查找|搜索|寻找|定位)(?:函数|方法|类|变量|代码)(?:叫|名为)?(.+)?",
                r"(?:列出|显示|展示|告诉我)(?:一下)?(?:当前|这个|指定)(?:目录|文件夹|路径)(?:下的|里的|包含的)?(?:文件|子目录|内容)(?:列表)?(.+)?",
                r"(?:查看|显示|展示|获取)(?:一下)?(?:项目的|程序的|代码库的)(?:信息|摘要|概览|概况|结构)",
                r"(?:找到|查找|定位)(.+?)(?:的定义|的实现|的位置|在哪里)",
                r"(?:谁调用了|谁使用了|被谁引用)(?:函数|方法|类|变量)(.+)?",
                r"(?:显示|展示|查看)(?:一下)?(.+?)(?:的|的函数|的方法|的类的|的变量的)(?:调用链|引用关系|依赖关系)"
            ],
            "default_confidence": 0.98,
            "suggested_pipeline": None
        },
        IntentType.CONVERSION: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "转换为CLI", "转为CLI", "解释CLI", "CLI命令", "转换命令",
                    # 口语化表达
                    "翻译成命令", "变成CLI", "转成命令行",
                    "命令行格式", "CLI语法", "等价命令",
                    "自然语言转CLI", "文本转命令", "对话转指令"
                ],
                "en": ["convert to CLI", "to CLI", "explain CLI", "CLI command", "translate to command"]
            },
            "patterns": [
                # 标准模式
                r"(?:转换|转)(?:为|到)[:\s]*CLI",
                r"解释(?:CLI|命令)[:\s]*(.+)",
                r"CLI命令[:\s]*(.+)",
                
                # 口语化模式（新增）
                r"(?:把|将|把...转换|将...转换)(.+?)(?:翻译|转换|转变|变成|转为)(?:成|为|到)(?:CLI|命令行|命令|指令)(?:格式)?",
                r"(?:给我|替我|帮我)(?:生成|创建|写出|输出)(?:对应的|等价的|等效的)(?:CLI|命令行|命令)(?:用于|来完成|来实现)?(.+)?",
                r"(?:这个|那个|该)(.+?)(?:对应|等于|相当于|等价于)(?:什么|哪个|哪条)(?:CLI|命令|命令行指令)?",
                r"(?:用|使用|采用)(?:CLI|命令行|命令)(?:怎么|如何|怎样)(?:表达|表示|描述|说|写)(.+)?",
                r"(?:解释|说明|告诉我)(?:一下)?(.+?)(?:这条|该|这个)(?:CLI|命令|命令行指令)(?:是什么意思|的含义|的作用|的功能|是干什么的)",
                r"(?:将|把|把...将)(.+?)(?:这句|这段|这个)(?:话|文字|描述|请求)(?:转|翻|变|转换)(?:成|为|到)(?:命令|指令|CLI)"
            ],
            "default_confidence": 0.93,
            "suggested_pipeline": None
        },
        IntentType.INFO: {
            "keywords": {
                "zh": [
                    # 基础词汇
                    "帮助", "help", "信息", "info", "说明",
                    # 口语化表达
                    "怎么用", "如何使用", "使用教程",
                    "功能介绍", "特性说明", "操作指南",
                    "常见问题", "FAQ", "入门指南",
                    "文档", "手册", "参考资料"
                ],
                "en": ["help", "info", "information", "how to", "tutorial", "documentation"]
            },
            "patterns": [r"^/help$", r"^帮助$", r"^帮助我$", r"^怎么用$", r"^如何使用$"],
            "default_confidence": 1.0,
            "suggested_pipeline": None
        }
    }
    
    def parse(self, text: str) -> ParsedIntent:
        """基于规则解析意图
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的意图对象
        """
        if not text or not text.strip():
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.0,
                raw_text=text
            )
        
        text_lower = text.lower().strip()
        best_intent = None
        best_confidence = 0.0
        entities = {}
        
        for intent_type, config in self.INTENT_PATTERNS.items():
            confidence = config["default_confidence"]
            
            # 关键词匹配
            keywords_matched = False
            for lang_keywords in config["keywords"].values():
                for keyword in lang_keywords:
                    if keyword.lower() in text_lower:
                        keywords_matched = True
                        break
                if keywords_matched:
                    break
            
            if not keywords_matched:
                continue
                
            # 正则提取实体
            matched_pattern = False
            for pattern in config["patterns"]:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    matched_pattern = True
                    groups = match.groups()
                    if groups:
                        for i, group in enumerate(groups):
                            if group and group.strip():
                                entities[f"group_{i}"] = group.strip()
                    break
            
            if matched_pattern or keywords_matched:
                if not matched_pattern:
                    confidence *= 0.9  # 仅关键词匹配，略微降低置信度
                    
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_intent = intent_type
        
        if best_intent:
            return ParsedIntent(
                type=best_intent,
                confidence=best_confidence,
                entities=entities,
                raw_text=text,
                suggested_pipeline=self.INTENT_PATTERNS[best_intent].get("suggested_pipeline")
            )
        
        return ParsedIntent(
            type=IntentType.GENERAL,
            confidence=0.3,
            raw_text=text,
            suggested_pipeline=["scan", "report"]
        )


class AIIntentParser:
    """基于AI的意图解析器（用于复杂场景）"""
    
    def __init__(self, ai_client=None):
        self.ai_client = ai_client
        
    async def enhance(self, rule_intent: ParsedIntent, text: str) -> ParsedIntent:
        """使用AI增强规则解析结果
        
        Args:
            rule_intent: 规则解析的结果
            text: 原始文本
            
        Returns:
            AI增强后的意图
        """
        if not self.ai_client:
            return rule_intent
            
        try:
            from src.ai.models import AIRequest
            from src.core.module_capabilities import get_module_capabilities
            
            # 获取模块能力信息
            module_capabilities = get_module_capabilities()
            available_modules = list(module_capabilities.get_all_capabilities().keys())
            
            # 检测是否为长文本
            is_long_text = len(text) > 500
            
            # 检测是否为多任务命令
            is_multi_task = 'tasks' in rule_intent.entities
            
            if is_multi_task:
                # 多任务命令处理
                prompt = f"""你是一个用户意图识别专家。分析用户的输入，判断其真实意图和任务顺序。

用户输入: {text}
规则解析结果: 多任务命令

可用的功能模块:
{', '.join(available_modules)}

请分析：
1. 任务的具体内容和顺序
2. 是否需要纯AI模式
3. 是否为测试模式及文件数量
4. 每个任务需要使用哪些功能模块

请返回JSON格式:
{
  "intent": "general",
  "confidence": 0.0-1.0,
  "entities": {
    "tasks": [
      {
        "type": "任务类型",
        "content": "任务内容",
        "modules": ["使用的模块"]
      }
    ],
    "pure_ai": true/false,
    "test_mode": true/false,
    "test_file_count": 1
  }
}

只返回JSON，不要其他内容。"""
                
                request = AIRequest(
                    prompt=prompt,
                    system_prompt="你是用户意图识别专家，擅长分析复杂的多任务命令，能够理解口语化表达和长文本。",
                    max_tokens=500,
                    temperature=0.1
                )
                
                response = await self.ai_client.generate(request)
                
                result = self._parse_ai_response(response.content)
                
                try:
                    intent_type = IntentType(result.get("intent", rule_intent.type.value))
                    confidence = float(result.get("confidence", rule_intent.confidence))
                    entities = result.get("entities", {})
                    
                    # 确保任务列表存在
                    if 'tasks' not in entities:
                        entities['tasks'] = rule_intent.entities.get('tasks', [])
                    
                    return ParsedIntent(
                        type=intent_type,
                        confidence=max(confidence, rule_intent.confidence),
                        entities={**rule_intent.entities, **entities},
                        raw_text=text,
                        suggested_pipeline=rule_intent.suggested_pipeline
                    )
                except (ValueError, TypeError):
                    return rule_intent
            elif is_long_text:
                # 长文本命令处理
                prompt = f"""你是一个用户意图识别专家。分析用户的长文本输入，判断其真实意图。

用户输入: {text}

可用的意图类型:
- scan: 代码安全扫描
- analyze: 深度分析/评估
- exploit: 漏洞利用/POC生成
- fix: 修复建议/补丁
- plan: 方案/计划管理
- git: Git操作
- code_tool: 代码库工具(读取文件、搜索函数等)
- conversion: CLI/自然语言转换
- info: 帮助/信息查询
- general: 通用对话

可用的功能模块:
{', '.join(available_modules)}

请分析：
1. 用户的主要意图是什么
2. 需要使用哪些功能模块
3. 是否需要纯AI模式
4. 是否为测试模式

请返回JSON格式:
{
  "intent": "意图类型",
  "confidence": 0.0-1.0,
  "entities": {
    "modules": ["使用的模块"],
    "pure_ai": true/false,
    "test_mode": true/false,
    "test_file_count": 1,
    "target": "目标路径",
    "details": "详细需求"
  }
}

只返回JSON，不要其他内容。"""
                
                request = AIRequest(
                    prompt=prompt,
                    system_prompt="你是用户意图识别专家，擅长分析长文本命令，能够理解口语化表达和复杂需求。",
                    max_tokens=400,
                    temperature=0.1
                )
                
                response = await self.ai_client.generate(request)
                
                result = self._parse_ai_response(response.content)
                
                try:
                    intent_type = IntentType(result.get("intent", rule_intent.type.value))
                    confidence = float(result.get("confidence", rule_intent.confidence))
                    entities = result.get("entities", {})
                    
                    return ParsedIntent(
                        type=intent_type,
                        confidence=max(confidence, rule_intent.confidence),
                        entities={**rule_intent.entities, **entities},
                        raw_text=text,
                        suggested_pipeline=rule_intent.suggested_pipeline
                    )
                except (ValueError, TypeError):
                    return rule_intent
            else:
                # 单任务命令处理
                prompt = f"""你是一个用户意图识别专家。分析用户的输入，判断其真实意图。

用户输入: {text}
规则解析结果: {rule_intent.type.value} (置信度: {rule_intent.confidence:.0%})

可用的意图类型:
- scan: 代码安全扫描
- analyze: 深度分析/评估
- exploit: 漏洞利用/POC生成
- fix: 修复建议/补丁
- plan: 方案/计划管理
- git: Git操作
- code_tool: 代码库工具(读取文件、搜索函数等)
- conversion: CLI/自然语言转换
- info: 帮助/信息查询
- general: 通用对话

可用的功能模块:
{', '.join(available_modules)}

请返回JSON格式:
{{"intent": "意图类型", "confidence": 0.0-1.0, "entities": {{"modules": ["使用的模块"]}}}}

只返回JSON，不要其他内容。"""

                request = AIRequest(
                    prompt=prompt,
                    system_prompt="你是用户意图识别专家，擅长理解口语化表达和用户需求。",
                    max_tokens=300,
                    temperature=0.1  # 低温度确保稳定输出
                )
                
                response = await self.ai_client.generate(request)
                
                result = self._parse_ai_response(response.content)
                
                try:
                    intent_type = IntentType(result.get("intent", rule_intent.type.value))
                    confidence = float(result.get("confidence", rule_intent.confidence))
                    entities = result.get("entities", {})
                    
                    return ParsedIntent(
                        type=intent_type,
                        confidence=max(confidence, rule_intent.confidence),
                        entities={**rule_intent.entities, **entities},
                        raw_text=text,
                        suggested_pipeline=rule_intent.suggested_pipeline
                    )
                except (ValueError, TypeError):
                    return rule_intent
                    
        except Exception as e:
            return rule_intent
    
    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """解析AI响应"""
        import json
        
        json_match = re.search(r'\{[^{}]+\}', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
                
        return {"intent": "general", "confidence": 0.5}


class IntentParser:
    """统一的意图解析器（规则+AI）
    
    使用策略：
    1. 优先使用规则匹配（快速、准确）
    2. 如果置信度 < 0.8 且AI可用，使用AI增强
    3. 返回最优结果
    """
    
    def __init__(self, ai_client=None):
        self.rule_parser = RuleBasedIntentParser()
        self.ai_parser = AIIntentParser(ai_client) if ai_client else None
        
    def parse(self, text: str) -> ParsedIntent:
        """解析用户意图（同步版本）
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的意图对象
        """
        import asyncio
        
        # 处理长文本
        if len(text) > 1000:
            # 长文本分块处理
            chunks = self._split_long_text(text)
            # 合并分块解析结果
            return self._parse_long_text(chunks)
        
        # 首先检查是否为多任务命令
        multi_task_info = self._detect_multi_task(text)
        if multi_task_info:
            # 对于多任务命令，优先使用AI增强
            if self.ai_parser:
                try:
                    enhanced_intent = asyncio.run(
                        self.ai_parser.enhance(multi_task_info, text)
                    )
                    return enhanced_intent
                except Exception:
                    pass
            return multi_task_info
        
        # 默认使用AI进行理解和规划
        if self.ai_parser:
            try:
                # 先进行规则解析作为基础
                rule_intent = self.rule_parser.parse(text)
                # 无论置信度如何，都使用AI增强
                enhanced_intent = asyncio.run(
                    self.ai_parser.enhance(rule_intent, text)
                )
                return enhanced_intent
            except Exception:
                # AI失败时回退到规则解析
                pass
        
        # 最后回退到规则解析
        rule_intent = self.rule_parser.parse(text)
        return rule_intent
    
    def _split_long_text(self, text: str, max_chunk_size: int = 800) -> List[str]:
        """将长文本分块
        
        Args:
            text: 长文本
            max_chunk_size: 每个分块的最大长度
            
        Returns:
            分块后的文本列表
        """
        chunks = []
        current_chunk = ""
        
        # 按句子分块
        sentences = text.split('。')
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            
            if len(current_chunk) + len(sentence) + 1 <= max_chunk_size:
                current_chunk += sentence + '。'
            else:
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = sentence + '。'
        
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks
    
    def _parse_long_text(self, chunks: List[str]) -> ParsedIntent:
        """解析长文本分块
        
        Args:
            chunks: 分块后的文本列表
            
        Returns:
            合并后的意图
        """
        # 解析每个分块
        chunk_intents = []
        for chunk in chunks:
            # 检测是否为多任务命令
            multi_task_info = self._detect_multi_task(chunk)
            if multi_task_info:
                return multi_task_info
            
            rule_intent = self.rule_parser.parse(chunk)
            chunk_intents.append(rule_intent)
        
        # 合并意图
        if not chunk_intents:
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.5,
                entities={},
                raw_text=' '.join(chunks),
                suggested_pipeline=None
            )
        
        # 确定主要意图类型
        intent_counts = {}
        for intent in chunk_intents:
            intent_counts[intent.type] = intent_counts.get(intent.type, 0) + 1
        
        main_intent_type = max(intent_counts, key=intent_counts.get)
        
        # 合并实体
        merged_entities = {}
        for intent in chunk_intents:
            for key, value in intent.entities.items():
                if key not in merged_entities:
                    merged_entities[key] = value
                elif isinstance(merged_entities[key], list) and isinstance(value, list):
                    merged_entities[key].extend(value)
                elif isinstance(merged_entities[key], dict) and isinstance(value, dict):
                    merged_entities[key].update(value)
        
        # 构建合并后的意图
        merged_intent = ParsedIntent(
            type=main_intent_type,
            confidence=0.8,
            entities=merged_entities,
            raw_text=' '.join(chunks),
            suggested_pipeline=chunk_intents[0].suggested_pipeline
        )
        
        # 如果有AI客户端，使用AI增强意图解析
        if self.ai_parser:
            import asyncio
            try:
                enhanced_intent = asyncio.run(self.ai_parser.enhance(merged_intent, ' '.join(chunks)))
                return enhanced_intent
            except Exception:
                pass
        
        return merged_intent
    
    def _detect_multi_task(self, text: str) -> Optional[ParsedIntent]:
        """检测多任务命令
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的多任务意图对象，或None
        """
        # 检测任务类型关键词
        explain_keywords = ['讲解', '解释', '说明', '介绍', 'explain', 'introduce', '工作原理', '原理', '怎么工作', '如何实现', '什么是']
        scan_keywords = ['扫描', 'scan', '测试', 'test', '检测', '检查']
        pure_ai_keywords = ['纯净', 'pure', '纯AI', 'pure-ai', '纯 AI']
        test_keywords = ['测试', 'test', '只扫描', '仅扫描', '一个文件', '1个文件', '随便扫描', '扫一份文件']
        
        # 检测是否包含讲解和扫描任务
        has_explain = any(keyword in text for keyword in explain_keywords)
        has_scan = any(keyword in text for keyword in scan_keywords)
        has_pure_ai = any(keyword in text for keyword in pure_ai_keywords)
        has_test = any(keyword in text for keyword in test_keywords)
        
        # 即使没有明确的顺序关键词，只要包含讲解和扫描任务，也视为多任务命令
        if has_explain and has_scan:
            # 构建多任务意图
            entities = {
                'tasks': [
                    {'type': 'explain', 'content': '讲解漏扫实现原理'},
                    {'type': 'scan', 'content': '使用纯净AI模式扫描文件'}
                ],
                'pure_ai': has_pure_ai or self.detect_pure_ai_mode(text),
                'test_mode': has_test or self.detect_test_mode(text)[0]
            }
            
            # 检测测试模式文件数量
            test_mode, file_count = self.detect_test_mode(text)
            if test_mode:
                entities['test_file_count'] = file_count
            
            # 检测是否指定了扫描一个文件
            if '一个文件' in text or '1个文件' in text or 'one file' in text.lower() or '只扫描' in text or '仅扫描' in text or '扫一份文件' in text or '随便扫描' in text:
                entities['test_mode'] = True
                entities['test_file_count'] = 1
            
            # 检测是否包含纯净AI模式
            if has_pure_ai:
                entities['pure_ai'] = True
            
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.95,
                entities=entities,
                raw_text=text,
                suggested_pipeline=None
            )
        
        return None
    
    async def parse_async(self, text: str) -> ParsedIntent:
        """异步解析用户意图
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的意图对象
        """
        # 首先检查是否为多任务命令
        multi_task_info = self._detect_multi_task(text)
        if multi_task_info:
            return multi_task_info
        
        rule_intent = self.rule_parser.parse(text)
        
        if rule_intent.confidence < 0.8 and self.ai_parser:
            try:
                return await self.ai_parser.enhance(rule_intent, text)
            except Exception:
                pass
                
        return rule_intent
    
    @staticmethod
    def extract_target_path(text: str) -> str:
        """从文本中提取目标路径
        
        支持格式：
        - Windows绝对路径：C:\\path\\to\\project
        - 相对路径：./src, src/
        - 引号路径："path with spaces"
        
        Args:
            text: 用户输入
            
        Returns:
            提取到的路径，默认为"."
        """
        patterns = [
            r'"([a-zA-Z]:\\[\\\w\s.-]+)"',  # 带引号的Windows路径
            r'([a-zA-Z]:\\[\\\w\s.-]+?)(?:\s+(?:的|扫描|分析)|$)',  # Windows路径
            r'"(.*?)"',  # 带引号的通用路径
            r'(?:目录|文件夹|folder)\s*(.+?)(?:\s|$)',  # 目录后面的路径
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                path = match.group(1).strip()
                if path:
                    return path
                    
        return "."
    
    @staticmethod
    def detect_pure_ai_mode(text: str) -> bool:
        """检测是否需要使用纯AI模式
        
        Args:
            text: 用户输入
            
        Returns:
            是否启用纯AI模式
        """
        pure_ai_indicators = ['纯', 'pure', 'pure-ai', '轻量', '快速']
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in pure_ai_indicators)
    
    @staticmethod
    def detect_test_mode(text: str) -> tuple:
        """检测测试模式及文件数量
        
        Returns:
            (是否测试模式, 文件数量)
        """
        test_match = re.search(r'(?:只|仅|测试)?(?:扫描)?(\d+)个?文件?', text)
        if test_match or '测试' in text or 'test' in text.lower():
            count = int(test_match.group(1)) if test_match else 1
            # 限制测试模式下的文件数量，最多不超过5个
            count = min(count, 5)
            return True, count
        return False, 0

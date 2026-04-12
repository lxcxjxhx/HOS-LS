"""Plan生成器和管理器

负责Plan的生成、管理和版本控制。
"""

import os
import re
from typing import Dict, Any, Optional, List
from pathlib import Path

from src.core.plan import Plan, PlanProfile, PlanStepType
from src.core.plan_dsl import PlanDSLParser
from src.core.config import Config
from src.core.ai_plan_generator import AIPlanGenerator
from src.core.intent_parser import IntentType  # 🔧 BUG FIX #1: 添加缺失的导入


class PlanManager:
    """Plan管理器（增强版：支持自适应策略）"""

    def __init__(self, config: Optional[Config] = None):
        # 确保配置正确传递
        self.config = config
        self.plan_dir = Path.home() / ".hos-ls" / "plans"
        self.plan_dir.mkdir(parents=True, exist_ok=True)
        # 传递配置给AI Plan生成器
        self.ai_generator = AIPlanGenerator(config)

        # ★ 新增：初始化Memory和Strategy系统（可选）
        self.memory_manager = None
        self.strategy_engine = None
        try:
            from ..memory.manager import get_memory_manager
            from .strategy_engine import StrategyEngine

            self.memory_manager = get_memory_manager()
            if config:
                self.strategy_engine = StrategyEngine(config, self.memory_manager)
        except Exception:
            pass  # Memory/Strategy系统可选，失败不影响基本功能

    def generate_adaptive_plan(
        self,
        natural_language: str,
        target_path: str = ".",
        use_strategy: bool = True,
    ) -> "Plan":
        """生成自适应Plan（集成策略引擎）

        这是fix_3.md中"Plan ← Strategy 映射"的具体实现。

        Args:
            natural_language: 自然语言描述的目标
            target_path: 目标路径
            use_strategy: 是否使用AI策略引擎（默认True）

        Returns:
            生成的Plan对象
        """
        # 尝试使用策略引擎
        if use_strategy and self.strategy_engine and self.memory_manager:
            try:
                import asyncio
                from ..memory.models import Intent, IntentType

                # 解析意图
                intent = Intent(
                    intent_type=self._infer_intent_type(natural_language),
                    original_text=natural_language,
                    confidence=0.8,
                    extracted_params=self._extract_plan_params(natural_language),
                )

                # 生成策略
                strategy = asyncio.run(self.strategy_engine.generate_strategy(
                    intent=intent,
                    target_path=target_path,
                ))

                # 策略→Plan转换
                plan = self._strategy_to_plan(strategy, natural_language, target_path)
                return plan

            except Exception as e:
                import logging
                logging.getLogger(__name__).warning(f"自适应Plan生成失败，回退到传统模式: {e}")

        # 回退到原有逻辑
        return self.generate_from_natural_language(natural_language)

    def _infer_intent_type(self, text: str) -> IntentType:
        """从文本推断意图类型"""
        text_lower = text.lower()
        if any(kw in text_lower for kw in ["扫描", "scan", "检查", "检测"]):
            return IntentType.SCAN
        elif any(kw in text_lower for kw in ["分析", "analyze", "审计", "audit"]):
            return IntentType.ANALYZE
        elif any(kw in text_lower for kw in ["攻击", "exploit", "poc", "利用"]):
            return IntentType.EXPLOIT
        else:
            return IntentType.GENERAL

    def _extract_plan_params(self, text: str) -> dict:
        """从文本提取参数"""
        params = {}
        text_lower = text.lower()

        if "快速" in text_lower or "fast" in text_lower:
            params["fast"] = True
        if "深度" in text_lower or "deep" in text_lower or "全面" in text_lower:
            params["deep"] = True
        if "poc" in text_lower or "利用" in text_lower:
            params["poc"] = True
        if "报告" in text_lower or "report" in text_lower:
            params["report"] = True

        return params

    def _strategy_to_plan(
        self,
        strategy: "Strategy",
        goal: str,
        target_path: str,
    ) -> "Plan":
        """将Strategy对象转换为Plan对象

        实现fix_3.md中的映射规则。
        """
        from .plan import Plan, PlanProfile, PlanStepType

        plan = Plan(goal=goal)

        # 映射模式到Profile
        mode_profile_map = {
            "fast": PlanProfile.FAST,
            "balanced": PlanProfile.STANDARD,
            "conservative": PlanProfile.STEALTH,
            "deep": PlanProfile.DEEP,
            "aggressive": PlanProfile.FULL,
        }
        plan.profile = mode_profile_map.get(strategy.mode, PlanProfile.STANDARD)

        # 扫描步骤（必须）
        scan_config = {
            "path": target_path,
            "depth": strategy.decisions.scan_depth,
            "modules": strategy.decisions.modules[:5],  # 限制模块数量
            "safe_mode": strategy.decisions.safe_mode,
        }
        plan.add_step(PlanStepType.SCAN, scan_config)

        # 根据策略决定其他步骤
        if strategy.decisions.enable_auth_analysis or "auth" in strategy.decisions.modules:
            plan.add_step(PlanStepType.AUTH_ANALYSIS, {
                "detect": ["jwt", "session", "oauth", "basic"]
            })

        if strategy.decisions.enable_poc:
            severity_threshold = "high" if strategy.constraints.production_environment else "medium"
            plan.add_step(PlanStepType.POC, {
                "generate": True,
                "severity_threshold": severity_threshold,
            })

        if strategy.decisions.enable_attack_chain:
            plan.add_step(PlanStepType.ATTACK_CHAIN, {"enabled": True})

        # 报告步骤（通常需要）
        plan.add_step(PlanStepType.REPORT, {
            "format": strategy.decisions.output_format or "html",
            "include_code_snippets": True,
        })

        # 应用profile
        plan.apply_profile()

        # 添加元数据
        plan.metadata["strategy_id"] = strategy.strategy_id
        plan.metadata["strategy_source"] = strategy.source
        plan.metadata["strategy_confidence"] = strategy.confidence
        plan.metadata["reasoning"] = strategy.reasoning

        return plan
    
    def generate_from_natural_language(self, natural_language: str) -> Plan:
        """从自然语言生成Plan"""
        # 使用AI生成Plan
        plan = self.ai_generator.generate_plan_sync(natural_language)
        # 应用配置文件
        plan.apply_profile()
        return plan
    
    def generate_from_cli_args(self, args: Dict[str, Any]) -> Plan:
        """从CLI参数生成Plan"""
        # 构建目标
        goal = "代码安全扫描"
        if args.get("ask"):
            goal = args["ask"]
        
        # 确定配置文件
        profile = PlanProfile.STANDARD
        if args.get("fast"):
            profile = PlanProfile.FAST
        elif args.get("deep"):
            profile = PlanProfile.DEEP
        elif args.get("stealth"):
            profile = PlanProfile.STEALTH
        
        # 构建步骤
        steps = []
        
        # 扫描步骤
        scan_config = {"path": args.get("target", ".")}
        if args.get("deep"):
            scan_config["depth"] = "high"
        elif args.get("fast"):
            scan_config["depth"] = "low"
        else:
            scan_config["depth"] = "medium"
        
        if args.get("stealth"):
            scan_config["stealth"] = True
        
        steps.append({
            "type": PlanStepType.SCAN,
            "config": scan_config
        })
        
        # 认证分析
        if args.get("reason") or args.get("full_audit") or args.get("deep_audit"):
            steps.append({
                "type": PlanStepType.AUTH_ANALYSIS,
                "config": {"detect": ["jwt", "session", "oauth"]}
            })
        
        # POC生成
        if args.get("poc") or args.get("full_audit") or args.get("deep_audit") or args.get("red_team"):
            steps.append({
                "type": PlanStepType.POC,
                "config": {"generate": True}
            })
        
        # 攻击链分析
        if args.get("attack_chain") or args.get("full_audit") or args.get("deep_audit") or args.get("red_team"):
            steps.append({
                "type": PlanStepType.ATTACK_CHAIN,
                "config": {"enabled": True}
            })
        
        # 报告生成
        if args.get("report") or args.get("full_audit") or args.get("quick_scan") or args.get("bug_bounty") or args.get("compliance"):
            report_config = {"format": args.get("output_format", "html")}
            if args.get("output"):
                report_config["output"] = args["output"]
            steps.append({
                "type": PlanStepType.REPORT,
                "config": report_config
            })
        
        # 创建Plan
        plan = Plan(goal=goal, profile=profile)
        
        # 添加步骤
        for step_data in steps:
            plan.add_step(step_data["type"], step_data["config"])
        
        # 应用配置文件
        plan.apply_profile()
        
        return plan
    
    def generate_from_template(self, template_name: str) -> Plan:
        """从预设模板生成Plan"""
        templates = {
            "auth-audit": {
                "goal": "认证漏洞审计",
                "profile": PlanProfile.STANDARD,
                "steps": [
                    {"type": PlanStepType.SCAN, "config": {"path": ".", "depth": "medium"}},
                    {"type": PlanStepType.AUTH_ANALYSIS, "config": {"detect": ["jwt", "session", "oauth"]}},
                    {"type": PlanStepType.POC, "config": {"generate": False}}
                ]
            },
            "full-audit": {
                "goal": "全面安全审计",
                "profile": PlanProfile.FULL,
                "steps": [
                    {"type": PlanStepType.SCAN, "config": {"path": ".", "depth": "high"}},
                    {"type": PlanStepType.AUTH_ANALYSIS, "config": {"detect": ["jwt", "session", "oauth", "basic"]}},
                    {"type": PlanStepType.POC, "config": {"generate": True}},
                    {"type": PlanStepType.ATTACK_CHAIN, "config": {"enabled": True}},
                    {"type": PlanStepType.REPORT, "config": {"format": "html"}}
                ]
            },
            "quick-scan": {
                "goal": "快速安全扫描",
                "profile": PlanProfile.FAST,
                "steps": [
                    {"type": PlanStepType.SCAN, "config": {"path": ".", "depth": "low"}},
                    {"type": PlanStepType.REPORT, "config": {"format": "html"}}
                ]
            }
        }
        
        template = templates.get(template_name)
        if not template:
            raise ValueError(f"模板不存在: {template_name}")
        
        plan = Plan(
            goal=template["goal"],
            profile=template["profile"]
        )
        
        for step_data in template["steps"]:
            plan.add_step(step_data["type"], step_data["config"])
        
        plan.apply_profile()
        return plan
    
    def save_plan(self, plan: Plan, name: str) -> str:
        """保存Plan到文件"""
        file_path = self.plan_dir / f"{name}.yaml"
        PlanDSLParser.save_to_file(plan, str(file_path))
        return str(file_path)
    
    def load_plan(self, name: str) -> Plan:
        """加载Plan从文件"""
        file_path = self.plan_dir / f"{name}.yaml"
        if not file_path.exists():
            # 尝试其他格式
            json_path = self.plan_dir / f"{name}.json"
            if json_path.exists():
                file_path = json_path
            else:
                raise FileNotFoundError(f"Plan文件不存在: {name}")
        
        return PlanDSLParser.parse_file(str(file_path))
    
    def list_plans(self) -> List[str]:
        """列出所有保存的Plan"""
        plans = []
        
        # 查找YAML文件
        for file in self.plan_dir.glob("*.yaml"):
            plans.append(file.stem)
        
        # 查找JSON文件
        for file in self.plan_dir.glob("*.json"):
            if file.stem not in plans:
                plans.append(file.stem)
        
        return plans
    
    def delete_plan(self, name: str) -> bool:
        """删除Plan文件"""
        file_path = self.plan_dir / f"{name}.yaml"
        if file_path.exists():
            file_path.unlink()
            return True
        
        json_path = self.plan_dir / f"{name}.json"
        if json_path.exists():
            json_path.unlink()
            return True
        
        return False
    
    def update_plan_version(self, plan: Plan) -> Plan:
        """更新Plan版本"""
        # 解析当前版本
        current_version = plan.plan_version
        match = re.match(r'v(\d+)\.(\d+)', current_version)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            new_version = f"v{major}.{minor + 1}"
        else:
            new_version = "v1.0"
        
        plan.plan_version = new_version
        return plan
    
    def modify_plan(self, plan: Plan, modification: str) -> Plan:
        """通过自然语言修改Plan"""
        # 直接修改Plan的目标和配置
        # 这里我们简化处理，直接更新目标并根据修改内容调整步骤
        
        # 更新目标
        plan.goal = modification
        
        # 检查是否需要修改扫描文件数量
        import re
        count_match = re.search(r'(?:扫|扫描)\s*(\d+)\s*个文件', modification)
        if count_match:
            test_file_count = int(count_match.group(1))
            # 更新扫描步骤的配置
            for step in plan.steps:
                if step.type == PlanStepType.SCAN:
                    step.config['test_file_count'] = test_file_count
        
        # 检查是否需要修改目标路径
        path_match = re.search(r'目录\s*(.+?)\s*下', modification)
        if path_match:
            target_path = path_match.group(1).strip()
            # 更新扫描步骤的配置
            for step in plan.steps:
                if step.type == PlanStepType.SCAN:
                    step.config['path'] = target_path
        
        # 更新版本
        self.update_plan_version(plan)
        return plan
    
    def get_plan_directory(self) -> str:
        """获取Plan目录"""
        return str(self.plan_dir)

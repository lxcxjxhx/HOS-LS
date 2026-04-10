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


class PlanManager:
    """Plan管理器"""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config
        self.plan_dir = Path.home() / ".hos-ls" / "plans"
        self.plan_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_from_natural_language(self, natural_language: str) -> Plan:
        """从自然语言生成Plan"""
        # 简单的规则匹配
        goal = natural_language
        profile = PlanProfile.STANDARD
        steps = []
        
        # 解析目标
        if "认证" in natural_language or "auth" in natural_language.lower():
            goal = "分析认证漏洞"
            steps.append({
                "type": PlanStepType.SCAN,
                "config": {"path": ".", "depth": "medium"}
            })
            steps.append({
                "type": PlanStepType.AUTH_ANALYSIS,
                "config": {"detect": ["jwt", "session", "oauth"]}
            })
            steps.append({
                "type": PlanStepType.POC,
                "config": {"generate": False}
            })
        
        elif "漏洞" in natural_language or "vulnerability" in natural_language.lower():
            goal = "全面漏洞扫描"
            profile = PlanProfile.FULL
            steps.append({
                "type": PlanStepType.SCAN,
                "config": {"path": ".", "depth": "high"}
            })
            steps.append({
                "type": PlanStepType.POC,
                "config": {"generate": True}
            })
            steps.append({
                "type": PlanStepType.ATTACK_CHAIN,
                "config": {"enabled": True}
            })
        
        elif "快速" in natural_language or "fast" in natural_language.lower():
            goal = "快速安全检查"
            profile = PlanProfile.FAST
            steps.append({
                "type": PlanStepType.SCAN,
                "config": {"path": ".", "depth": "low"}
            })
            steps.append({
                "type": PlanStepType.REPORT,
                "config": {"format": "html"}
            })
        
        else:
            # 默认Plan
            goal = natural_language
            steps.append({
                "type": PlanStepType.SCAN,
                "config": {"path": ".", "depth": "medium"}
            })
            steps.append({
                "type": PlanStepType.REPORT,
                "config": {"format": "html"}
            })
        
        # 创建Plan
        plan = Plan(goal=goal, profile=profile)
        
        # 添加步骤
        for step_data in steps:
            plan.add_step(step_data["type"], step_data["config"])
        
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
        # 简单的规则匹配
        if "加上POC" in modification or "add poc" in modification.lower():
            plan.update_step(PlanStepType.POC, {"generate": True})
        
        elif "移除POC" in modification or "remove poc" in modification.lower():
            plan.remove_step(PlanStepType.POC)
        
        elif "深度改成最高" in modification or "depth high" in modification.lower():
            scan_step = plan.get_step(PlanStepType.SCAN)
            if scan_step:
                scan_step.config["depth"] = "high"
        
        elif "深度改成中等" in modification or "depth medium" in modification.lower():
            scan_step = plan.get_step(PlanStepType.SCAN)
            if scan_step:
                scan_step.config["depth"] = "medium"
        
        elif "深度改成最低" in modification or "depth low" in modification.lower():
            scan_step = plan.get_step(PlanStepType.SCAN)
            if scan_step:
                scan_step.config["depth"] = "low"
        
        elif "只扫描登录模块" in modification or "scan login" in modification.lower():
            scan_step = plan.get_step(PlanStepType.SCAN)
            if scan_step:
                scan_step.config["path"] = "./login"
        
        elif "安全模式" in modification:
            if "启用" in modification or "enable" in modification.lower():
                plan.constraints.safe_mode = True
            elif "禁用" in modification or "disable" in modification.lower():
                plan.constraints.safe_mode = False
        
        # 更新版本
        self.update_plan_version(plan)
        
        return plan
    
    def get_plan_directory(self) -> str:
        """获取Plan目录"""
        return str(self.plan_dir)

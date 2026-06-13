"""模板作业系统

支持模板化的扫描作业。
"""

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ScanTemplate:
    """扫描模板"""
    
    name: str
    description: str
    target: str
    ruleset: str = "default"
    format: str = "json"
    output: str = "./report"
    parameters: Dict[str, Any] = field(default_factory=dict)
    pre_scan_hooks: List[str] = field(default_factory=list)
    post_scan_hooks: List[str] = field(default_factory=list)


class TemplateManager:
    """模板管理器"""
    
    def __init__(self, templates_dir: Optional[str] = None) -> None:
        self.templates_dir = Path(templates_dir) if templates_dir else Path("templates")
        self.templates: Dict[str, ScanTemplate] = {}
        self._load_builtin_templates()
    
    def _load_builtin_templates(self) -> None:
        """加载内置模板"""
        builtin_templates = [
            ScanTemplate(
                name="default_scan",
                description="默认扫描模板",
                target=".",
                ruleset="default",
                format="json",
                output="./security-report",
            ),
            ScanTemplate(
                name="quick_scan",
                description="快速扫描模板",
                target=".",
                ruleset="quick",
                format="json",
                output="./quick-report",
                parameters={"max_files": 100, "timeout": 60},
            ),
            ScanTemplate(
                name="deep_scan",
                description="深度扫描模板",
                target=".",
                ruleset="full",
                format="html",
                output="./detailed-report",
                parameters={"ai_enabled": True, "attack_simulation": True},
            ),
            ScanTemplate(
                name="pr_scan",
                description="PR 扫描模板",
                target="--diff",
                ruleset="default",
                format="sarif",
                output="./pr-results",
                parameters={"comment_on_pr": True},
            ),
            ScanTemplate(
                name="ai_security",
                description="AI 安全扫描模板",
                target=".",
                ruleset="ai_security",
                format="html",
                output="./ai-security-report",
                parameters={
                    "check_prompt_injection": True,
                    "check_data_leakage": True,
                    "check_model_abuse": True,
                },
            ),
        ]
        
        for template in builtin_templates:
            self.templates[template.name] = template
    
    def load_from_file(self, file_path: str) -> Optional[ScanTemplate]:
        """从文件加载模板"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            template = ScanTemplate(
                name=data.get("name", "unnamed"),
                description=data.get("description", ""),
                target=data.get("target", "."),
                ruleset=data.get("ruleset", "default"),
                format=data.get("format", "json"),
                output=data.get("output", "./report"),
                parameters=data.get("parameters", {}),
                pre_scan_hooks=data.get("pre_scan_hooks", []),
                post_scan_hooks=data.get("post_scan_hooks", []),
            )
            
            self.templates[template.name] = template
            return template
            
        except Exception:
            return None
    
    def load_from_directory(self) -> int:
        """从目录加载所有模板"""
        if not self.templates_dir.exists():
            return 0
        
        count = 0
        for file_path in self.templates_dir.glob("*.yaml"):
            if self.load_from_file(str(file_path)):
                count += 1
        
        return count
    
    def get_template(self, name: str) -> Optional[ScanTemplate]:
        """获取模板"""
        return self.templates.get(name)
    
    def list_templates(self) -> List[ScanTemplate]:
        """列出所有模板"""
        return list(self.templates.values())
    
    def save_template(
        self, template: ScanTemplate, file_path: Optional[str] = None
    ) -> str:
        """保存模板"""
        if file_path is None:
            self.templates_dir.mkdir(parents=True, exist_ok=True)
            file_path = str(self.templates_dir / f"{template.name}.yaml")
        
        data = {
            "name": template.name,
            "description": template.description,
            "target": template.target,
            "ruleset": template.ruleset,
            "format": template.format,
            "output": template.output,
            "parameters": template.parameters,
            "pre_scan_hooks": template.pre_scan_hooks,
            "post_scan_hooks": template.post_scan_hooks,
        }
        
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        
        return file_path


class TemplateExecutor:
    """模板执行器"""
    
    def __init__(self, template_manager: Optional[TemplateManager] = None) -> None:
        self.template_manager = template_manager or TemplateManager()
    
    async def execute(
        self,
        template_name: str,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """执行模板
        
        Args:
            template_name: 模板名称
            overrides: 覆盖参数
            
        Returns:
            执行结果
        """
        template = self.template_manager.get_template(template_name)
        if not template:
            return {"error": f"模板 '{template_name}' 不存在"}
        
        # 合并覆盖参数
        params = {**template.parameters, **(overrides or {})}
        
        # 执行预扫描钩子
        for hook in template.pre_scan_hooks:
            await self._execute_hook(hook, params)
        
        # 执行扫描
        from src.core.scanner import create_scanner
        
        scanner = create_scanner()
        result = scanner.scan_sync(
            overrides.get("target", template.target) if overrides else template.target
        )
        
        # 执行后扫描钩子
        for hook in template.post_scan_hooks:
            await self._execute_hook(hook, {**params, "result": result.to_dict()})
        
        return {
            "template": template_name,
            "result": result.to_dict(),
            "output_path": template.output,
        }
    
    async def _execute_hook(
        self, hook: str, parameters: Dict[str, Any]
    ) -> None:
        """执行钩子"""
        # 简单的钩子执行实现
        if hook == "notify":
            print(f"通知: 扫描完成")
        elif hook == "cleanup":
            print("清理临时文件")
        elif hook.startswith("script:"):
            script = hook[7:]
            print(f"执行脚本: {script}")

"""POC 集成模块

将 POC 生成和执行集成到 HOS-LS 扫描流程中。
"""

from typing import Dict, List, Any, Optional
from pathlib import Path


class POCIntegration:
    """POC 集成管理器"""

    def __init__(self, config):
        self.config = config
        self.poc_generator = None
        self.poc_runner = None
        self._init_components()

    def _init_components(self):
        """初始化 POC 组件"""
        try:
            from src.analyzers.verification.method_storage import MethodStorage
            from src.analyzers.verification.poc_generator import AIPOCGenerator

            project_root = Path(__file__).parent.parent.parent
            storage_path = project_root / "dynamic_code" / "methods"
            pocs_output = project_root / "dynamic_code" / "pocs" / "generated"

            storage_path.mkdir(parents=True, exist_ok=True)
            pocs_output.mkdir(parents=True, exist_ok=True)

            method_storage = MethodStorage(str(storage_path))
            self.poc_generator = AIPOCGenerator(method_storage, str(pocs_output))
        except Exception as e:
            self.poc_generator = None

        try:
            from src.execution.poc_runner import POCRunner
            self.poc_runner = POCRunner()
        except Exception:
            self.poc_runner = None

    def generate_pocs_for_findings(self, findings: List[Any], target: str) -> Dict[str, Any]:
        """为扫描发现生成 POC

        Args:
            findings: 扫描发现的漏洞列表
            target: 扫描目标

        Returns:
            POC 生成结果
        """
        results = {
            "total": len(findings),
            "generated": 0,
            "failed": 0,
            "pocs": []
        }

        if not self.poc_generator:
            results["error"] = "POC Generator not initialized"
            return results

        for finding in findings:
            try:
                context = {
                    "file_path": getattr(finding, 'file_path', ''),
                    "line_number": getattr(finding, 'line_number', 0),
                    "vuln_type": getattr(finding, 'vuln_type', getattr(finding, 'rule_name', 'unknown')),
                    "message": getattr(finding, 'message', ''),
                    "severity": str(getattr(finding, 'severity', 'unknown')),
                    "confidence": getattr(finding, 'confidence', 0.0),
                }

                method_id = self.poc_generator.generate_poc(
                    context=context,
                    validator_name=getattr(finding, 'validator_name', None)
                )

                results["generated"] += 1
                results["pocs"].append({
                    "method_id": method_id,
                    "vuln_type": context["vuln_type"],
                    "file_path": context["file_path"],
                    "line_number": context["line_number"]
                })
            except Exception as e:
                results["failed"] += 1

        return results

    def run_pocs(self, poc_list: List[Dict], target: str) -> Dict[str, Any]:
        """执行 POC 列表

        Args:
            poc_list: POC 列表
            target: 目标 URL

        Returns:
            执行结果
        """
        results = {
            "total": len(poc_list),
            "executed": 0,
            "vulnerable": 0,
            "errors": 0,
            "details": []
        }

        if not self.poc_runner:
            results["error"] = "POC Runner not initialized"
            return results

        if not self.poc_generator:
            results["error"] = "POC Generator not initialized"
            return results

        for poc in poc_list:
            try:
                method_id = poc.get("method_id")
                vuln_type = poc.get("vuln_type", "unknown")

                script = self.poc_generator.get_poc_script(method_id)
                if not script:
                    continue

                result = self.poc_runner.run_poc(
                    poc_script=script,
                    target=target,
                    vuln_type=vuln_type,
                    poc_id=method_id
                )

                results["executed"] += 1
                if result.get("vulnerable"):
                    results["vulnerable"] += 1
                results["details"].append(result)

            except Exception as e:
                results["errors"] += 1

        return results

    def get_poc_script(self, method_id: str) -> Optional[str]:
        """获取 POC 脚本

        Args:
            method_id: POC 方法 ID

        Returns:
            POC 脚本内容
        """
        if not self.poc_generator:
            return None
        return self.poc_generator.get_poc_script(method_id)

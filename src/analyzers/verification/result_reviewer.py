from pathlib import Path
from typing import Dict, List, Optional, Any
import json
import yaml
from datetime import datetime

from .interfaces import ValidationResult, VulnContext
from .dynamic_loader import DynamicLoader
from .method_storage import MethodStorage
from .poc_generator import AIPOCGenerator
from .config_loader import ConfigLoader


class ResultReviewer:
    """
    扫描结果复核器

    职责：
    - 加载扫描报告
    - 选择合适的验证器
    - 执行验证
    - 生成最终报告
    - AI 辅助验证（当验证器不确定时）
    """

    def __init__(
        self,
        project_root: str,
        dynamic_code_path: str,
        config_path: str
    ):
        self.project_root = Path(project_root)
        self.dynamic_code_path = Path(dynamic_code_path)

        self.config_loader = ConfigLoader(config_path)
        self.dynamic_loader = DynamicLoader(str(self.dynamic_code_path))
        self.method_storage = MethodStorage(str(self.dynamic_code_path / 'methods'))
        self.poc_generator = AIPOCGenerator(
            self.method_storage,
            str(self.dynamic_code_path / 'pocs' / 'generated')
        )

        self.scan_report: Dict[str, Any] = {}
        self.verification_results: List[Dict[str, Any]] = []
        self.ai_enabled: bool = False
        self.ai_fallback_threshold: float = 0.6
        self._load_ai_config()

    def _load_ai_config(self) -> None:
        """加载 AI 配置"""
        try:
            config = self.config_loader.get_config()
            global_config = config.get('global', {})
            self.ai_enabled = global_config.get('ai_verification_enabled', False)
            self.ai_fallback_threshold = global_config.get('ai_fallback_threshold', 0.6)
        except Exception as e:
            print(f"Failed to load AI config: {e}")
            self.ai_enabled = False

    def load_report(self, report_path: str) -> bool:
        """
        加载扫描报告

        Args:
            report_path: 报告文件路径

        Returns:
            是否加载成功
        """
        report_path = Path(report_path)

        if not report_path.exists():
            print(f"Report file not found: {report_path}")
            return False

        try:
            if report_path.suffix == '.json':
                with open(report_path, 'r', encoding='utf-8') as f:
                    self.scan_report = json.load(f)
            elif report_path.suffix in ['.yaml', '.yml']:
                with open(report_path, 'r', encoding='utf-8') as f:
                    self.scan_report = yaml.safe_load(f)
            else:
                print(f"Unsupported report format: {report_path.suffix}")
                return False

            return True

        except Exception as e:
            print(f"Failed to load report: {e}")
            return False

    def load_report_from_dict(self, report_data: Dict[str, Any]):
        """
        从字典加载报告数据

        Args:
            report_data: 报告数据字典
        """
        self.scan_report = report_data

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        获取扫描发现列表

        Returns:
            发现列表
        """
        if 'findings' in self.scan_report:
            return self.scan_report['findings']
        elif 'vulnerabilities' in self.scan_report:
            return self.scan_report['vulnerabilities']
        else:
            return []

    def select_validators(self, vuln_type: str = None) -> List[Any]:
        """
        选择验证器

        Args:
            vuln_type: 漏洞类型过滤（可选）

        Returns:
            验证器列表
        """
        self.dynamic_loader.scan_validators()

        if vuln_type:
            return self.dynamic_loader.select_validators(vuln_type)

        return list(self.dynamic_loader.validators.values())

    def run_verification(
        self,
        findings: List[Dict[str, Any]] = None,
        vuln_type: str = None,
        use_ai_fallback: bool = True
    ) -> List[Dict[str, Any]]:
        """
        执行验证

        Args:
            findings: 发现列表（可选，默认使用报告中的发现）
            vuln_type: 漏洞类型过滤（可选）
            use_ai_fallback: 当验证器不确定时是否使用 AI 辅助

        Returns:
            验证结果列表
        """
        if findings is None:
            findings = self.get_findings()

        validators = self.select_validators(vuln_type)

        self.verification_results = []

        for finding in findings:
            finding_id = finding.get('id', finding.get('finding_id', ''))
            file_path = finding.get('file_path', finding.get('path', ''))
            line_number = finding.get('line_number', finding.get('line', 0))
            code_snippet = finding.get('code_snippet', finding.get('snippet', ''))
            vuln_type = finding.get('vuln_type', finding.get('type', ''))

            context = VulnContext(
                file_path=str(file_path),
                line_number=int(line_number),
                code_snippet=str(code_snippet),
                vuln_type=str(vuln_type),
                project_root=str(self.project_root),
                finding_id=str(finding_id),
                metadata=finding
            )

            result = self._verify_finding(context, validators, finding, use_ai_fallback)

            self.verification_results.append({
                'finding_id': finding_id,
                'file_path': file_path,
                'line_number': line_number,
                'vuln_type': vuln_type,
                'is_valid': result.is_valid,
                'is_false_positive': result.is_false_positive,
                'confidence': result.confidence,
                'reason': result.reason,
                'evidence': result.evidence,
                'poc_script': result.poc_script,
                'verification_steps': result.verification_steps,
                'ai_assisted': getattr(result, 'ai_assisted', False)
            })

        return self.verification_results

    def _verify_finding(
        self,
        context: VulnContext,
        validators: List[Any],
        finding: Dict[str, Any],
        use_ai_fallback: bool = True
    ) -> ValidationResult:
        """
        验证单个发现

        Args:
            context: 漏洞上下文
            validators: 验证器列表
            finding: 原始发现数据
            use_ai_fallback: 是否使用 AI 辅助

        Returns:
            验证结果
        """
        applicable_validators = [
            v for v in validators
            if v.check_applicability(context)
        ]

        if not applicable_validators:
            if use_ai_fallback and self.ai_enabled:
                return self.verify_with_ai(context, finding, "no_applicable_validator")
            return ValidationResult(
                is_valid=None,
                is_false_positive=None,
                confidence=0.5,
                reason="没有适用的验证器，需人工复核",
                evidence={'finding': finding}
            )

        best_result = None
        best_confidence = -1

        for validator in applicable_validators:
            try:
                result = validator.validate(context)

                if result.confidence > best_confidence:
                    best_confidence = result.confidence
                    best_result = result

                if result.is_valid is True and result.confidence >= 0.8:
                    break

            except Exception as e:
                print(f"Validator {validator.name} failed: {e}")
                continue

        if best_result is None:
            if use_ai_fallback and self.ai_enabled:
                return self.verify_with_ai(context, finding, "all_validators_failed")
            return ValidationResult(
                is_valid=None,
                is_false_positive=None,
                confidence=0.5,
                reason="所有验证器执行失败，需人工复核",
                evidence={'finding': finding}
            )

        if best_result.is_valid is None and best_result.confidence < self.ai_fallback_threshold:
            if use_ai_fallback and self.ai_enabled:
                ai_result = self.verify_with_ai(context, finding, "low_confidence")
                if ai_result and ai_result.confidence > best_result.confidence:
                    return ai_result

        return best_result

    def verify_with_ai(
        self,
        context: VulnContext,
        finding: Dict[str, Any],
        fallback_reason: str
    ) -> ValidationResult:
        """
        使用 AI 辅助验证

        Args:
            context: 漏洞上下文
            finding: 原始发现数据
            fallback_reason: 调用 AI 的原因

        Returns:
            AI 验证结果
        """
        try:
            import openai

            vuln_type = context.vuln_type
            code_snippet = context.code_snippet
            file_path = context.file_path

            prompt = f"""你是专业的安全研究员，请分析以下代码片段是否存在安全漏洞。

漏洞类型: {vuln_type}
文件: {file_path}
代码片段:
```{code_snippet}```

请分析：
1. 这段代码是否真的存在 {vuln_type} 漏洞？
2. 如果存在，攻击者如何利用？
3. 如果不存在，请说明原因（可能是误报）

请以以下格式回复：
- 结论: 存在漏洞/不存在漏洞/需人工复核
- 置信度: 0.0-1.0
- 原因: 详细解释
"""

            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a professional security researcher."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )

            ai_response = response.choices[0].message.content

            is_valid = "存在漏洞" in ai_response and "不存在漏洞" not in ai_response
            is_false_positive = "不存在漏洞" in ai_response

            if "置信度:" in ai_response:
                try:
                    conf_str = ai_response.split("置信度:")[1].split("\n")[0].strip()
                    confidence = float(conf_str)
                except:
                    confidence = 0.6
            else:
                confidence = 0.6

            result = ValidationResult(
                is_valid=is_valid if not is_false_positive else False,
                is_false_positive=is_false_positive,
                confidence=confidence,
                reason=f"[AI辅助] {ai_response}",
                evidence={'fallback_reason': fallback_reason, 'ai_response': ai_response}
            )
            result.ai_assisted = True

            return result

        except ImportError:
            print("OpenAI not installed, skipping AI verification")
        except Exception as e:
            print(f"AI verification failed: {e}")

        return ValidationResult(
            is_valid=None,
            is_false_positive=None,
            confidence=0.5,
            reason=f"AI验证失败(fallback_reason: {fallback_reason})，需人工复核",
            evidence={'fallback_reason': fallback_reason}
        )

    def generate_final_report(
        self,
        output_path: str = None,
        include_poc: bool = True
    ) -> Dict[str, Any]:
        """
        生成最终验证报告

        Args:
            output_path: 输出路径（可选）
            include_poc: 是否包含 POC 脚本信息

        Returns:
            最终报告字典
        """
        verified_count = sum(1 for r in self.verification_results if r['is_valid'] is True)
        false_positive_count = sum(1 for r in self.verification_results if r['is_false_positive'] is True)
        uncertain_count = sum(1 for r in self.verification_results if r['is_valid'] is None)
        ai_assisted_count = sum(1 for r in self.verification_results if r.get('ai_assisted', False))

        final_report = {
            'scan_info': self.scan_report.get('scan_info', {}),
            'verification_summary': {
                'total_findings': len(self.verification_results),
                'verified': verified_count,
                'false_positives': false_positive_count,
                'uncertain': uncertain_count,
                'ai_assisted': ai_assisted_count,
                'verification_time': datetime.now().isoformat(),
            },
            'verification_results': self.verification_results,
            'config': {
                'verification_enabled': self.config_loader.is_verification_enabled(),
                'ai_verification_enabled': self.ai_enabled,
                'ai_fallback_threshold': self.ai_fallback_threshold,
                'dynamic_code_path': str(self.dynamic_code_path),
            }
        }

        if include_poc:
            pocs = self.poc_generator.list_generated_pocs()
            final_report['generated_pocs'] = pocs

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(final_report, f, ensure_ascii=False, indent=2)

        return final_report

    def generate_markdown_report(self, output_path: str = None) -> str:
        """
        生成 Markdown 格式的报告

        Args:
            output_path: 输出路径（可选）

        Returns:
            Markdown 格式的报告字符串
        """
        md_lines = [
            "# 漏洞验证报告",
            "",
            "## 验证摘要",
            "",
        ]

        verified_count = sum(1 for r in self.verification_results if r['is_valid'] is True)
        false_positive_count = sum(1 for r in self.verification_results if r['is_false_positive'] is True)
        uncertain_count = sum(1 for r in self.verification_results if r['is_valid'] is None)
        ai_assisted_count = sum(1 for r in self.verification_results if r.get('ai_assisted', False))

        md_lines.extend([
            f"- 总发现数: {len(self.verification_results)}",
            f"- 确认漏洞: {verified_count}",
            f"- 误报: {false_positive_count}",
            f"- 待复核: {uncertain_count}",
            f"- AI辅助: {ai_assisted_count}",
            "",
            "## 验证结果详情",
            "",
        ])

        for result in self.verification_results:
            status = "✅ 确认" if result['is_valid'] else ("❌ 误报" if result['is_false_positive'] else "⚠️ 待复核")
            ai_tag = " [AI]" if result.get('ai_assisted', False) else ""
            md_lines.extend([
                f"### {result['finding_id']} - {result['vuln_type']}{ai_tag}",
                "",
                f"- **状态**: {status}",
                f"- **文件**: {result['file_path']}:{result['line_number']}",
                f"- **置信度**: {result['confidence']:.2f}",
                f"- **原因**: {result['reason']}",
                "",
            ])

        md_content = "\n".join(md_lines)

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_content)

        return md_content

    def get_false_positives(self) -> List[Dict[str, Any]]:
        """
        获取误报列表

        Returns:
            误报列表
        """
        return [
            r for r in self.verification_results
            if r.get('is_false_positive') is True
        ]

    def get_verified_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        获取确认的漏洞列表

        Returns:
            确认的漏洞列表
        """
        return [
            r for r in self.verification_results
            if r.get('is_valid') is True
        ]

    def get_uncertain_findings(self) -> List[Dict[str, Any]]:
        """
        获取待复核的发现列表

        Returns:
            待复核的发现列表
        """
        return [
            r for r in self.verification_results
            if r.get('is_valid') is None
        ]

    def apply_user_feedback(
        self,
        finding_id: str,
        feedback: Dict[str, Any]
    ) -> bool:
        """
        应用用户反馈

        Args:
            finding_id: 发现ID
            feedback: 反馈内容

        Returns:
            是否应用成功
        """
        for result in self.verification_results:
            if result['finding_id'] == finding_id:
                if 'is_false_positive' in feedback:
                    result['is_false_positive'] = feedback['is_false_positive']
                    result['is_valid'] = not feedback['is_false_positive']

                if 'reason' in feedback:
                    result['reason'] = feedback['reason']

                if feedback.get('adjust_poc') and result.get('poc_script'):
                    new_method_id = self.poc_generator.auto_adjust_poc(
                        result['poc_script'],
                        feedback
                    )
                    result['poc_script'] = new_method_id

                return True

        return False

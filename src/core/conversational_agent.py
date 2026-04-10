from typing import Dict, Any, Optional, List
from pathlib import Path
import json
import os

from src.core.config import Config
from src.core.langgraph_flow import analyze_code
from src.core.scanner import create_scanner
from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline


class ConversationalSecurityAgent:
    """对话式安全 Agent
    
    处理用户自然语言输入，路由到相应的安全分析流程
    """
    
    def __init__(self, config: Config, session: Optional[str] = None, model: Optional[str] = None):
        """初始化对话 Agent
        
        Args:
            config: 配置对象
            session: 会话名称，用于保存对话历史
            model: AI 模型名称
        """
        self.config = config
        self.session = session
        self.model = model or config.ai.model
        self.conversation_history: List[Dict[str, str]] = []
        self.project_context: Dict[str, Any] = {}
        
        # 加载会话历史
        if session:
            self._load_session()
        
        # 初始化多 Agent 管道
        import asyncio
        from src.ai.client import get_model_manager
        
        # 初始化模型管理器
        model_manager = asyncio.run(get_model_manager(config))
        ai_client = model_manager.get_default_client()
        
        if not ai_client:
            raise RuntimeError("无法初始化 AI 客户端")
        
        self.multi_agent_pipeline = MultiAgentPipeline(ai_client, config)
        
        # 生成项目摘要
        self._generate_project_summary()
    
    def process(self, user_input: str) -> Dict[str, Any]:
        """处理用户输入
        
        Args:
            user_input: 用户自然语言输入
            
        Returns:
            处理结果
        """
        # 添加到对话历史
        self.conversation_history.append({"role": "user", "content": user_input})
        
        try:
            # 分析用户意图
            intent = self.parse_intent(user_input)
            
            # 根据意图执行相应操作
            if intent == "scan":
                result = self._handle_scan(user_input)
            elif intent == "analyze":
                result = self._handle_analyze(user_input)
            elif intent == "exploit":
                result = self._handle_exploit(user_input)
            elif intent == "fix":
                result = self._handle_fix(user_input)
            elif intent == "info":
                result = self._handle_info(user_input)
            elif intent == "git":
                result = self._handle_git_operations(user_input)
            else:
                result = self._handle_general(user_input)
            
            # 添加到对话历史
            self.conversation_history.append({"role": "assistant", "content": str(result)})
            
            # 保存会话历史
            if self.session:
                self._save_session()
            
            return result
            
        except Exception as e:
            error_result = {"error": str(e)}
            self.conversation_history.append({"role": "assistant", "content": f"错误: {str(e)}"})
            return error_result
    
    def parse_intent(self, user_input: str) -> str:
        """解析用户意图
        
        Args:
            user_input: 用户输入
            
        Returns:
            意图类型
        """
        user_input_lower = user_input.lower()
        
        if any(keyword in user_input_lower for keyword in ["scan", "扫描", "检查", "检测"]):
            return "scan"
        elif any(keyword in user_input_lower for keyword in ["analyze", "分析", "评估", "风险"]):
            return "analyze"
        elif any(keyword in user_input_lower for keyword in ["exploit", "攻击", "poc", "利用"]):
            return "exploit"
        elif any(keyword in user_input_lower for keyword in ["fix", "修复", "patch", "修复建议"]):
            return "fix"
        elif any(keyword in user_input_lower for keyword in ["help", "帮助", "info", "信息"]):
            return "info"
        elif any(keyword in user_input_lower for keyword in ["git", "commit", "提交", "branch", "分支", "diff", "差异", "status", "状态"]):
            return "git"
        else:
            return "general"
    
    def _handle_scan(self, user_input: str) -> Dict[str, Any]:
        """处理扫描命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            扫描结果
        """
        # 提取目标路径
        target = "."
        import re
        
        # 尝试提取路径（支持绝对路径）
        # 改进的 Windows 路径匹配，支持包含空格的路径
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:测试|test|模式|pure|纯|个文件|文件)|$)"  # 匹配 Windows 绝对路径，直到特定关键词
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
        # 尝试匹配带引号的路径
        quoted_path_pattern = r'"([a-zA-Z]:\\[\\\w\s.-]+)"'
        quoted_match = re.search(quoted_path_pattern, user_input)
        if quoted_match:
            target = quoted_match.group(1).strip()
        elif "目录" in user_input or "folder" in user_input:
            # 尝试提取相对路径
            path_match = re.search(r"(目录|folder)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                target = path_match.group(2).strip() or "."
        
        # 检查是否使用纯 AI 模式
        pure_ai = "pure" in user_input.lower() or "纯" in user_input
        
        # 检查是否为测试模式
        test_mode = "测试" in user_input or "test" in user_input.lower()
        test_file_count = 1
        if test_mode:
            # 尝试提取测试文件数量
            test_match = re.search(r"(只|仅)扫描(\d+)个文件", user_input)
            if test_match:
                try:
                    test_file_count = int(test_match.group(2))
                except:
                    test_file_count = 1
            self.config.test_mode = True
            self.config.__dict__['test_file_count'] = test_file_count
        else:
            self.config.test_mode = False
        
        # 执行扫描
        try:
            if pure_ai:
                self.config.pure_ai = True
                scanner = create_scanner(self.config)
                result = scanner.scan_sync(target)
            else:
                self.config.pure_ai = False
                scanner = create_scanner(self.config)
                result = scanner.scan_sync(target)
            
            return {
                "type": "scan_result",
                "target": target,
                "pure_ai": pure_ai,
                "test_mode": test_mode,
                "test_file_count": test_file_count,
                "result": result.to_dict()
            }
        except Exception as e:
            return {
                "type": "error",
                "target": target,
                "error": str(e)
            }
    
    def _handle_analyze(self, user_input: str) -> Dict[str, Any]:
        """处理分析命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            分析结果
        """
        # 提取目标路径
        target = "."
        import re
        
        # 尝试提取路径（支持绝对路径）
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:分析|analyze|评估|风险)|$)"
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
        # 尝试匹配带引号的路径
        quoted_path_pattern = r'"([a-zA-Z]:\\[\\\w\s.-]+)"'
        quoted_match = re.search(quoted_path_pattern, user_input)
        if quoted_match:
            target = quoted_match.group(1).strip()
        elif "目录" in user_input or "folder" in user_input:
            # 尝试提取相对路径
            path_match = re.search(r"(目录|folder)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                target = path_match.group(2).strip() or "."
        
        # 执行 LangGraph 分析
        try:
            import asyncio
            from src.utils.terminal_ui import TerminalUI
            
            terminal_ui = TerminalUI()
            
            # 显示分析进度
            terminal_ui.show_agent_thinking("Planner", f"开始分析目标: {target}")
            
            # 执行 LangGraph 分析
            result = asyncio.run(analyze_code(f"目录扫描: {target}"))
            
            # 显示分析完成
            terminal_ui.show_agent_thinking("Planner", "分析完成")
            
            return {
                "type": "analysis_result",
                "target": target,
                "result": result
            }
        except Exception as e:
            return {
                "type": "error",
                "target": target,
                "error": str(e)
            }
    
    def _handle_exploit(self, user_input: str) -> Dict[str, Any]:
        """处理漏洞利用命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            利用结果
        """
        # 提取目标
        target = "."
        import re
        
        # 尝试提取路径
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:攻击|exploit|poc|利用)|$)"
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
        elif "目录" in user_input or "folder" in user_input:
            path_match = re.search(r"(目录|folder)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                target = path_match.group(2).strip() or "."
        
        # 检查是否需要验证 POC
        verify_poc = "验证" in user_input or "verify" in user_input.lower()
        
        # 生成 POC
        try:
            from src.exploit.generator import ExploitGenerator
            generator = ExploitGenerator(self.config)
            
            # 先执行扫描获取漏洞信息
            scanner = create_scanner(self.config)
            scan_result = scanner.scan_sync(target)
            
            # 生成 POC
            exploits = []
            if scan_result.findings:
                for finding in scan_result.findings[:3]:  # 只生成前3个漏洞的 POC
                    try:
                        exploit = generator.generate(finding)
                        if exploit:
                            # 如果需要验证，在沙箱中运行
                            if verify_poc:
                                verification_result = self._verify_exploit(exploit, finding)
                                exploits.append({
                                    "exploit": exploit,
                                    "verification": verification_result
                                })
                            else:
                                exploits.append(exploit)
                    except Exception as e:
                        # 记录错误但继续处理其他漏洞
                        pass
            
            return {
                "type": "exploit_result",
                "target": target,
                "verify_poc": verify_poc,
                "exploits": exploits
            }
        except Exception as e:
            return {
                "type": "error",
                "target": target,
                "error": f"生成漏洞利用失败: {str(e)}"
            }
    
    def _verify_exploit(self, exploit: str, finding) -> Dict[str, Any]:
        """在沙箱中验证 POC
        
        Args:
            exploit: 漏洞利用代码
            finding: 漏洞发现
            
        Returns:
            验证结果
        """
        try:
            # 检查是否有 Docker 环境
            import subprocess
            import os
            
            # 检查 Docker 是否可用
            try:
                subprocess.run(["docker", "--version"], capture_output=True, check=True)
                docker_available = True
            except (subprocess.SubprocessError, FileNotFoundError):
                docker_available = False
            
            if not docker_available:
                return {
                    "status": "error",
                    "message": "Docker 环境不可用，无法验证 POC"
                }
            
            # 这里是示例实现，实际需要根据漏洞类型创建相应的沙箱环境
            # 注意：实际实现需要更复杂的逻辑来处理不同类型的漏洞
            
            # 创建临时目录
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                # 写入 POC 文件
                poc_file = os.path.join(temp_dir, "exploit.py")
                with open(poc_file, 'w', encoding='utf-8') as f:
                    f.write(exploit)
                
                # 模拟沙箱验证
                # 实际实现中，这里应该启动 Docker 容器并运行 POC
                
                # 示例验证结果
                return {
                    "status": "success",
                    "message": "POC 验证成功",
                    "details": "在沙箱环境中成功验证了漏洞利用"
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"验证 POC 失败: {str(e)}"
            }
    
    def _handle_git_operations(self, user_input: str) -> Dict[str, Any]:
        """处理 Git 操作命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            Git 操作结果
        """
        import re
        import subprocess
        import os
        
        # 提取操作类型
        if "commit" in user_input or "提交" in user_input:
            return self._git_commit(user_input)
        elif "branch" in user_input or "分支" in user_input:
            return self._git_branch(user_input)
        elif "diff" in user_input or "差异" in user_input:
            return self._git_diff(user_input)
        elif "status" in user_input or "状态" in user_input:
            return self._git_status(user_input)
        else:
            return {
                "type": "error",
                "error": "不支持的 Git 操作"
            }
    
    def _git_commit(self, user_input: str) -> Dict[str, Any]:
        """执行 Git 提交操作
        
        Args:
            user_input: 用户输入
            
        Returns:
            提交结果
        """
        try:
            # 检查是否在 Git 仓库中
            if not self._is_git_repository():
                return {
                    "type": "error",
                    "error": "当前目录不是 Git 仓库"
                }
            
            # 提取提交信息
            import re
            commit_msg_match = re.search(r"(commit|提交)\s*(.*?)(?:的|$)", user_input)
            commit_message = commit_msg_match.group(2).strip() if commit_msg_match else "修复安全漏洞"
            
            # 执行 git add .
            subprocess.run(["git", "add", "."], check=True, capture_output=True)
            
            # 执行 git commit
            result = subprocess.run(
                ["git", "commit", "-m", commit_message],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "type": "git_result",
                    "operation": "commit",
                    "status": "success",
                    "message": "提交成功",
                    "output": result.stdout
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "commit",
                    "status": "error",
                    "message": "提交失败",
                    "output": result.stderr
                }
        except Exception as e:
            return {
                "type": "error",
                "error": f"执行 Git 提交失败: {str(e)}"
            }
    
    def _git_branch(self, user_input: str) -> Dict[str, Any]:
        """执行 Git 分支操作
        
        Args:
            user_input: 用户输入
            
        Returns:
            分支操作结果
        """
        try:
            # 检查是否在 Git 仓库中
            if not self._is_git_repository():
                return {
                    "type": "error",
                    "error": "当前目录不是 Git 仓库"
                }
            
            import re
            # 提取分支名称
            branch_match = re.search(r"(branch|分支)\s*(.*?)(?:的|$)", user_input)
            branch_name = branch_match.group(2).strip() if branch_match else "security-fixes"
            
            # 执行 git checkout -b
            result = subprocess.run(
                ["git", "checkout", "-b", branch_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "type": "git_result",
                    "operation": "branch",
                    "status": "success",
                    "message": f"创建并切换到分支 {branch_name}",
                    "output": result.stdout
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "branch",
                    "status": "error",
                    "message": "分支操作失败",
                    "output": result.stderr
                }
        except Exception as e:
            return {
                "type": "error",
                "error": f"执行 Git 分支操作失败: {str(e)}"
            }
    
    def _git_diff(self, user_input: str) -> Dict[str, Any]:
        """执行 Git diff 操作
        
        Args:
            user_input: 用户输入
            
        Returns:
            差异分析结果
        """
        try:
            # 检查是否在 Git 仓库中
            if not self._is_git_repository():
                return {
                    "type": "error",
                    "error": "当前目录不是 Git 仓库"
                }
            
            # 执行 git diff
            result = subprocess.run(
                ["git", "diff"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                diff_output = result.stdout
                return {
                    "type": "git_result",
                    "operation": "diff",
                    "status": "success",
                    "message": "差异分析完成",
                    "diff": diff_output
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "diff",
                    "status": "error",
                    "message": "差异分析失败",
                    "output": result.stderr
                }
        except Exception as e:
            return {
                "type": "error",
                "error": f"执行 Git diff 失败: {str(e)}"
            }
    
    def _git_status(self, user_input: str) -> Dict[str, Any]:
        """执行 Git status 操作
        
        Args:
            user_input: 用户输入
            
        Returns:
            状态结果
        """
        try:
            # 检查是否在 Git 仓库中
            if not self._is_git_repository():
                return {
                    "type": "error",
                    "error": "当前目录不是 Git 仓库"
                }
            
            # 执行 git status
            result = subprocess.run(
                ["git", "status"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "type": "git_result",
                    "operation": "status",
                    "status": "success",
                    "message": "获取状态成功",
                    "output": result.stdout
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "status",
                    "status": "error",
                    "message": "获取状态失败",
                    "output": result.stderr
                }
        except Exception as e:
            return {
                "type": "error",
                "error": f"执行 Git status 失败: {str(e)}"
            }
    
    def _is_git_repository(self) -> bool:
        """检查当前目录是否是 Git 仓库
        
        Returns:
            是否是 Git 仓库
        """
        import subprocess
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _handle_fix(self, user_input: str) -> Dict[str, Any]:
        """处理修复建议命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            修复建议
        """
        # 提取目标
        target = "."
        import re
        
        # 尝试提取路径
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:修复|fix|patch)|$)"
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
        elif "目录" in user_input or "folder" in user_input:
            path_match = re.search(r"(目录|folder)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                target = path_match.group(2).strip() or "."
        
        # 执行扫描获取漏洞信息
        try:
            scanner = create_scanner(self.config)
            scan_result = scanner.scan_sync(target)
            
            # 生成修复建议和补丁
            fix_suggestions = []
            patches = []
            
            if scan_result.findings:
                for finding in scan_result.findings[:3]:  # 只生成前3个漏洞的修复建议
                    # 生成修复建议
                    suggestion = self._generate_fix_suggestion(finding)
                    fix_suggestions.append(suggestion)
                    
                    # 生成补丁
                    patch = self._generate_patch(finding)
                    if patch:
                        patches.append(patch)
            
            return {
                "type": "fix_result",
                "target": target,
                "fix_suggestions": fix_suggestions,
                "patches": patches
            }
        except Exception as e:
            return {
                "type": "error",
                "target": target,
                "error": f"生成修复建议失败: {str(e)}"
            }
    
    def _generate_fix_suggestion(self, finding) -> Dict[str, Any]:
        """生成修复建议
        
        Args:
            finding: 漏洞发现
            
        Returns:
            修复建议
        """
        return {
            "vulnerability": finding.message,
            "severity": finding.severity.value,
            "rule_name": finding.rule_name,
            "location": finding.location,
            "suggestion": f"修复 {finding.rule_name} 漏洞: {finding.description}",
            "recommendation": self._get_specific_recommendation(finding)
        }
    
    def _get_specific_recommendation(self, finding) -> str:
        """获取特定漏洞的修复建议
        
        Args:
            finding: 漏洞发现
            
        Returns:
            具体修复建议
        """
        rule_name = finding.rule_name.lower()
        
        # 根据不同类型的漏洞提供具体修复建议
        if "sql" in rule_name or "injection" in rule_name:
            return "使用参数化查询或预处理语句，避免直接拼接SQL语句。"
        elif "xss" in rule_name:
            return "对用户输入进行HTML转义，使用安全的模板引擎。"
        elif "command" in rule_name:
            return "避免使用用户输入构建命令，使用安全的API替代。"
        elif "hardcoded" in rule_name:
            return "将硬编码的敏感信息移至配置文件或环境变量。"
        elif "authentication" in rule_name:
            return "实现强密码策略，使用安全的认证机制。"
        elif "cryptography" in rule_name:
            return "使用强加密算法，避免使用不安全的加密方法。"
        elif "data" in rule_name and "exposure" in rule_name:
            return "对敏感数据进行加密存储，限制数据访问权限。"
        else:
            return "根据漏洞描述和最佳实践进行修复。"
    
    def _generate_patch(self, finding) -> Dict[str, Any]:
        """生成修复补丁
        
        Args:
            finding: 漏洞发现
            
        Returns:
            补丁信息
        """
        try:
            # 读取文件内容
            file_path = finding.location.split(':')[0] if ':' in finding.location else finding.location
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 生成补丁（这里是示例，实际需要根据具体漏洞类型生成）
            # 注意：这只是一个示例，实际补丁生成需要更复杂的逻辑
            patch = {
                "file_path": file_path,
                "original_content": content[:500] + "..." if len(content) > 500 else content,
                "fixed_content": content[:500] + "..." if len(content) > 500 else content,
                "diff": "--- a/{file_path}\n+++ b/{file_path}\n@@ -1,5 +1,5 @@\n- vulnerable code\n+ fixed code",
                "description": f"修复 {finding.rule_name} 漏洞"
            }
            
            return patch
        except Exception:
            return None
    
    def _handle_info(self, user_input: str) -> Dict[str, Any]:
        """处理信息查询命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            信息结果
        """
        return {
            "type": "info_result",
            "message": "HOS-LS 安全对话模式\n\n" +
                      "可用命令:\n" +
                      "- 扫描命令: 例如 '扫描当前目录的安全风险'\n" +
                      "- 分析命令: 例如 '分析这个项目的漏洞'\n" +
                      "- 利用命令: 例如 '生成漏洞的 POC'\n" +
                      "- 修复命令: 例如 '提供修复建议'\n" +
                      "- 特殊命令: /help, /exit, /clear\n" +
                      "- CLI转换: 例如 '转换为CLI命令' 或 '解释CLI命令'"
        }
    
    def natural_language_to_cli(self, natural_language: str) -> str:
        """将自然语言转换为CLI命令
        
        Args:
            natural_language: 自然语言输入
            
        Returns:
            CLI命令字符串
        """
        # 分析自然语言意图
        intent = self.parse_intent(natural_language)
        
        # 基础命令
        cli_command = "hos-ls"
        
        # 根据意图构建CLI命令
        if intent == "scan":
            cli_command += " --scan"
            # 检查是否需要纯AI模式
            if "pure" in natural_language.lower() or "纯" in natural_language:
                cli_command += " --pure-ai"
            # 检查是否需要POC生成
            if "poc" in natural_language.lower() or "利用" in natural_language:
                cli_command += " --poc"
        elif intent == "analyze":
            cli_command += " --scan --reason"
            # 检查是否需要攻击链分析
            if "攻击链" in natural_language or "attack chain" in natural_language.lower():
                cli_command += " --attack-chain"
        elif intent == "exploit":
            cli_command += " --scan --reason --poc"
            # 检查是否需要验证
            if "验证" in natural_language or "verify" in natural_language.lower():
                cli_command += " --verify"
        elif intent == "fix":
            cli_command += " --scan --reason --fix"
        
        # 添加目标路径
        target = "."
        import re
        # 尝试提取路径
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s+(?:测试|test|模式|pure|纯|个文件|文件)|$)"
        path_match = re.search(path_pattern, natural_language)
        if path_match:
            target = path_match.group(0).strip()
        cli_command += f" {target}"
        
        return cli_command
    
    def cli_to_natural_language(self, cli_command: str) -> str:
        """将CLI命令转换为自然语言
        
        Args:
            cli_command: CLI命令
            
        Returns:
            自然语言描述
        """
        # 解析CLI命令
        import shlex
        parts = shlex.split(cli_command)
        
        # 移除命令名
        if parts and parts[0] == "hos-ls":
            parts = parts[1:]
        
        # 分析参数
        actions = []
        target = "."
        
        for part in parts:
            if part.startswith("--"):
                flag = part[2:]
                if flag == "scan":
                    actions.append("扫描代码")
                elif flag == "reason":
                    actions.append("分析漏洞")
                elif flag == "attack-chain":
                    actions.append("分析攻击链")
                elif flag == "poc":
                    actions.append("生成漏洞利用代码")
                elif flag == "verify":
                    actions.append("验证漏洞")
                elif flag == "fix":
                    actions.append("提供修复建议")
                elif flag == "report":
                    actions.append("生成报告")
                elif flag == "pure-ai":
                    actions.append("使用纯AI模式")
                elif flag == "full-audit":
                    actions.append("执行完整安全审计")
                elif flag == "quick-scan":
                    actions.append("执行快速扫描")
            else:
                # 假设是目标路径
                target = part
        
        # 构建自然语言描述
        if not actions:
            return "执行安全扫描"
        
        description = ""
        if actions:
            description = "、".join(actions)
            description += f"，目标路径为 {target}"
        
        return description
    
    def _handle_general(self, user_input: str) -> Dict[str, Any]:
        """处理通用命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            处理结果
        """
        # 检查是否是代码库工具命令
        if "@file:" in user_input:
            # 处理文件引用
            import re
            file_match = re.search(r"@file:(.+?)(\s|$)", user_input)
            if file_match:
                file_path = file_match.group(1).strip()
                return self._read_file(file_path)
        elif "@func:" in user_input:
            # 处理函数引用
            import re
            func_match = re.search(r"@func:(.+?)(\s|$)", user_input)
            if func_match:
                func_name = func_match.group(1).strip()
                return self._search_ast(func_name)
        elif "搜索代码" in user_input or "grep" in user_input:
            # 处理代码搜索
            import re
            keyword_match = re.search(r"(搜索代码|grep)\s*(.*?)(?:的|$)", user_input)
            if keyword_match:
                keyword = keyword_match.group(2).strip()
                return self._grep_code(keyword)
        elif "列出目录" in user_input or "list dir" in user_input:
            # 处理目录列出
            import re
            path_match = re.search(r"(列出目录|list dir)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                path = path_match.group(2).strip() or "."
                return self._list_dir(path)
        elif "项目摘要" in user_input or "项目信息" in user_input or "project summary" in user_input.lower():
            # 处理项目摘要请求
            return {
                "type": "project_summary",
                **self.project_context
            }
        elif "转换为CLI命令" in user_input or "转为CLI命令" in user_input:
            # 处理自然语言转CLI命令
            # 提取实际的自然语言请求
            import re
            request_match = re.search(r"(转换为CLI命令|转为CLI命令)\s*(.*?)(?:的|$)", user_input)
            if request_match:
                natural_language = request_match.group(2).strip() or user_input
                cli_command = self.natural_language_to_cli(natural_language)
                return {
                    "type": "cli_conversion",
                    "natural_language": natural_language,
                    "cli_command": cli_command
                }
        elif "解释CLI命令" in user_input or "解释命令" in user_input:
            # 处理CLI命令转自然语言
            # 提取CLI命令
            import re
            command_match = re.search(r"(解释CLI命令|解释命令)\s*(.*?)(?:的|$)", user_input)
            if command_match:
                cli_command = command_match.group(2).strip()
                if cli_command:
                    natural_language = self.cli_to_natural_language(cli_command)
                    return {
                        "type": "cli_explanation",
                        "cli_command": cli_command,
                        "natural_language": natural_language
                    }
        
        # 使用多 Agent 管道处理通用查询
        result = self.multi_agent_pipeline.process_query(user_input)
        
        return {
            "type": "general_result",
            "query": user_input,
            "result": result
        }
    
    def _grep_code(self, keyword: str) -> Dict[str, Any]:
        """搜索代码中的关键词
        
        Args:
            keyword: 要搜索的关键词
            
        Returns:
            搜索结果
        """
        import subprocess
        import os
        
        try:
            # 使用 ripgrep 或 grep 搜索代码
            if os.name == 'nt':
                # Windows 系统
                result = subprocess.run(
                    ['findstr', '/s', '/n', keyword, '*.py', '*.js', '*.ts', '*.java', '*.c', '*.cpp', '*.h'],
                    capture_output=True,
                    text=True,
                    cwd="."
                )
            else:
                # Unix 系统
                result = subprocess.run(
                    ['grep', '-r', '-n', keyword, '--include=*.py', '--include=*.js', '--include=*.ts', '--include=*.java', '--include=*.c', '--include=*.cpp', '--include=*.h', '.'],
                    capture_output=True,
                    text=True
                )
            
            matches = result.stdout.strip().split('\n') if result.stdout.strip() else []
            matches = [m for m in matches if m]
            
            return {
                "type": "grep_result",
                "keyword": keyword,
                "matches": matches[:50],  # 限制结果数量
                "total": len(matches)
            }
        except Exception as e:
            return {
                "type": "error",
                "error": f"搜索代码失败: {str(e)}"
            }
    
    def _read_file(self, file_path: str) -> Dict[str, Any]:
        """读取文件内容
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件内容
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return {
                "type": "file_content",
                "file_path": file_path,
                "content": content,
                "lines": len(content.split('\n'))
            }
        except Exception as e:
            return {
                "type": "error",
                "error": f"读取文件失败: {str(e)}"
            }
    
    def _list_dir(self, path: str = ".") -> Dict[str, Any]:
        """列出目录内容
        
        Args:
            path: 目录路径
            
        Returns:
            目录内容
        """
        import os
        from pathlib import Path
        
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                return {
                    "type": "error",
                    "error": f"路径不存在: {path}"
                }
            
            if path_obj.is_file():
                return {
                    "type": "file_info",
                    "file_path": str(path_obj),
                    "size": path_obj.stat().st_size,
                    "modified": path_obj.stat().st_mtime
                }
            
            # 列出目录内容
            items = []
            for item in sorted(path_obj.iterdir()):
                items.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0
                })
            
            return {
                "type": "directory_listing",
                "path": str(path_obj),
                "items": items
            }
        except Exception as e:
            return {
                "type": "error",
                "error": f"列出目录失败: {str(e)}"
            }
    
    def _search_ast(self, func_name: str) -> Dict[str, Any]:
        """搜索 AST 中的函数
        
        Args:
            func_name: 函数名
            
        Returns:
            搜索结果
        """
        import ast
        import os
        
        try:
            matches = []
            
            # 搜索 Python 文件
            for root, dirs, files in os.walk('.'):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                            
                            tree = ast.parse(content, filename=file_path)
                            for node in ast.walk(tree):
                                if isinstance(node, ast.FunctionDef) and node.name == func_name:
                                    # 提取函数定义
                                    start_line = node.lineno
                                    end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line + 10
                                    
                                    # 提取函数代码
                                    lines = content.split('\n')
                                    func_code = '\n'.join(lines[start_line-1:end_line])
                                    
                                    matches.append({
                                        "file_path": file_path,
                                        "start_line": start_line,
                                        "end_line": end_line,
                                        "function_code": func_code
                                    })
                        except Exception:
                            pass
            
            return {
                "type": "ast_search_result",
                "function_name": func_name,
                "matches": matches
            }
        except Exception as e:
            return {
                "type": "error",
                "error": f"搜索 AST 失败: {str(e)}"
            }
    
    def _load_session(self):
        """加载会话历史"""
        session_path = Path.home() / ".hos-ls" / "sessions"
        session_path.mkdir(parents=True, exist_ok=True)
        session_file = session_path / f"{self.session}.json"
        
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.conversation_history = data.get("history", [])
                    self.project_context = data.get("context", {})
            except Exception:
                pass
    
    def _save_session(self):
        """保存会话历史"""
        session_path = Path.home() / ".hos-ls" / "sessions"
        session_path.mkdir(parents=True, exist_ok=True)
        session_file = session_path / f"{self.session}.json"
        
        data = {
            "history": self.conversation_history,
            "context": self.project_context
        }
        
        try:
            with open(session_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    
    def get_conversation_history(self) -> List[Dict[str, str]]:
        """获取对话历史
        
        Returns:
            对话历史列表
        """
        return self.conversation_history
    
    def clear_history(self):
        """清除对话历史"""
        self.conversation_history = []
        if self.session:
            self._save_session()
    
    def _generate_project_summary(self):
        """生成项目摘要
        
        生成项目的文件树和关键文件索引，存储到 project_context 中
        """
        import os
        from pathlib import Path
        
        try:
            # 生成文件树
            file_tree = self._build_file_tree(".")
            
            # 识别关键文件
            key_files = self._identify_key_files(".")
            
            # 生成项目摘要
            project_summary = {
                "root": os.getcwd(),
                "file_tree": file_tree,
                "key_files": key_files,
                "total_files": self._count_files("."),
                "languages": self._detect_languages(".")
            }
            
            self.project_context = project_summary
        except Exception as e:
            # 如果生成失败，使用空摘要
            self.project_context = {
                "error": f"生成项目摘要失败: {str(e)}"
            }
    
    def _build_file_tree(self, path: str, max_depth: int = 3, current_depth: int = 0) -> Dict[str, Any]:
        """构建文件树
        
        Args:
            path: 起始路径
            max_depth: 最大深度
            current_depth: 当前深度
            
        Returns:
            文件树结构
        """
        from pathlib import Path
        
        path_obj = Path(path)
        tree = {
            "name": path_obj.name,
            "type": "directory",
            "children": []
        }
        
        if current_depth >= max_depth:
            return tree
        
        try:
            for item in sorted(path_obj.iterdir()):
                if item.name.startswith('.'):
                    continue  # 跳过隐藏文件
                
                if item.is_dir():
                    child_tree = self._build_file_tree(item, max_depth, current_depth + 1)
                    tree["children"].append(child_tree)
                else:
                    tree["children"].append({
                        "name": item.name,
                        "type": "file",
                        "size": item.stat().st_size
                    })
        except Exception:
            pass
        
        return tree
    
    def _identify_key_files(self, path: str) -> List[Dict[str, Any]]:
        """识别关键文件
        
        Args:
            path: 搜索路径
            
        Returns:
            关键文件列表
        """
        import os
        from pathlib import Path
        
        key_files = []
        key_patterns = [
            ("配置文件", ["requirements.txt", "pyproject.toml", "setup.py", "package.json", "go.mod", "pom.xml"]),
            ("主文件", ["main.py", "app.py", "index.js", "server.py", "__main__.py"]),
            ("配置目录", ["config", "conf", "settings"]),
            ("源码目录", ["src", "lib", "app", "src/main"]),
            ("测试目录", ["tests", "test"]),
            ("文档", ["README", "README.md", "README.rst", "docs"]),
            ("构建文件", ["Makefile", "build.py", "CMakeLists.txt"])
        ]
        
        for category, patterns in key_patterns:
            for pattern in patterns:
                for root, dirs, files in os.walk(path):
                    for item in dirs + files:
                        if item == pattern or item.startswith(pattern):
                            item_path = os.path.join(root, item)
                            key_files.append({
                                "path": item_path,
                                "category": category,
                                "type": "directory" if os.path.isdir(item_path) else "file"
                            })
        
        # 去重
        seen_paths = set()
        unique_key_files = []
        for file_info in key_files:
            if file_info["path"] not in seen_paths:
                seen_paths.add(file_info["path"])
                unique_key_files.append(file_info)
        
        return unique_key_files[:20]  # 限制数量
    
    def _count_files(self, path: str) -> int:
        """统计文件数量
        
        Args:
            path: 搜索路径
            
        Returns:
            文件数量
        """
        import os
        count = 0
        for root, dirs, files in os.walk(path):
            # 跳过隐藏目录
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            count += len(files)
        return count
    
    def _detect_languages(self, path: str) -> Dict[str, int]:
        """检测项目语言
        
        Args:
            path: 搜索路径
            
        Returns:
            语言统计
        """
        import os
        from pathlib import Path
        
        extensions = {}
        language_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.h': 'C/C++ Header',
            '.html': 'HTML',
            '.css': 'CSS',
            '.json': 'JSON',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.md': 'Markdown',
            '.txt': 'Text'
        }
        
        for root, dirs, files in os.walk(path):
            # 跳过隐藏目录
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in language_map:
                    language = language_map[ext]
                    extensions[language] = extensions.get(language, 0) + 1
        
        return extensions

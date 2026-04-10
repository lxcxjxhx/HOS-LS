"""统一智能交互引擎

整合聊天模式和Agent编排语言的核心类。
提供统一的交互接口，支持：
- 自然语言处理
- Agent Pipeline 构建与执行
- Plan 管理
- 双向转换（自然语言 ↔ CLI/Pipeline）
- AI API 动态配置（零硬编码）
"""

from typing import Dict, Any, Optional, List
import asyncio
import os

from src.core.config import Config
from src.core.conversation_manager import ConversationManager
from src.core.intelligent_pipeline_builder import IntelligentPipelineBuilder
from src.core.intent_parser import IntentParser, IntentType, ParsedIntent
from src.core.plan_manager import PlanManager
from src.core.ai_config_validator import AIConfigValidator


class UnifiedInteractionEngine:
    """统一智能交互引擎
    
    这是整个智能交互模式的核心，整合了：
    - 聊天模式的自然语言理解
    - Agent 编排语言的 Pipeline 构建
    - AI 驱动的意图识别和响应生成
    
    使用示例:
    >>> engine = UnifiedInteractionEngine(config)
    >>> result = engine.process("扫描当前目录")
    >>> print(result)
    """
    
    def __init__(self, config: Config, session_name: Optional[str] = None):
        """初始化统一交互引擎

        Args:
            config: 配置对象（必须包含AI相关配置）
            session_name: 会话名称（可选，用于持久化）
        """
        self.config = config
        
        # 初始化各组件
        self.conversation_manager = ConversationManager(config, session_name)
        self.pipeline_builder = IntelligentPipelineBuilder
        self.plan_manager = PlanManager(config)
        self.intent_parser = None  # 延迟初始化
        self.ai_client = None  # 延迟初始化
        
        # 🔥 新增：统一执行引擎（用于 Agent 能力系统）
        self.unified_engine = None  # 延迟初始化
        
        # 状态标志
        self._initialized = False
        self._initialization_error = None
        
    async def initialize(self):
        """异步初始化AI客户端（懒加载）
        
        从配置动态加载AI客户端，确保零硬编码。
        
        Raises:
            RuntimeError: 如果AI客户端初始化失败
        """
        if self._initialized:
            return
            
        try:
            from src.ai.client import get_model_manager
            from src.core.unified_execution_engine import UnifiedExecutionEngine  # 🔥 新增
            
            model_manager = await get_model_manager(self.config)
            self.ai_client = model_manager.get_default_client()
            
            if not self.ai_client:
                raise RuntimeError(
                    "❌ 无法初始化AI客户端\n\n"
                    "请检查以下配置:\n"
                    "1. 设置API密钥环境变量:\n"
                    "   Windows: set DEEPSEEK_API_KEY=sk-xxx\n"
                    "   Linux/Mac: export DEEPSEEK_API_KEY=sk-xxx\n\n"
                    "2. 或在配置文件中设置:\n"
                    "   ai:\n"
                    "     provider: deepseek\n"
                    "     api_key: sk-xxx\n\n"
                    f"3. 当前配置: {AIConfigValidator.validate(self.config)[2]}"
                )
            
            # 初始化意图解析器（带AI增强能力）
            self.intent_parser = IntentParser(self.ai_client)
            
            # 🔥🔥🔥 初始化统一执行引擎（核心改动！）
            self.unified_engine = UnifiedExecutionEngine(
                config=self.config,
                strategy_engine=None  # 暂时不启用策略引擎
            )
            
            self._initialized = True
            
        except Exception as e:
            self._initialization_error = str(e)
            # 即使AI不可用也继续工作（降级到规则模式）
            self.intent_parser = IntentParser(None)  # 仅使用规则解析
            self._initialized = True  # 标记为已初始化（虽然部分功能受限）
    
    def ensure_initialized(self):
        """确保已初始化（同步包装）"""
        if not self._initialized:
            asyncio.run(self.initialize())
    
    def process(self, user_input: str) -> Dict[str, Any]:
        """处理用户输入（主入口）
        
        这是统一的入口点，自动路由到合适的处理器：
        - 自然语言命令 → IntentParser → ActionExecutor
        - CLI命令 → CLIParser → PipelineBuilder  
        - Plan DSL → PlanParser → PipelineExecutor
        
        Args:
            user_input: 用户输入文本
            
        Returns:
            处理结果字典
        """
        if not user_input or not user_input.strip():
            return {
                "type": "error",
                "error": "输入不能为空",
                "message": "请输入有效的命令或问题"
            }
        
        # 确保初始化
        self.ensure_initialized()
        
        # 记录到会话历史
        self.conversation_manager.add_user_message(user_input)
        
        try:
            # 解析意图
            intent = self.intent_parser.parse(user_input)
            
            # 根据意图类型分发处理
            result = self._dispatch_intent(intent, user_input)
            
            # 记录助手回复
            if result.get('type') != 'error':
                self.conversation_manager.add_assistant_message(
                    str(result.get('message', result.get('display', ''))),
                    metadata={"intent_type": intent.type.value}
                )
            
            # 更新上下文
            self.conversation_manager.update_context(result)
            
            return result
            
        except Exception as e:
            error_result = {
                "type": "error",
                "error": str(e),
                "message": f"处理请求时出错: {str(e)}"
            }
            self.conversation_manager.update_context(error_result)
            return error_result
    
    def _dispatch_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """根据意图分发到对应处理器"""
        intent_type = intent.type
        
        if intent_type == IntentType.SCAN:
            return self._handle_scan_intent(intent, user_input)
            
        elif intent_type == IntentType.ANALYZE:
            return self._handle_analyze_intent(intent, user_input)
            
        elif intent_type == IntentType.EXPLOIT:
            return self._handle_exploit_intent(intent, user_input)
            
        elif intent_type == IntentType.FIX:
            return self._handle_fix_intent(intent, user_input)
            
        elif intent_type == IntentType.PLAN:
            return self._handle_plan_intent(intent, user_input)
            
        elif intent_type == IntentType.GIT:
            return self._handle_git_intent(user_input)
            
        elif intent_type == IntentType.CODE_TOOL:
            return self._handle_code_tool_intent(intent, user_input)
            
        elif intent_type == IntentType.CONVERSION:
            return self._handle_conversion_intent(user_input)
            
        elif intent_type == IntentType.INFO:
            return self._handle_info_intent()
            
        else:
            return self._handle_general_intent(intent, user_input)
    
    def _handle_scan_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理扫描意图（已改造为使用统一执行引擎）"""
        target = IntentParser.extract_target_path(user_input)
        pure_ai = IntentParser.detect_pure_ai_mode(user_input)
        
        try:
            # 🔥🔥🔥 优先使用统一执行引擎
            if self.unified_engine:
                import asyncio
                
                from src.core.base_agent import ExecutionRequest
                
                request = ExecutionRequest(
                    target=target,
                    natural_language=user_input,
                    mode="pure-ai" if pure_ai else "auto"
                )
                
                result = asyncio.run(self.unified_engine.execute(request))
                
                return {
                    "type": "scan_result",
                    "target": target,
                    "pure_ai": pure_ai or result.mode == "pure-ai",
                    "mode": result.mode,
                    "result": result.to_dict() if hasattr(result, 'to_dict') else {
                        'success': result.success,
                        'message': result.message,
                        'findings_count': result.total_findings,
                        'pipeline': result.pipeline_used,
                        'execution_time': result.execution_time
                    },
                    "message": f"✅ {result.message} (模式: {result.mode.upper()})"
                }
            
            # Fallback：旧逻辑（如果统一引擎不可用）
            from src.core.scanner import create_scanner
            
            config = self.config
            config.pure_ai = pure_ai
            
            scanner = create_scanner(config)
            result = scanner.scan_sync(target)
            
            return {
                "type": "scan_result",
                "target": target,
                "pure_ai": pure_ai,
                "test_mode": False,
                "result": result.to_dict() if hasattr(result, 'to_dict') else str(result),
                "message": f"✅ 扫描完成: {target} ({'纯AI模式' if pure_ai else '标准模式'})"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "error": str(e),
                "message": f"扫描失败: {str(e)}"
            }
    
    def _handle_analyze_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理分析意图"""
        target = IntentParser.extract_target_path(user_input)
        
        try:
            import asyncio
            from src.core.langgraph_flow import analyze_code
            
            code = f"目录扫描: {target}"
            result = asyncio.run(analyze_code(code))
            
            return {
                "type": "analysis_result",
                "target": target,
                "result": result,
                "message": f"✅ 分析完成: {target}"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "error": str(e),
                "message": f"分析失败: {str(e)}"
            }
    
    def _handle_exploit_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理漏洞利用意图"""
        target = IntentParser.extract_target_path(user_input)
        
        try:
            from src.core.scanner import create_scanner
            from src.exploit.generator import ExploitGenerator
            
            scanner = create_scanner(self.config)
            scan_result = scanner.scan_sync(target)
            
            generator = ExploitGenerator(self.config)
            exploits = []
            
            if scan_result.findings:
                for finding in scan_result.findings[:3]:
                    try:
                        exploit = generator.generate(finding)
                        if exploit:
                            exploits.append(exploit)
                    except Exception:
                        continue
                        
            return {
                "type": "exploit_result",
                "target": target,
                "exploits": exploits,
                "message": f"✅ 生成了 {len(exploits)} 个POC"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "error": str(e),
                "message": f"POC生成失败: {str(e)}"
            }
    
    def _handle_fix_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理修复建议意图"""
        target = IntentParser.extract_target_path(user_input)
        
        try:
            from src.core.scanner import create_scanner
            
            scanner = create_scanner(self.config)
            scan_result = scanner.scan_sync(target)
            
            fix_suggestions = []
            if scan_result.findings:
                for finding in scan_result.findings[:3]:
                    fix_suggestions.append({
                        "vulnerability": finding.message,
                        "rule_name": finding.rule_name,
                        "suggestion": f"修复建议: {finding.description}"
                    })
                    
            return {
                "type": "fix_result",
                "target": target,
                "fix_suggestions": fix_suggestions,
                "message": f"✅ 生成了 {len(fix_suggestions)} 条修复建议"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "error": str(e),
                "message": f"生成修复建议失败: {str(e)}"
            }
    
    def _handle_plan_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理Plan相关意图"""
        user_input_lower = user_input.lower()
        
        if any(kw in user_input_lower for kw in ['生成', '创建', 'generate', 'create']):
            plan = self.plan_manager.generate_from_natural_language(user_input)
            
            from src.core.plan_dsl import PlanDSLParser
            display = PlanDSLParser.format_plan_for_display(plan)
            
            self.conversation_manager.plan_state.update_plan(plan)
            
            return {
                "type": "plan_generated",
                "plan": plan.to_dict(),
                "display": display,
                "message": "✅ 已生成执行方案\n\n" + display + "\n\n是否执行？(输入'执行方案'开始运行)"
            }
            
        elif any(kw in user_input_lower for kw in ['修改', '更新', 'modify', 'update']):
            current_plan = self.conversation_manager.plan_state.current_plan
            if current_plan:
                modified_plan = self.plan_manager.modify_plan(current_plan, user_input)
                
                from src.core.plan_dsl import PlanDSLParser
                display = PlanDSLParser.format_plan_for_display(modified_plan)
                
                return {
                    "type": "plan_modified",
                    "plan": modified_plan.to_dict(),
                    "display": display,
                    "message": "✅ 方案已修改\n\n" + display
                }
            else:
                return {
                    "type": "error",
                    "error": "没有当前方案可修改",
                    "message": "先生成一个方案再进行修改"
                }
                
        elif any(kw in user_input_lower for kw in ['执行', '运行', 'run', 'execute']):
            current_plan = self.conversation_manager.plan_state.current_plan
            if current_plan:
                from src.cli.plan_commands import _plan_to_cli_args
                
                cli_args = _plan_to_cli_args(current_plan)
                pipeline_nodes = self.pipeline_builder.from_plan(current_plan)
                
                nl_description = self.pipeline_builder.to_natural_language(pipeline_nodes)
                
                return {
                    "type": "plan_executed",
                    "plan": current_plan.to_dict(),
                    "pipeline": [n.type.value for n in pipeline_nodes],
                    "cli_args": cli_args,
                    "display": nl_description,
                    "message": f"🚀 正在执行方案...\n\n{nl_description}"
                }
            else:
                return {
                    "type": "error",
                    "error": "没有当前方案可执行",
                    "message": "先生成一个方案再执行"
                }
        else:
            plan = self.plan_manager.generate_from_natural_language(user_input)
            from src.core.plan_dsl import PlanDSLParser
            display = PlanDSLParser.format_plan_for_display(plan)
            
            return {
                "type": "plan_generated",
                "plan": plan.to_dict(),
                "display": display,
                "message": "✅ 已生成方案\n\n" + display
            }
    
    def _handle_git_intent(self, user_input: str) -> Dict[str, Any]:
        """处理Git操作意图"""
        import subprocess
        
        try:
            if 'commit' in user_input.lower() or '提交' in user_input:
                msg_match = __import__('re').search(r'(?:commit|提交)\s*(.*)', user_input)
                message = msg_match.group(1).strip() if msg_match else "安全修复"
                
                subprocess.run(["git", "add", "."], check=True, capture_output=True)
                result = subprocess.run(
                    ["git", "commit", "-m", message],
                    capture_output=True,
                    text=True
                )
                
                return {
                    "type": "git_result",
                    "operation": "commit",
                    "status": "success" if result.returncode == 0 else "error",
                    "message": "✅ 提交成功" if result.returncode == 0 else f"❌ 提交失败: {result.stderr}",
                    "output": result.stdout if result.returncode == 0 else result.stderr
                }
            else:
                return {
                    "type": "git_result",
                    "operation": "unknown",
                    "status": "error",
                    "message": "不支持的Git操作"
                }
                
        except Exception as e:
            return {
                "type": "git_result",
                "operation": "unknown",
                "status": "error",
                "message": f"Git操作失败: {str(e)}"
            }
    
    def _handle_code_tool_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理代码库工具意图"""
        entities = intent.entities
        
        if '@file:' in user_input:
            file_match = __import__('re').search(r'@file:(.+?)(?:\s|$)', user_input)
            if file_match:
                file_path = file_match.group(1).strip()
                return self._read_file(file_path)
                
        elif '@func:' in user_input:
            func_match = __import__('re').search(r'@func:(.+?)(?:\s|$)', user_input)
            if func_match:
                func_name = func_match.group(1).strip()
                return self._search_function(func_name)
                
        elif '搜索代码' in user_input or 'grep' in user_input.lower():
            keyword_match = __import__('re').search(r'(?:搜索代码|grep)[:\s]*(.*?)(?:\s|$)', user_input)
            keyword = keyword_match.group(1).strip() if keyword_match else ""
            return self._grep_code(keyword)
            
        elif '列出目录' in user_input or 'list dir' in user_input.lower():
            path_match = __import__('re').search(r'(?:列出目录|list dir)[:\s]*(.*?)(?:\s|$)', user_input)
            path = path_match.group(1).strip() if path_match else "."
            return self._list_directory(path)
            
        elif '项目摘要' in user_input or '项目信息' in user_input:
            return {
                "type": "project_summary",
                **self.conversation_manager.project_context.__dict__
            }
            
        return {
            "type": "code_tool_result",
            "message": "无法识别的代码库工具命令"
        }
    
    def _handle_conversion_intent(self, user_input: str) -> Dict[str, Any]:
        """处理CLI/自然语言转换意图"""
        if '转换为CLI' in user_input or '转为CLI' in user_input:
            request_match = __import__('re').search(r'(?:转换|转)(?:为|到)?CLI[:\s]*(.*)', user_input)
            natural_lang = request_match.group(1).strip() if request_match else user_input.replace('转换为CLI', '').replace('转为CLI', '').strip()
            
            cli_command = self.natural_language_to_cli(natural_lang)
            
            return {
                "type": "cli_conversion",
                "natural_language": natural_lang,
                "cli_command": cli_command,
                "message": f"📝 CLI命令:\n\n{cli_command}"
            }
            
        elif '解释CLI' in user_input or '解释命令' in user_input:
            cmd_match = __import__('re').search(r'(?:解释CLI|解释命令)[:\s]*(.*)', user_input)
            cli_cmd = cmd_match.group(1).strip() if cmd_match else ""
            
            if cli_cmd:
                nl_desc = self.cli_to_natural_language(cli_cmd)
                
                return {
                    "type": "cli_explanation",
                    "cli_command": cli_cmd,
                    "natural_language": nl_desc,
                    "message": f"💡 命令含义:\n\n{nl_desc}"
                }
                
        return {
            "type": "conversion_result",
            "message": "无法识别的转换请求"
        }
    
    def _handle_info_intent(self) -> Dict[str, Any]:
        """处理帮助/信息意图"""
        help_text = """
🔒 HOS-LS 智能交互模式帮助

📌 **常用命令类型:**

**1️⃣ 扫描分析**
• "扫描当前目录" - 基础安全扫描
• "用纯AI模式分析" - AI深度分析
• "全面审计这个项目" - 完整安全审计

**2️⃣ 漏洞利用**
• "生成POC" - 创建漏洞利用代码
• "验证漏洞" - 在沙箱中验证

**3️⃣ 方案管理**
• "生成审计方案" - AI生成执行计划
• "修改方案：添加POC" - 调整方案
• "执行方案" - 运行当前方案

**4️⃣ 代码工具**
• "@file:path/to/file" - 读取文件
• "@func:function_name" - 搜索函数
• "搜索代码: 关键词" - 代码搜索

**5️⃣ 转换工具**
• "转换为CLI: 扫描并生成报告"
• "解释CLI: --full-audit"

**6️⃣ 特殊命令**
• /help - 显示此帮助
• /exit - 退出对话
• /clear - 清屏

💡 **提示:** 支持中英文混合输入，AI会智能理解你的需求！
"""
        
        return {
            "type": "info_result",
            "message": help_text
        }
    
    def _handle_general_intent(self, intent: ParsedIntent, user_input: str) -> Dict[str, Any]:
        """处理通用意图（回退到多Agent管道）"""
        try:
            from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline
            
            if self.ai_client:
                pipeline = MultiAgentPipeline(self.ai_client, self.config)
                result = pipeline.process_query(user_input)
                
                return {
                    "type": "general_result",
                    "query": user_input,
                    "result": result,
                    "message": f"✅ 已处理您的查询"
                }
            else:
                return {
                    "type": "general_result",
                    "query": user_input,
                    "result": "AI服务暂时不可用，请检查配置",
                    "message": "⚠️ AI服务不可用"
                }
                
        except Exception as e:
            return {
                "type": "general_result",
                "query": user_input,
                "result": f"处理失败: {str(e)}",
                "message": f"❌ 处理失败: {str(e)}"
            }
    
    def _read_file(self, file_path: str) -> Dict[str, Any]:
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            return {
                "type": "file_content",
                "file_path": file_path,
                "content": content,
                "lines": len(content.split('\n')),
                "message": f"📄 文件: {file_path} ({len(content.split('\n'))} 行)"
            }
        except Exception as e:
            return {"type": "error", "error": f"读取文件失败: {str(e)}"}
    
    def _search_function(self, func_name: str) -> Dict[str, Any]:
        """搜索函数定义"""
        import ast
        matches = []
        
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
                                start_line = node.lineno
                                end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line + 10
                                lines = content.split('\n')
                                func_code = '\n'.join(lines[start_line-1:end_line])
                                
                                matches.append({
                                    "file_path": file_path,
                                    "start_line": start_line,
                                    "end_line": end_line,
                                    "function_code": func_code
                                })
                    except Exception:
                        continue
                        
        return {
            "type": "ast_search_result",
            "function_name": func_name,
            "matches": matches,
            "message": f"🔍 找到 {len(matches)} 个匹配的函数"
        }
    
    def _grep_code(self, keyword: str) -> Dict[str, Any]:
        """搜索代码关键词"""
        import subprocess
        
        try:
            if os.name == 'nt':
                result = subprocess.run(
                    ['findstr', '/s', '/n', keyword, '*.py', '*.js', '*.ts'],
                    capture_output=True, text=True, cwd="."
                )
            else:
                result = subprocess.run(
                    ['grep', '-r', '-n', keyword, '--include=*.py', '--include=*.js', '.'],
                    capture_output=True, text=True
                )
                
            matches = [m for m in result.stdout.strip().split('\n') if m]
            
            return {
                "type": "grep_result",
                "keyword": keyword,
                "matches": matches[:50],
                "total": len(matches),
                "message": f"🔎 搜索 '{keyword}': 找到 {len(matches)} 个匹配"
            }
        except Exception as e:
            return {"type": "error", "error": f"搜索失败: {str(e)}"}
    
    def _list_directory(self, path: str = ".") -> Dict[str, Any]:
        """列出目录内容"""
        from pathlib import Path
        
        try:
            path_obj = Path(path)
            items = []
            
            if path_obj.is_dir():
                for item in sorted(path_obj.iterdir()):
                    items.append({
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": item.stat().st_size if item.is_file() else 0
                    })
                    
            return {
                "type": "directory_listing",
                "path": str(path_obj.absolute()),
                "items": items[:50],
                "message": f"📁 目录: {path} ({len(items)} 项)"
            }
        except Exception as e:
            return {"type": "error", "error": f"列出目录失败: {str(e)}"}
    
    def natural_language_to_cli(self, text: str) -> str:
        """自然语言转CLI命令（公开接口）"""
        nodes = self.pipeline_builder.from_natural_language(text, self.ai_client, self.config)
        target = IntentParser.extract_target_path(text)
        return self.pipeline_builder.to_cli_command(nodes, target)
    
    def cli_to_natural_language(self, cli_command: str) -> str:
        """CLI命令转自然语言（公开接口）"""
        nodes = self.pipeline_builder.from_cli_command(cli_command)
        return self.pipeline_builder.to_natural_language(nodes)
    
    def get_conversation_history(self):
        """获取对话历史"""
        return self.conversation_manager.history
    
    def clear_history(self):
        """清空对话历史"""
        self.conversation_manager.clear()
    
    def save_session(self):
        """保存当前会话"""
        self.conversation_manager.save_session()

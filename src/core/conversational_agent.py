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
            intent = self._analyze_intent(user_input)
            
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
    
    def _analyze_intent(self, user_input: str) -> str:
        """分析用户意图
        
        Args:
            user_input: 用户输入
            
        Returns:
            意图类型
        """
        user_input = user_input.lower()
        
        if any(keyword in user_input for keyword in ["scan", "扫描", "检查", "检测"]):
            return "scan"
        elif any(keyword in user_input for keyword in ["analyze", "分析", "评估", "风险"]):
            return "analyze"
        elif any(keyword in user_input for keyword in ["exploit", "攻击", "poc", "利用"]):
            return "exploit"
        elif any(keyword in user_input for keyword in ["fix", "修复", "patch", "修复建议"]):
            return "fix"
        elif any(keyword in user_input for keyword in ["help", "帮助", "info", "信息"]):
            return "info"
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
        path_pattern = r"[a-zA-Z]:\\[\\\w\s.-]+?(?=\s|$)"  # 匹配 Windows 绝对路径，直到空格或结束
        path_match = re.search(path_pattern, user_input)
        if path_match:
            target = path_match.group(0).strip()
            # 清理路径，移除可能的额外文本
            target = target.split()[0]  # 只取第一个空格前的部分
        elif "目录" in user_input or "folder" in user_input:
            # 尝试提取相对路径
            path_match = re.search(r"(目录|folder)\s*(.*?)(?:的|$)", user_input)
            if path_match:
                target = path_match.group(2).strip() or "."
        
        # 检查是否使用纯 AI 模式
        pure_ai = "pure" in user_input or "纯" in user_input
        
        # 检查是否为测试模式
        test_mode = "测试" in user_input or "test" in user_input
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
    
    def _handle_analyze(self, user_input: str) -> Dict[str, Any]:
        """处理分析命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            分析结果
        """
        # 提取目标路径或代码
        target = "."
        
        # 执行 LangGraph 分析
        import asyncio
        result = asyncio.run(analyze_code("目录扫描: " + target))
        
        return {
            "type": "analysis_result",
            "target": target,
            "result": result
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
        
        # 生成 POC
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
                        exploits.append(exploit)
                except Exception:
                    pass
        
        return {
            "type": "exploit_result",
            "target": target,
            "exploits": exploits
        }
    
    def _handle_fix(self, user_input: str) -> Dict[str, Any]:
        """处理修复建议命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            修复建议
        """
        # 提取目标
        target = "."
        
        # 执行扫描获取漏洞信息
        scanner = create_scanner(self.config)
        scan_result = scanner.scan_sync(target)
        
        # 生成修复建议
        fix_suggestions = []
        if scan_result.findings:
            for finding in scan_result.findings[:3]:  # 只生成前3个漏洞的修复建议
                fix_suggestions.append({
                    "vulnerability": finding.message,
                    "severity": finding.severity.value,
                    "suggestion": f"修复 {finding.rule_name} 漏洞: {finding.description}"
                })
        
        return {
            "type": "fix_result",
            "target": target,
            "fix_suggestions": fix_suggestions
        }
    
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
                      "- 特殊命令: /help, /exit, /clear"
        }
    
    def _handle_general(self, user_input: str) -> Dict[str, Any]:
        """处理通用命令
        
        Args:
            user_input: 用户输入
            
        Returns:
            处理结果
        """
        # 使用多 Agent 管道处理通用查询
        result = self.multi_agent_pipeline.process_query(user_input)
        
        return {
            "type": "general_result",
            "query": user_input,
            "result": result
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